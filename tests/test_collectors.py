import subprocess
import unittest
from datetime import datetime, timezone
from unittest.mock import patch

from difftrail.collectors.powershell import PowerShellError, run_json
from difftrail.collectors.windows import WindowsCollector
from difftrail.privacy import extract_safe_application_name


class CollectorTests(unittest.TestCase):
    def test_powershell_collection_is_windowless_on_windows(self) -> None:
        completed = subprocess.CompletedProcess(["powershell.exe"], 0, "[]", "")
        windowless_flag = 0x08000000
        with patch("difftrail.collectors.powershell.powershell_path", return_value="powershell.exe"), patch(
            "difftrail.collectors.powershell.subprocess.run", return_value=completed
        ) as run, patch("difftrail._process.os.name", "nt"), patch(
            "difftrail._process.subprocess.CREATE_NO_WINDOW", windowless_flag, create=True
        ):
            self.assertEqual(run_json("@() | ConvertTo-Json"), [])
        self.assertEqual(run.call_args.kwargs["creationflags"], windowless_flag)

        with patch("difftrail.collectors.powershell.powershell_path", return_value="powershell.exe"), patch(
            "difftrail.collectors.powershell.subprocess.run", return_value=completed
        ) as run, patch("difftrail._process.os.name", "posix"):
            self.assertEqual(run_json("@() | ConvertTo-Json"), [])
        self.assertNotIn("creationflags", run.call_args.kwargs)

    def test_application_event_identity_is_safe_and_stable(self) -> None:
        self.assertEqual(
            extract_safe_application_name(r"Faulting application name: C:\Games\Example.exe, version 1.0"),
            "Example.exe",
        )

    def test_nvidia_display_container_service_is_graphics(self) -> None:
        collector = WindowsCollector()
        items = collector._services(
            [
                {
                    "Name": "NVDisplay.ContainerLocalSystem",
                    "DisplayName": "NVIDIA Display Container LS",
                    "PathName": r"C:\Windows\System32\DriverStore\FileRepository\nv_dispi.inf\Display.NvContainer\NVDisplay.Container.exe",
                    "State": "Running",
                    "StartMode": "Auto",
                    "StartName": "LocalSystem",
                }
            ]
        )
        self.assertEqual(items[0].subsystem, "graphics")

    def test_nvidia_high_definition_audio_is_audio_not_graphics(self) -> None:
        collector = WindowsCollector()
        items = collector._devices(
            [
                {
                    "InstanceId": "HDAUDIO\\FUNC_01",
                    "FriendlyName": "NVIDIA High Definition Audio",
                    "Class": "MEDIA",
                    "Status": "OK",
                    "Manufacturer": "NVIDIA",
                }
            ]
        )
        self.assertEqual(items[0].subsystem, "audio")

    def test_driver_rows_with_missing_present_flag_are_still_normalized(self) -> None:
        collector = WindowsCollector()
        items = collector._drivers(
            [
                {
                    "DeviceID": "PCI\\GPU",
                    "DeviceName": "Example Display Adapter",
                    "DriverVersion": "1.2.3",
                    "DriverDate": "2026-01-01",
                    "Manufacturer": "Example",
                    "Class": "Display",
                    "IsSigned": True,
                }
            ]
        )
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0].subsystem, "graphics")
        self.assertEqual(items[0].payload["version"], "1.2.3")

    def test_one_unavailable_provider_does_not_stop_other_snapshots(self) -> None:
        collector = WindowsCollector()

        def fake_run(script: str, *, timeout: int = 45):
            if "Win32_PnPSignedDriver" in script:
                raise PowerShellError("driver provider unavailable")
            return []

        with patch("difftrail.collectors.windows.platform.system", return_value="Windows"), patch(
            "difftrail.collectors.windows.run_json", side_effect=fake_run
        ):
            snapshots = collector.collect_snapshots()
        self.assertNotIn("drivers", snapshots)
        self.assertIn("apps", snapshots)
        self.assertIn("services", snapshots)
        self.assertTrue(any(error.startswith("drivers:") for error in collector.last_errors))

    def test_eventlog_symptoms_are_normalized_across_supported_windows_events(self) -> None:
        rows = [
            {
                "TimeCreated": "2026-08-07T10:00:00Z",
                "Id": 4101,
                "LogName": "System",
                "ProviderName": "Display",
                "Level": "Error",
                "RecordId": "1",
                "Message": "Display driver stopped responding and has recovered.",
            },
            {
                "TimeCreated": "2026-08-07T10:01:00Z",
                "Id": 41,
                "LogName": "System",
                "ProviderName": "Microsoft-Windows-Kernel-Power",
                "Level": "Critical",
                "RecordId": "2",
                "Message": "The system rebooted without cleanly shutting down first.",
            },
            {
                "TimeCreated": "2026-08-07T10:02:00Z",
                "Id": 6008,
                "LogName": "System",
                "ProviderName": "EventLog",
                "Level": "Error",
                "RecordId": "3",
                "Message": "The previous system shutdown was unexpected.",
            },
            {
                "TimeCreated": "2026-08-07T10:03:00Z",
                "Id": 1002,
                "LogName": "Application",
                "ProviderName": "Application Hang",
                "Level": "Error",
                "RecordId": "4",
                "Message": r"The program C:\Users\testuser\Games\Example.exe version 1.0 stopped interacting with Windows.",
            },
            {
                "TimeCreated": "2026-08-07T10:04:00Z",
                "Id": 1000,
                "LogName": "Application",
                "ProviderName": "Application Error",
                "Level": "Error",
                "RecordId": "5",
                "Message": r"Faulting application name: C:\Users\testuser\Games\Example.exe, version 1.2.3",
            },
        ]
        collector = WindowsCollector()
        with patch("difftrail.collectors.windows.platform.system", return_value="Windows"), patch(
            "difftrail.collectors.windows.run_json", return_value=rows
        ):
            events = collector.collect_symptoms(datetime(2026, 8, 7, 9, 59, tzinfo=timezone.utc))

        self.assertEqual(
            [(event.action, event.subsystem, event.severity) for event in events],
            [
                ("driver_reset", "graphics", "high"),
                ("unexpected_restart", "general", "critical"),
                ("unexpected_shutdown", "general", "high"),
                ("hang", "application", "high"),
                ("crash", "application", "high"),
            ],
        )
        self.assertEqual(events[3].entity, "Example.exe")
        self.assertEqual(events[4].details["application_name"], "Example.exe")
        self.assertNotIn(r"C:\Users\testuser", events[4].details["application_name"])
