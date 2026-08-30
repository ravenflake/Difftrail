import subprocess
import unittest
from datetime import datetime, timezone
from unittest.mock import patch

from difftrail.collectors.powershell import PowerShellError, run_json
from difftrail.collectors.windows import WindowsCollector
from difftrail.privacy import extract_safe_application_name


class CollectorTests(unittest.TestCase):
    def test_per_user_service_suffix_uses_stable_logical_key(self) -> None:
        collector = WindowsCollector()
        metadata = {
            "DisplayName": "Push notifications",
            "PathName": r"C:\Windows\System32\svchost.exe -k UnistackSvcGroup",
            "ServiceType": "Share Process",
        }
        first = collector._services([{"Name": "WpnUserService_a1234", **metadata}])[0]
        second = collector._services([{"Name": "WpnUserService_d7351", **metadata}])[0]
        self.assertEqual(first.key, "per-user:WpnUserService")
        self.assertEqual(second.key, first.key)
        self.assertNotEqual(first.payload["name"], second.payload["name"])

    def test_concurrent_per_user_instances_keep_distinct_keys(self) -> None:
        items = WindowsCollector()._services([
            {"Name": "WpnUserService_a1234", "PathName": "svchost.exe", "ServiceType": "Share Process"},
            {"Name": "WpnUserService_d7351", "PathName": "svchost.exe", "ServiceType": "Share Process"},
        ])
        self.assertEqual(
            {item.key for item in items},
            {"per-user:WpnUserService_a1234", "per-user:WpnUserService_d7351"},
        )

    def test_hex_suffix_alone_does_not_create_a_per_user_service_identity(self) -> None:
        item = WindowsCollector()._services([
            {
                "Name": "Example_abcd",
                "PathName": r"C:\Program Files\Example\service.exe",
                "ServiceType": "Own Process",
            }
        ])[0]

        self.assertEqual(item.key, "Example_abcd")
        self.assertNotIn("per_user_service", item.payload)

    def test_service_template_and_per_user_instance_keep_distinct_keys(self) -> None:
        rows = [
            {
                "Name": "OneSyncSvc",
                "DisplayName": "OneSyncSvc",
                "PathName": r"C:\Windows\System32\OneSyncSvc.dll",
                "ServiceType": "Own Process",
            },
            {
                "Name": "OneSyncSvc_c837b",
                "DisplayName": "OneSyncSvc_c837b",
                "PathName": r"C:\Windows\System32\svchost.exe -k UnistackSvcGroup",
                "ServiceType": "Share Process",
            },
        ]

        first = WindowsCollector()._services(rows)
        second = WindowsCollector()._services(rows)

        self.assertEqual(
            {item.key for item in first},
            {"OneSyncSvc", "per-user:OneSyncSvc"},
        )
        self.assertEqual(
            {item.key: item.payload["name"] for item in first},
            {"OneSyncSvc": "OneSyncSvc", "per-user:OneSyncSvc": "OneSyncSvc_c837b"},
        )
        self.assertEqual(
            {item.key for item in second},
            {item.key for item in first},
        )

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

    def test_powershell_rejects_non_object_or_failed_output(self) -> None:
        cases = (
            (0, '"oops"', "not an object or array"),
            (0, '[{"Name":"valid"}, 42]', "non-object row"),
            (1, "[]", "PowerShell exited with code 1"),
        )
        for returncode, stdout, message in cases:
            with self.subTest(stdout=stdout):
                completed = subprocess.CompletedProcess(["powershell.exe"], returncode, stdout, "")
                with patch("difftrail.collectors.powershell.powershell_path", return_value="powershell.exe"), patch(
                    "difftrail.collectors.powershell.subprocess.run", return_value=completed
                ):
                    with self.assertRaisesRegex(PowerShellError, message):
                        run_json("Get-Item")

    def test_powershell_rejects_deeply_nested_json_without_aborting_collection(self) -> None:
        deep_json = '{"nested":' * 10_000 + "null" + "}" * 10_000
        completed = subprocess.CompletedProcess(["powershell.exe"], 0, deep_json, "")
        with patch("difftrail.collectors.powershell.powershell_path", return_value="powershell.exe"), patch(
            "difftrail.collectors.powershell.subprocess.run", return_value=completed
        ):
            with self.assertRaisesRegex(PowerShellError, "invalid JSON"):
                run_json("Get-Item")

    def test_powershell_json_depth_ignores_structural_characters_in_strings(self) -> None:
        completed = subprocess.CompletedProcess(
            ["powershell.exe"],
            0,
            '[{"Name":"text with { [ } ] and an escaped \\\" quote"}]',
            "",
        )
        with patch("difftrail.collectors.powershell.powershell_path", return_value="powershell.exe"), patch(
            "difftrail.collectors.powershell.subprocess.run", return_value=completed
        ):
            self.assertEqual(
                run_json("Get-Item"),
                [{"Name": 'text with { [ } ] and an escaped " quote'}],
            )

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

    def test_per_user_service_suffix_is_normalized_to_stable_identity(self) -> None:
        collector = WindowsCollector()
        items = collector._services(
            [
                {
                    "Name": "OneSyncSvc_c837b",
                    "DisplayName": "OneSyncSvc_c837b",
                    "PathName": r"C:\Windows\System32\svchost.exe -k UnistackSvcGroup",
                    "ServiceType": "Share Process",
                    "State": "Stopped",
                    "StartMode": "Manual",
                    "StartName": "",
                }
            ]
        )
        self.assertEqual(items[0].key, "per-user:OneSyncSvc")
        self.assertEqual(items[0].entity, "OneSyncSvc")
        self.assertEqual(items[0].display_name, "Service OneSyncSvc")
        self.assertTrue(items[0].payload["per_user_service"])
        self.assertEqual(items[0].payload["service_instance_suffix"], "c837b")

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

    def test_driver_inventory_does_not_duplicate_device_presence_transitions(self) -> None:
        script = WindowsCollector.snapshot_scripts["drivers"]

        self.assertIn("Get-CimInstance Win32_PnPSignedDriver", script)
        self.assertIn("Where-Object { $_.DeviceID }", script)
        self.assertNotIn("$_.Present", script)

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
                "Message": r"The program C:\Users\Jane Doe\Games\Example Game.exe version 1.0 stopped interacting with Windows.",
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
        self.assertEqual(events[3].entity, "Example Game.exe")
        self.assertEqual(events[4].details["application_name"], "Example.exe")
        self.assertEqual(
            [event.details["message"] for event in events[3:]],
            [
                r"The program C:\Users\<user> version 1.0 stopped interacting with Windows.",
                r"Faulting application name: C:\Users\<user>, version 1.2.3",
            ],
        )

    def test_malformed_eventlog_rows_do_not_discard_valid_rows_or_collapse_ids(self) -> None:
        rows = [
            {
                "TimeCreated": "2026-08-07T10:00:00Z",
                "Id": "not-an-event-id",
                "LogName": "Application",
            },
            {
                "TimeCreated": "2026-08-07T10:01:00Z",
                "Id": 1000,
                "LogName": "Application",
                "RecordId": r"C:\Users\Alice\record",
                "ProviderName": "Application Error",
                "Message": "First crash",
            },
            {
                "TimeCreated": "2026-08-07T10:02:00Z",
                "Id": 1000,
                "LogName": "Application",
                "ProviderName": "Application Error",
                "Message": "Second crash",
            },
        ]
        collector = WindowsCollector()
        with patch("difftrail.collectors.windows.platform.system", return_value="Windows"), patch(
            "difftrail.collectors.windows.run_json", return_value=rows
        ):
            events = collector.collect_symptoms(datetime(2026, 8, 7, 9, 59, tzinfo=timezone.utc))

        self.assertEqual(len(events), 2)
        self.assertEqual(len({event.event_id for event in events}), 2)
        self.assertTrue(all((event.event_id or "").startswith("eventlog:fallback:") for event in events))
        self.assertNotIn("Alice", " ".join(event.event_id or "" for event in events))
        self.assertIn("eventlog: skipped malformed event row", collector.last_errors)
