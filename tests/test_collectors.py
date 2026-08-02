import unittest
from unittest.mock import patch

from difftrail.collectors.powershell import PowerShellError
from difftrail.collectors.windows import WindowsCollector


class CollectorTests(unittest.TestCase):
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

        with patch("difftrail.collectors.windows.run_json", side_effect=fake_run):
            snapshots = collector.collect_snapshots()
        self.assertNotIn("drivers", snapshots)
        self.assertIn("apps", snapshots)
        self.assertIn("services", snapshots)
        self.assertTrue(any(error.startswith("drivers:") for error in collector.last_errors))
