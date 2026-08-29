from pathlib import Path
import unittest
from unittest.mock import patch

from difftrail import overhead


class OverheadTests(unittest.TestCase):
    def test_frozen_backend_uses_its_cli_directly(self) -> None:
        executable = r"C:\Program Files\Difftrail\backend\difftrail-backend.exe"
        with (
            patch.object(overhead.sys, "frozen", True, create=True),
            patch.object(overhead.sys, "executable", executable),
        ):
            command, working_directory = overhead._watcher_command(15)

        self.assertEqual(command[0], str(Path(executable).resolve()))
        self.assertEqual(command[1:], ["--db", ":memory:", "watch", "--interval", "15"])
        self.assertNotIn("-m", command)
        self.assertEqual(working_directory, Path(executable).resolve().parent)

    def test_source_checkout_uses_python_module_entry_point(self) -> None:
        with patch.object(overhead.sys, "frozen", False, create=True):
            command, _ = overhead._watcher_command(30)

        self.assertEqual(command[1:3], ["-m", "difftrail"])
        self.assertEqual(command[-3:], ["watch", "--interval", "30"])


if __name__ == "__main__":
    unittest.main()
