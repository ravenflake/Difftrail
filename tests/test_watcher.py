import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from difftrail.watcher import _active_marker, _active_marker_path


class WatcherMarkerTests(unittest.TestCase):
    def test_active_marker_exists_only_inside_scan_scope(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            database = Path(temp_dir) / "difftrail.db"
            with patch.dict(os.environ, {"LOCALAPPDATA": temp_dir}):
                marker = _active_marker_path(database)
                with _active_marker(database):
                    self.assertEqual(marker.read_text(encoding="ascii"), str(os.getpid()))
                self.assertFalse(marker.exists())

    def test_active_marker_is_removed_after_failure(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            database = Path(temp_dir) / "difftrail.db"
            with patch.dict(os.environ, {"LOCALAPPDATA": temp_dir}):
                marker = _active_marker_path(database)
                with self.assertRaisesRegex(RuntimeError, "scan failed"):
                    with _active_marker(database):
                        raise RuntimeError("scan failed")
                self.assertFalse(marker.exists())


if __name__ == "__main__":
    unittest.main()
