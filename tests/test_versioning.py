from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts.stamp_build_version import main as stamp_build_version
from scripts.versioning import (
    artifact_name,
    development_version,
    main_artifact_name,
    main_snapshot_version,
    read_next_version,
    short_commit_sha,
    write_build_stamp,
)


class BuildVersioningTests(unittest.TestCase):
    def test_next_version_is_separate_from_committed_release_metadata(self) -> None:
        root = Path(__file__).resolve().parents[1]

        self.assertEqual(read_next_version(root), "0.1.4")
        self.assertEqual(
            (root / "difftrail" / "__init__.py").read_text(encoding="utf-8").count('"0.1.3"'),
            1,
        )

    def test_development_version_contains_pr_and_short_commit_identity(self) -> None:
        self.assertEqual(
            development_version("0.1.4", 27, "ABCDEF1234567890"),
            "0.1.4-dev.27+abcdef1",
        )
        self.assertEqual(short_commit_sha("abcdef1"), "abcdef1")
        self.assertEqual(
            artifact_name(27, "ABCDEF1234567890"),
            "difftrail-windows-installer-pr-27-abcdef1",
        )

    def test_main_snapshot_version_contains_channel_and_commit_identity(self) -> None:
        self.assertEqual(
            main_snapshot_version("0.1.4", 124, "8B7B92CC4741ACE8"),
            "0.1.4-dev.main.124+8b7b92c",
        )
        self.assertEqual(
            main_artifact_name("8B7B92CC4741ACE8"),
            "difftrail-windows-installer-main-8b7b92c",
        )

    def test_development_version_rejects_ambiguous_inputs(self) -> None:
        with self.assertRaises(ValueError):
            development_version("0.1.4-beta.1", 27, "abcdef123456")
        with self.assertRaises(ValueError):
            development_version("0.1.4", 0, "abcdef123456")
        with self.assertRaises(ValueError):
            development_version("0.1.4", 27, "not-a-commit")
        with self.assertRaises(ValueError):
            main_snapshot_version("0.1.4-beta.1", 124, "abcdef123456")
        with self.assertRaises(ValueError):
            main_snapshot_version("0.1.4", 124, "not-a-commit")
        with self.assertRaises(ValueError):
            main_snapshot_version("0.1.4", 0, "abcdef123456")

    def test_build_stamp_is_ignored_and_targets_backend_and_tauri(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            version = "0.1.4-dev.27+abcdef1"

            write_build_stamp(root, version)

            build_module = (root / "difftrail" / "_build_version.py").read_text(encoding="utf-8")
            self.assertIn("BUILD_VERSION = '0.1.4-dev.27+abcdef1'", build_module)
            tauri_config = json.loads(
                (root / "ui" / "src-tauri" / "tauri.build.conf.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual(tauri_config, {"version": version})

    def test_main_snapshot_build_stamp_targets_backend_and_tauri(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            version = "0.1.4-dev.main.124+8b7b92c"

            write_build_stamp(root, version)

            build_module = (root / "difftrail" / "_build_version.py").read_text(
                encoding="utf-8"
            )
            self.assertIn("BUILD_VERSION = '0.1.4-dev.main.124+8b7b92c'", build_module)
            tauri_config = json.loads(
                (root / "ui" / "src-tauri" / "tauri.build.conf.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual(tauri_config, {"version": version})

    def test_main_snapshot_cli_writes_the_expected_build_inputs(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            (root / "VERSION_NEXT").write_text("0.1.4\n", encoding="utf-8")

            with patch.dict("os.environ", {"GITHUB_OUTPUT": ""}):
                result = stamp_build_version(
                    [
                        "--root",
                        str(root),
                        "--channel",
                        "main",
                        "--build-number",
                        "124",
                        "--commit-sha",
                        "8b7b92cc4741ace8",
                    ]
                )

            self.assertEqual(result, 0)
            tauri_config = json.loads(
                (root / "ui" / "src-tauri" / "tauri.build.conf.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual(tauri_config, {"version": "0.1.4-dev.main.124+8b7b92c"})


if __name__ == "__main__":
    unittest.main()
