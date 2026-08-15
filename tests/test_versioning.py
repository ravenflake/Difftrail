from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from scripts.versioning import (
    artifact_name,
    development_version,
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

    def test_development_version_rejects_ambiguous_inputs(self) -> None:
        with self.assertRaises(ValueError):
            development_version("0.1.4-beta.1", 27, "abcdef123456")
        with self.assertRaises(ValueError):
            development_version("0.1.4", 0, "abcdef123456")
        with self.assertRaises(ValueError):
            development_version("0.1.4", 27, "not-a-commit")

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


if __name__ == "__main__":
    unittest.main()
