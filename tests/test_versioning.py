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


def semver_prerelease_precedence(left: str, right: str) -> int:
    """Compare the prerelease identifiers used by disposable test builds."""

    left_core = left.split("+", 1)[0]
    right_core = right.split("+", 1)[0]
    left_base, left_pre = left_core.split("-", 1)
    right_base, right_pre = right_core.split("-", 1)
    if left_base != right_base:
        raise ValueError("test helper expects matching base versions")
    for left_part, right_part in zip(left_pre.split("."), right_pre.split(".")):
        if left_part == right_part:
            continue
        left_numeric = left_part.isdigit()
        right_numeric = right_part.isdigit()
        if left_numeric and right_numeric:
            return (int(left_part) > int(right_part)) - (int(left_part) < int(right_part))
        if left_numeric != right_numeric:
            return -1 if left_numeric else 1
        return (left_part > right_part) - (left_part < right_part)
    return 0


class BuildVersioningTests(unittest.TestCase):
    def test_next_version_is_not_behind_committed_release_metadata(self) -> None:
        root = Path(__file__).resolve().parents[1]

        next_version = tuple(int(part) for part in read_next_version(root).split("."))
        stable_version = (0, 1, 4)
        self.assertGreaterEqual(next_version, stable_version)

    def test_development_version_contains_pr_and_short_commit_identity(self) -> None:
        self.assertEqual(
            development_version("0.1.4", 27, 33255304554, "ABCDEF1234567890"),
            "0.1.4-preview.33255304554.pr.27+abcdef1",
        )
        self.assertEqual(short_commit_sha("abcdef1"), "abcdef1")
        self.assertEqual(
            artifact_name(27, "ABCDEF1234567890"),
            "difftrail-windows-installer-pr-27-abcdef1",
        )

    def test_main_snapshot_version_contains_channel_and_commit_identity(self) -> None:
        self.assertEqual(
            main_snapshot_version("0.1.4", 33253989141, "8B7B92CC4741ACE8"),
            "0.1.4-preview.33253989141.main+8b7b92c",
        )
        self.assertEqual(
            main_artifact_name("8B7B92CC4741ACE8"),
            "difftrail-windows-installer-main-8b7b92c",
        )

    def test_development_version_rejects_ambiguous_inputs(self) -> None:
        with self.assertRaises(ValueError):
            development_version("0.1.4-beta.1", 27, 100, "abcdef123456")
        with self.assertRaises(ValueError):
            development_version("0.1.4", 0, 100, "abcdef123456")
        with self.assertRaises(ValueError):
            development_version("0.1.4", 27, 100, "not-a-commit")
        with self.assertRaises(ValueError):
            development_version("0.1.4", 27, 0, "abcdef123456")
        with self.assertRaises(ValueError):
            main_snapshot_version("0.1.4-beta.1", 124, "abcdef123456")
        with self.assertRaises(ValueError):
            main_snapshot_version("0.1.4", 124, "not-a-commit")
        with self.assertRaises(ValueError):
            main_snapshot_version("0.1.4", 0, "abcdef123456")

    def test_newer_build_ids_win_across_channels_and_legacy_versions(self) -> None:
        legacy_main = "0.1.4-dev.main.12+5b16880"
        main = main_snapshot_version("0.1.4", 33253989141, "8b7b92cc4741")
        pull_request = development_version("0.1.4", 37, 33255304554, "209c688c5ce2")
        next_main = main_snapshot_version("0.1.4", 33256000000, "abcdef123456")

        self.assertGreater(semver_prerelease_precedence(main, legacy_main), 0)
        self.assertGreater(semver_prerelease_precedence(pull_request, main), 0)
        self.assertGreater(semver_prerelease_precedence(next_main, pull_request), 0)

    def test_build_stamp_is_ignored_and_targets_backend_and_tauri(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            version = "0.1.4-preview.33255304554.pr.27+abcdef1"

            write_build_stamp(root, version)

            build_module = (root / "difftrail" / "_build_version.py").read_text(encoding="utf-8")
            self.assertIn(
                "BUILD_VERSION = '0.1.4-preview.33255304554.pr.27+abcdef1'",
                build_module,
            )
            tauri_config = json.loads(
                (root / "ui" / "src-tauri" / "tauri.build.conf.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual(tauri_config, {"version": version})

    def test_main_snapshot_build_stamp_targets_backend_and_tauri(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            version = "0.1.4-preview.33253989141.main+8b7b92c"

            write_build_stamp(root, version)

            build_module = (root / "difftrail" / "_build_version.py").read_text(
                encoding="utf-8"
            )
            self.assertIn(
                "BUILD_VERSION = '0.1.4-preview.33253989141.main+8b7b92c'",
                build_module,
            )
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
                        "--build-id",
                        "33253989141",
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
            self.assertEqual(
                tauri_config,
                {"version": "0.1.4-preview.33253989141.main+8b7b92c"},
            )


if __name__ == "__main__":
    unittest.main()
