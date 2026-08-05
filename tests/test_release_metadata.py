import unittest

from scripts.check_release_metadata import read_versions


class ReleaseMetadataTests(unittest.TestCase):
    def test_all_release_metadata_uses_one_version(self) -> None:
        from pathlib import Path

        root = Path(__file__).resolve().parents[1]
        versions = read_versions(root)
        self.assertEqual(set(versions.values()), {"0.1.3"})

    def test_installer_smoke_test_passes_unquoted_nsis_destination(self) -> None:
        from pathlib import Path

        root = Path(__file__).resolve().parents[1]
        script = (root / "scripts" / "validate-installer.ps1").read_text(encoding="utf-8")
        self.assertIn(
            'Invoke-Installer -FilePath $installer -ArgumentList @("/S", "/D=$installRoot")',
            script,
        )
        self.assertNotIn('/D=`"$installRoot`"', script)
