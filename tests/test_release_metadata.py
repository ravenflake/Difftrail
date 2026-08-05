import unittest

from scripts.check_release_metadata import read_versions


class ReleaseMetadataTests(unittest.TestCase):
    def test_all_release_metadata_uses_one_version(self) -> None:
        from pathlib import Path

        root = Path(__file__).resolve().parents[1]
        versions = read_versions(root)
        self.assertEqual(set(versions.values()), {"0.1.3"})

    def test_installer_smoke_script_preserves_argument_and_exit_code_contract(self) -> None:
        from pathlib import Path

        root = Path(__file__).resolve().parents[1]
        script = (root / "scripts" / "validate-installer.ps1").read_text(encoding="utf-8")
        self.assertIn(
            'Invoke-Installer -FilePath $installer -ArgumentList @("/S", "/D=$installRoot")',
            script,
        )
        self.assertIn("& $FilePath @ArgumentList", script)
        self.assertNotIn("Start-Process", script)
        self.assertIn("$exitCode = $LASTEXITCODE", script)
        self.assertIn('throw "Installer process failed with exit code', script)
        self.assertIn("Remove-Item -LiteralPath $smokeRoot -Recurse -Force -ErrorAction Stop", script)
        self.assertIn("Installer smoke-test cleanup failed", script)
        self.assertNotIn('/D=`"$installRoot`"', script)

    def test_release_workflow_reuses_metadata_checker(self) -> None:
        from pathlib import Path

        root = Path(__file__).resolve().parents[1]
        workflow = (root / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
        self.assertIn("id: release_tag", workflow)
        self.assertIn("steps.release_tag.outputs.expected", workflow)
        self.assertIn("python scripts/check_release_metadata.py --expected", workflow)
        self.assertNotIn("versions = {", workflow)
