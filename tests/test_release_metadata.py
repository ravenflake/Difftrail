import re
import unittest

from scripts.check_release_metadata import read_versions


class ReleaseMetadataTests(unittest.TestCase):
    def test_all_release_metadata_uses_one_version(self) -> None:
        from pathlib import Path

        root = Path(__file__).resolve().parents[1]
        versions = read_versions(root)
        expected_sources = {
            "difftrail/__init__.py",
            "pyproject.toml",
            "ui/package.json",
            "ui/package-lock.json",
            "ui/package-lock.json#root",
            "ui/src-tauri/tauri.conf.json",
            "ui/src-tauri/Cargo.toml",
            "ui/src-tauri/Cargo.lock",
        }
        self.assertEqual(set(versions), expected_sources)
        self.assertEqual(set(versions.values()), {"0.1.3"})

    def test_installer_smoke_script_preserves_argument_and_exit_code_contract(self) -> None:
        from pathlib import Path

        root = Path(__file__).resolve().parents[1]
        script = (root / "scripts" / "validate-installer.ps1").read_text(encoding="utf-8")
        self.assertIn('Invoke-Installer -FilePath $installer -RawArguments "/S /D=$installRoot"', script)
        self.assertIn("[Diagnostics.ProcessStartInfo]::new()", script)
        self.assertIn("$startInfo.ArgumentList.Add($argument)", script)
        self.assertIn("[Diagnostics.Process]::Start($startInfo)", script)
        self.assertIn("$process.WaitForExit($installerTimeoutMilliseconds)", script)
        self.assertIn("$installerTimeoutMilliseconds = 120000", script)
        self.assertIn("$processTreeWaitMilliseconds = 5000", script)
        self.assertIn("$uninstallCleanupTimeoutMilliseconds = 30000", script)
        self.assertIn("Get-CimInstance -ClassName Win32_Process", script)
        self.assertIn("Wait-ForProcessIdsToExit -ProcessIds $descendantIds", script)
        self.assertIn("$Process.HasExited", script)
        self.assertIn("$Process.Kill($true)", script)
        self.assertIn("$Process.Kill()", script)
        self.assertLess(script.index("$Process.Kill()"), script.index("$Process.WaitForExit()"))
        self.assertIn("$process.Dispose()", script)
        self.assertIn("Installer process timed out after", script)
        self.assertIn("$exitCode = $process.ExitCode", script)
        self.assertIn("if ($exitCode -ne 0)", script)
        self.assertIn('Filter "difftrail-desktop.exe"', script)
        self.assertIn('$startInfo.Arguments = $RawArguments', script)
        self.assertIn('Invoke-Installer -FilePath $installer -RawArguments "/S /D=$installRoot"', script)
        self.assertIn('Invoke-Installer -FilePath $uninstaller.FullName -RawArguments "/S _?=$installRoot"', script)
        self.assertIn("Difftrail Installer Smoke ", script)
        self.assertNotIn("Start-Process", script)
        self.assertIn('throw "Installer process failed with exit code', script)
        self.assertIn("Remove-Item -LiteralPath $smokeRoot -Recurse -Force -ErrorAction Stop", script)
        self.assertIn("Installer smoke-test cleanup failed", script)
        self.assertNotIn('/D=`"$installRoot`"', script)

    def test_release_workflow_reuses_metadata_checker(self) -> None:
        from pathlib import Path

        root = Path(__file__).resolve().parents[1]
        workflow = (root / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
        self.assertIn("id: release_tag", workflow)
        self.assertIn(
            "EXPECTED_VERSION: ${{ steps.release_tag.outputs.expected }}",
            workflow,
        )
        self.assertIn(
            'python scripts/check_release_metadata.py --expected "${EXPECTED_VERSION}"',
            workflow,
        )
        self.assertNotRegex(workflow, re.compile(r"\bversions\s*=\s*\{"))
