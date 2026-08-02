from __future__ import annotations

import json
import shutil
import subprocess
from typing import Any


class PowerShellError(RuntimeError):
    pass


def powershell_path() -> str | None:
    return shutil.which("powershell.exe") or shutil.which("pwsh.exe")


def run_json(script: str, *, timeout: int = 45) -> list[dict[str, Any]]:
    executable = powershell_path()
    if not executable:
        raise PowerShellError("PowerShell is not available")
    prelude = "$ErrorActionPreference = 'SilentlyContinue'; $ProgressPreference = 'SilentlyContinue'; "
    result = subprocess.run(
        [executable, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", prelude + script],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
        check=False,
    )
    stdout = result.stdout.strip()
    if result.returncode != 0 and not stdout:
        raise PowerShellError(result.stderr.strip() or f"PowerShell exited with code {result.returncode}")
    if not stdout:
        return []
    try:
        parsed = json.loads(stdout)
    except json.JSONDecodeError as exc:
        raise PowerShellError(f"PowerShell returned invalid JSON: {exc}") from exc
    if parsed is None:
        return []
    if isinstance(parsed, dict):
        return [parsed]
    if isinstance(parsed, list):
        return [item for item in parsed if isinstance(item, dict)]
    return []
