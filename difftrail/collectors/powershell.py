from __future__ import annotations

import json
import shutil
import subprocess
from typing import Any

from .._process import _hidden_process_kwargs


class PowerShellError(RuntimeError):
    pass


def powershell_path() -> str | None:
    return shutil.which("powershell.exe") or shutil.which("pwsh.exe")


def run_json(script: str, *, timeout: int = 45) -> list[dict[str, Any]]:
    executable = powershell_path()
    if not executable:
        raise PowerShellError("PowerShell is not available")
    # Windows PowerShell can otherwise emit through the active OEM/code-page
    # encoding. Explicit UTF-8 keeps names such as driver vendors and app
    # titles stable between scans and across interactive/non-interactive runs.
    prelude = (
        "$ErrorActionPreference = 'SilentlyContinue'; "
        "$ProgressPreference = 'SilentlyContinue'; "
        "$utf8 = New-Object System.Text.UTF8Encoding($false); "
        "[Console]::OutputEncoding = $utf8; "
        "$OutputEncoding = $utf8; "
    )
    result = subprocess.run(
        [executable, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", prelude + script],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
        check=False,
        **_hidden_process_kwargs(),
    )
    stdout = result.stdout.strip()
    # A non-zero PowerShell exit can still leave partial JSON on stdout. That
    # data is not a complete snapshot, so accepting it could turn a provider
    # failure into false removals from the local state journal.
    if result.returncode != 0:
        raise PowerShellError(result.stderr.strip() or f"PowerShell exited with code {result.returncode}")
    if not stdout:
        return []
    try:
        parsed = json.loads(stdout)
    except (json.JSONDecodeError, RecursionError) as exc:
        raise PowerShellError(f"PowerShell returned invalid JSON: {exc}") from exc
    if parsed is None:
        return []
    if isinstance(parsed, dict):
        return [parsed]
    if isinstance(parsed, list):
        if all(isinstance(item, dict) for item in parsed):
            return parsed
        raise PowerShellError("PowerShell returned a JSON array containing a non-object row")
    raise PowerShellError("PowerShell returned JSON that was not an object or array")
