from __future__ import annotations

"""Local automation for the evidence loop.

Automation is intentionally bounded to observation: it schedules the existing
watcher, records local notifications, and creates reviewable investigation
drafts. It never applies a Windows remediation on its own.
"""

import json
import os
import shutil
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable

from .correlation import investigation_summary, rank_candidates
from .db import Database
from .models import Event, IncidentRequest


TASK_NAME = "Difftrail Watcher"
WATCHER_EXECUTABLE_NAME = "difftrail-watcher.exe"
TASK_RESULT_HAS_NOT_RUN = 0x41303
MIN_INTERVAL_SECONDS = 15
MAX_INTERVAL_SECONDS = 86_400
AUTOMATION_META_KEY = "automation:config"

DEFAULT_AUTOMATION_CONFIG: dict[str, Any] = {
    "interval_seconds": 300,
    "notifications_enabled": True,
    "notify_on_crashes": True,
    "notify_on_changes": True,
    "notify_on_warnings": True,
    "draft_investigations": True,
}

_BOOLEAN_CONFIG_KEYS = frozenset(
    {
        "notifications_enabled",
        "notify_on_crashes",
        "notify_on_changes",
        "notify_on_warnings",
        "draft_investigations",
    }
)
_CRASH_TOKENS = (
    "crash",
    "hang",
    "failure",
    "failed",
    "reset",
    "unexpected",
    "bugcheck",
    "error",
)


def _validated_interval(value: Any) -> int:
    if isinstance(value, bool):
        raise ValueError("The watcher interval must be an integer")
    try:
        interval = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError("The watcher interval must be an integer") from exc
    if interval < MIN_INTERVAL_SECONDS or interval > MAX_INTERVAL_SECONDS:
        raise ValueError(
            f"The watcher interval must be between {MIN_INTERVAL_SECONDS} and {MAX_INTERVAL_SECONDS} seconds"
        )
    return interval


def load_automation_config(database: Database) -> dict[str, Any]:
    config = dict(DEFAULT_AUTOMATION_CONFIG)
    raw = database.get_meta(AUTOMATION_META_KEY)
    if raw:
        try:
            stored = json.loads(raw)
        except json.JSONDecodeError:
            stored = {}
        if isinstance(stored, dict):
            for key in _BOOLEAN_CONFIG_KEYS:
                if isinstance(stored.get(key), bool):
                    config[key] = stored[key]
            if "interval_seconds" in stored:
                try:
                    config["interval_seconds"] = _validated_interval(stored["interval_seconds"])
                except ValueError:
                    pass
    return config


def update_automation_config(database: Database, payload: dict[str, Any]) -> dict[str, Any]:
    incoming = payload.get("config") if isinstance(payload.get("config"), dict) else payload
    config = load_automation_config(database)
    if not isinstance(incoming, dict):
        raise ValueError("Automation configuration must be an object")
    if "interval_seconds" in incoming:
        config["interval_seconds"] = _validated_interval(incoming["interval_seconds"])
    for key in _BOOLEAN_CONFIG_KEYS:
        if key not in incoming:
            continue
        if not isinstance(incoming[key], bool):
            raise ValueError(f"Automation setting {key} must be a boolean")
        config[key] = incoming[key]
    database.set_meta(AUTOMATION_META_KEY, json.dumps(config, sort_keys=True, separators=(",", ":")))
    return config


def _empty_watcher_status(*, supported: bool, message: str) -> dict[str, Any]:
    return {
        "task_name": TASK_NAME,
        "supported": supported,
        "installed": False,
        "running": False,
        "state": None,
        "last_run_at": None,
        "next_run_at": None,
        "last_task_result": None,
        "needs_repair": False,
        "message": message,
    }


def _normalize_task_time(value: Any) -> str | None:
    """Hide Task Scheduler's 1999 placeholder for a task that never ran."""

    if not value:
        return None
    candidate = str(value)
    try:
        parsed = datetime.fromisoformat(candidate.replace("Z", "+00:00"))
    except ValueError:
        return candidate
    return candidate if parsed.year >= 2000 else None


def _powershell_executable() -> str | None:
    return shutil.which("powershell.exe") or shutil.which("powershell") or shutil.which("pwsh")


def _hidden_process_kwargs() -> dict[str, int]:
    """Keep console-based Windows helpers invisible when called by the GUI."""

    if os.name != "nt":
        return {}
    return {"creationflags": subprocess.CREATE_NO_WINDOW}


def _run_powershell(script: str) -> subprocess.CompletedProcess[str]:
    executable = _powershell_executable()
    if not executable:
        raise OSError("PowerShell is not available")
    return subprocess.run(
        [executable, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
        **_hidden_process_kwargs(),
    )


def _task_status() -> dict[str, Any]:
    if os.name != "nt":
        return _empty_watcher_status(
            supported=False,
            message="Scheduled task controls are available on Windows.",
        )

    script = r"""
$task = Get-ScheduledTask -TaskName 'Difftrail Watcher' -ErrorAction Stop
$info = Get-ScheduledTaskInfo -TaskName 'Difftrail Watcher' -ErrorAction Stop
$action = $task.Actions | Select-Object -First 1
$command = ([string]$action.Execute).ToLowerInvariant()
$arguments = ([string]$action.Arguments).ToLowerInvariant()
$hasRepetition = @($task.Triggers | Where-Object { $_.Repetition -and $_.Repetition.Interval }).Count -gt 0
$isHeadless = $command.EndsWith('\pythonw.exe') -or $command.EndsWith('difftrail-watcher.exe')
$isOneShot = $arguments.Contains('difftrail.watcher') -or $command.EndsWith('difftrail-watcher.exe')
$sentinel = [datetime]'2000-01-01'
$last = $null
$next = $null
if ($info.LastRunTime -and $info.LastRunTime -gt $sentinel) { $last = $info.LastRunTime.ToUniversalTime().ToString('o') }
if ($info.NextRunTime -and $info.NextRunTime -gt $sentinel) { $next = $info.NextRunTime.ToUniversalTime().ToString('o') }
[pscustomobject]@{
    state = [string]$task.State
    needs_repair = -not ($hasRepetition -and $isHeadless -and $isOneShot)
    last_run_at = $last
    next_run_at = $next
    last_task_result = [int]$info.LastTaskResult
} | ConvertTo-Json -Compress
"""
    try:
        result = _run_powershell(script)
    except (OSError, subprocess.SubprocessError) as exc:
        return _empty_watcher_status(
            supported=True,
            message=f"Could not read the scheduled task status: {exc}",
        )
    if result.returncode != 0:
        error_text = f"{result.stdout}\n{result.stderr}".casefold()
        if any(token in error_text for token in ("cannot find", "does not exist", "not found", "no msft", "0x80070002")):
            return _empty_watcher_status(
                supported=True,
                message="Watcher is not installed.",
            )
        return _empty_watcher_status(
            supported=True,
            message="Could not read the scheduled task status.",
        )
    try:
        payload = json.loads(result.stdout.strip())
    except json.JSONDecodeError:
        return _empty_watcher_status(
            supported=True,
            message="Could not read the scheduled task status.",
        )
    if not isinstance(payload, dict):
        return _empty_watcher_status(
            supported=True,
            message="Could not read the scheduled task status.",
        )
    state = str(payload.get("state") or "Unknown")
    try:
        last_task_result = int(payload["last_task_result"]) if payload.get("last_task_result") is not None else None
    except (TypeError, ValueError):
        last_task_result = None
    needs_repair = bool(payload.get("needs_repair", False))
    return {
        "task_name": TASK_NAME,
        "supported": True,
        "installed": True,
        "running": state.casefold() == "running",
        "state": state,
        "last_run_at": _normalize_task_time(payload.get("last_run_at")),
        "next_run_at": _normalize_task_time(payload.get("next_run_at")),
        "last_task_result": last_task_result,
        "needs_repair": needs_repair,
        "message": _watcher_status_message(state, last_task_result, needs_repair=needs_repair),
    }


def automation_snapshot(database: Database) -> dict[str, Any]:
    return {
        "config": load_automation_config(database),
        "watcher": _task_status(),
        "notifications": {
            "unread": database.unread_automation_notification_count(),
            "recent": database.list_automation_notifications(limit=25),
        },
        "drafts": database.automation_draft_count(),
    }


def _database_file(database: Database) -> Path:
    if str(database.path) == ":memory:":
        raise RuntimeError("Background automation needs a file-backed local journal")
    return database.path.resolve()


def _is_access_denied(result: subprocess.CompletedProcess[str]) -> bool:
    output = f"{result.stdout}\n{result.stderr}".casefold()
    return "access is denied" in output or "0x80070005" in output


def _task_failure_message(result: subprocess.CompletedProcess[str]) -> str:
    if _is_access_denied(result):
        return "Windows denied Task Scheduler access. Difftrail needs administrator approval; retry and accept the UAC prompt."
    output = f"{result.stdout}\n{result.stderr}".casefold()
    if "cannot find" in output or "not found" in output:
        return "Could not update the Difftrail scheduled task because the selected executable or script was not found."
    return "Could not update the Difftrail scheduled task. Check the local Python installation and Task Scheduler service."


def _watcher_status_message(
    state: str,
    last_task_result: int | None,
    *,
    needs_repair: bool = False,
) -> str | None:
    normalized_state = state.casefold()
    if needs_repair:
        return "The background watcher needs to be updated."
    if normalized_state == "disabled":
        return "The watcher task is disabled."
    if normalized_state == "running":
        return None
    if last_task_result == TASK_RESULT_HAS_NOT_RUN:
        return "Background scans are scheduled but have not run yet."
    if last_task_result not in (None, 0):
        result_code = last_task_result & 0xFFFFFFFF
        return f"The last background scan failed (Task Scheduler result 0x{result_code:08X})."
    if normalized_state == "ready":
        return "Background scans are scheduled."
    return "The watcher task is installed but unavailable."


def _run_elevated(executable: str, arguments: list[str]) -> subprocess.CompletedProcess[str]:
    """Retry a user-requested task change through the Windows UAC prompt."""

    argument_string = subprocess.list2cmdline(arguments).replace("'", "''")
    executable_literal = executable.replace("'", "''")
    command = (
        f"$process = Start-Process -FilePath '{executable_literal}' -Verb RunAs "
        f"-Wait -PassThru -ArgumentList '{argument_string}'; exit $process.ExitCode"
    )
    return subprocess.run(
        [executable, "-NoProfile", "-NonInteractive", "-Command", command],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
        **_hidden_process_kwargs(),
    )


def _run_task_script(script: Path, arguments: list[str]) -> None:
    executable = _powershell_executable()
    if not executable:
        raise RuntimeError("PowerShell is required to manage the Difftrail watcher")
    command_arguments = [
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        str(script),
        *arguments,
    ]
    result = subprocess.run(
        [executable, *command_arguments],
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
        **_hidden_process_kwargs(),
    )
    if result.returncode != 0:
        if _is_access_denied(result):
            elevated = _run_elevated(executable, command_arguments)
            if elevated.returncode == 0:
                return
            raise RuntimeError(_task_failure_message(elevated))
        raise RuntimeError(_task_failure_message(result))


def _run_schtasks(arguments: list[str]) -> None:
    executable = shutil.which("schtasks.exe") or shutil.which("schtasks")
    if not executable:
        raise RuntimeError("Windows Task Scheduler is not available")
    result = subprocess.run(
        [executable, *arguments],
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
        **_hidden_process_kwargs(),
    )
    if result.returncode != 0:
        if _is_access_denied(result):
            elevated = _run_elevated(executable, arguments)
            if elevated.returncode == 0:
                return
            raise RuntimeError(_task_failure_message(elevated))
        raise RuntimeError(_task_failure_message(result))


def _task_install_script() -> Path | None:
    if getattr(sys, "frozen", False):
        candidate = Path(sys.executable).resolve().with_name("install-watcher.ps1")
    else:
        candidate = Path(__file__).resolve().parent.parent / "scripts" / "install-watcher.ps1"
    return candidate if candidate.is_file() else None


def _watcher_executable() -> Path:
    """Return the console-free executable used by the scheduled task."""

    if getattr(sys, "frozen", False):
        candidate = Path(sys.executable).resolve().with_name(WATCHER_EXECUTABLE_NAME)
        if not candidate.is_file():
            raise RuntimeError(f"The bundled background watcher is missing at {candidate}")
        return candidate

    python = Path(sys.executable).resolve()
    windowless = python.with_name("pythonw.exe")
    return windowless if windowless.is_file() else python


def _fallback_task_action(database: Database) -> str:
    executable = _watcher_executable()
    if getattr(sys, "frozen", False):
        command = [str(executable), "--db", str(_database_file(database))]
    else:
        command = [str(executable), "-m", "difftrail.watcher", "--db", str(_database_file(database))]
    return subprocess.list2cmdline(command)


def enable_watcher(database: Database, interval_seconds: int | None = None) -> dict[str, Any]:
    if os.name != "nt":
        raise RuntimeError("Background watcher controls are available on Windows")
    interval = _validated_interval(
        interval_seconds if interval_seconds is not None else load_automation_config(database)["interval_seconds"]
    )
    database_file = _database_file(database)
    install_script = _task_install_script()
    if install_script is not None:
        script_arguments = [
            "-IntervalSeconds",
            str(interval),
            "-DatabasePath",
            str(database_file),
        ]
        if getattr(sys, "frozen", False):
            watcher = _watcher_executable()
            script_arguments.extend(
                [
                    "-ExecutablePath",
                    str(watcher),
                    "-WorkingDirectory",
                    str(watcher.parent),
                ]
            )
        else:
            script_arguments.extend(["-PythonPath", sys.executable])
        _run_task_script(
            install_script,
            script_arguments,
        )
    else:
        _run_schtasks(
            [
                "/Create",
                "/TN",
                TASK_NAME,
                "/TR",
                _fallback_task_action(database),
                "/SC",
                "MINUTE",
                "/MO",
                str(max(1, (interval + 59) // 60)),
                "/F",
            ]
        )
        _run_schtasks(["/Run", "/TN", TASK_NAME])
    config = load_automation_config(database)
    config["interval_seconds"] = interval
    database.set_meta(AUTOMATION_META_KEY, json.dumps(config, sort_keys=True, separators=(",", ":")))
    return _task_status()


def disable_watcher(database: Database) -> dict[str, Any]:
    if os.name != "nt":
        raise RuntimeError("Background watcher controls are available on Windows")
    scripts_root = Path(__file__).resolve().parent.parent / "scripts"
    uninstall_script = scripts_root / "uninstall-watcher.ps1"
    if uninstall_script.is_file() and not getattr(sys, "frozen", False):
        _run_task_script(uninstall_script, [])
    else:
        _run_schtasks(["/Delete", "/TN", TASK_NAME, "/F"])
    return _task_status()


def _is_crash_signal(event: Event) -> bool:
    text = f"{event.title} {event.action}".casefold()
    return event.kind == "symptom" and (
        event.severity in {"high", "critical"}
        or any(token in text for token in _CRASH_TOKENS)
    )


def _event_context(event: Event) -> str:
    area = event.entity or event.subsystem
    return f"{area} · {event.subsystem}" if area and event.subsystem else area


def _queue_event_notification(
    database: Database,
    event: Event,
    *,
    kind: str,
    title: str,
    body: str,
    incident_id: str | None = None,
) -> bool:
    event_id = event.event_id
    if not event_id or not database.record_automation_action(event_id, f"notification:{kind}", incident_id=incident_id):
        return False
    database.create_automation_notification(
        kind=kind,
        title=title,
        body=body,
        event_id=event_id,
        incident_id=incident_id,
    )
    return True


def _create_investigation_draft(database: Database, event: Event) -> str | None:
    if not event.event_id or not database.record_automation_action(event.event_id, "draft_investigation"):
        return None
    description = f"Automatic draft: {event.title}"
    request = IncidentRequest(
        description=description,
        onset_start=event.occurred_at,
        onset_end=event.occurred_at,
        subsystem=event.subsystem,
        lookback_days=7,
    )
    incident = database.create_incident(request, status="draft")
    events = database.list_events(limit=10_000, ascending=True)
    hypotheses = rank_candidates(events, request)
    summary = investigation_summary(request, hypotheses)
    database.update_incident_results(incident.id, summary["hypotheses"], status="draft")
    return incident.id


def process_scan_events(
    database: Database,
    result: Any,
    events: Iterable[Event],
) -> dict[str, int]:
    """Apply configured notification/draft rules to one completed scan."""

    config = load_automation_config(database)
    notifications = 0
    drafts = 0
    for event in events:
        if not event.event_id:
            continue
        crash_signal = _is_crash_signal(event)
        incident_id: str | None = None
        if crash_signal and config["draft_investigations"]:
            try:
                incident_id = _create_investigation_draft(database, event)
            except (ValueError, RuntimeError):
                incident_id = None
            if incident_id:
                drafts += 1
        if not config["notifications_enabled"]:
            continue
        if crash_signal and config["notify_on_crashes"]:
            if _queue_event_notification(
                database,
                event,
                kind="crash",
                title="High-severity signal detected",
                body=f"{event.title} · {_event_context(event)}. Review the evidence before acting.",
                incident_id=incident_id,
            ):
                notifications += 1
        elif event.kind == "change" and event.severity in {"high", "critical"} and config["notify_on_changes"]:
            if _queue_event_notification(
                database,
                event,
                kind="change",
                title="Meaningful system change detected",
                body=f"{event.title} · {_event_context(event)}.",
            ):
                notifications += 1

    errors = tuple(getattr(result, "errors", ()) or ())
    scan_id = str(getattr(result, "scan_id", ""))
    if errors and scan_id and config["notifications_enabled"] and config["notify_on_warnings"]:
        if database.record_automation_action(f"scan:{scan_id}", "notification:warning"):
            database.create_automation_notification(
                kind="warning",
                title="Scan completed with warnings",
                body=f"{len(errors)} provider warning{'' if len(errors) == 1 else 's'} was recorded. Review System health.",
            )
            notifications += 1
    return {"notifications": notifications, "drafts": drafts}


def run_automated_scan(database: Database, scanner: Any | None = None) -> Any:
    """Run a scan and process only events newly added by that scan."""

    before_ids = {
        event.event_id
        for event in database.list_events(limit=10_000, ascending=True)
        if event.event_id
    }
    if scanner is None:
        from .service import Scanner

        scanner = Scanner(database)
    result = scanner.scan()
    new_events = [
        event
        for event in database.list_events(limit=10_000, ascending=True)
        if event.event_id and event.event_id not in before_ids
    ]
    process_scan_events(database, result, new_events)
    return result


def mark_notifications_read(database: Database, ids: Iterable[str] | None = None) -> dict[str, Any]:
    database.mark_automation_notifications_read(ids)
    return automation_snapshot(database)
