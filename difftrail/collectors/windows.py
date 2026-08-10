from __future__ import annotations

import hashlib
import platform
from datetime import datetime, timedelta
from typing import Any, Callable

from ..correlation import infer_subsystem
from ..models import Event, SnapshotItem, iso_datetime, parse_datetime
from ..privacy import extract_safe_application_name, redact_text
from .powershell import PowerShellError, run_json


def _text(row: dict[str, Any], key: str, default: str = "") -> str:
    value = row.get(key, default)
    if value is None:
        return ""
    # A few Windows providers expose noncharacters for invalid registry/path
    # bytes. Treat them consistently so a provider representation glitch does
    # not look like a service or application change on the next scan.
    return str(value).replace("\x00", "").replace("\ufffd", "").replace("\ufffe", "").replace("\uffff", "")


def _subsystem_for_device(row: dict[str, Any]) -> str:
    text = " ".join(_text(row, key) for key in ("DeviceName", "FriendlyName", "Class", "Manufacturer")).casefold()
    if any(token in text for token in ("audio", "sound", "speaker", "microphone", "realtek")):
        return "audio"
    if any(token in text for token in ("display", "graphics", "nvidia", "radeon", "geforce", "amd gpu")):
        return "graphics"
    if any(token in text for token in ("bluetooth", "wi-fi", "wifi", "wireless", "ethernet", "network")):
        return "network"
    if any(token in text for token in ("usb", "keyboard", "mouse", "printer")):
        return "device"
    return "driver"


def _subsystem_for_service(row: dict[str, Any]) -> str:
    text = " ".join(_text(row, key) for key in ("Name", "DisplayName", "PathName")).casefold()
    if any(
        token in text
        for token in (
            "nvidia display",
            "nvdisplay",
            "display.nvcontainer",
            "amd display",
            "radeon display",
            "graphics container",
        )
    ) or ("driverstore" in text and "display" in text):
        return "graphics"
    return "startup"


class WindowsCollector:
    """Read-only Windows event and state collector.

    Each snapshot is intentionally compact. We store current normalized state
    and emit a single journal event only when that state changes.
    """

    def __init__(self) -> None:
        self.last_errors: list[str] = []

    snapshot_scripts: dict[str, str] = {
        "updates": r'''
$rows = @(Get-HotFix | ForEach-Object {
    [pscustomobject]@{
        HotFixID = [string]$_.HotFixID
        Description = [string]$_.Description
        InstalledOn = if ($_.InstalledOn) { $_.InstalledOn.ToString("o") } else { "" }
    }
})
if ($null -eq $rows) { $rows = @() }
$rows | ConvertTo-Json -Depth 5 -Compress
''',
        "apps": r'''
$roots = @(
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*",
    "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*"
)
$rows = @(Get-ItemProperty $roots | Where-Object { $_.DisplayName -and -not $_.SystemComponent } | ForEach-Object {
    [pscustomobject]@{
        Key = [string]$_.PSChildName
        DisplayName = [string]$_.DisplayName
        DisplayVersion = [string]$_.DisplayVersion
        Publisher = [string]$_.Publisher
        InstallDate = [string]$_.InstallDate
    }
})
if ($null -eq $rows) { $rows = @() }
$rows | ConvertTo-Json -Depth 5 -Compress
''',
        "drivers": r'''
$rows = @(Get-CimInstance Win32_PnPSignedDriver | Where-Object { $_.DeviceID -and ($null -eq $_.Present -or $_.Present -eq $true) } | ForEach-Object {
    [pscustomobject]@{
        DeviceID = [string]$_.DeviceID
        DeviceName = [string]$_.DeviceName
        DriverVersion = [string]$_.DriverVersion
        DriverDate = [string]$_.DriverDate
        Manufacturer = [string]$_.Manufacturer
        Class = [string]$_.ClassGuid
        IsSigned = [bool]$_.IsSigned
    }
})
if ($null -eq $rows) { $rows = @() }
$rows | ConvertTo-Json -Depth 5 -Compress
''',
        "services": r'''
$rows = @(Get-CimInstance Win32_Service | ForEach-Object {
    [pscustomobject]@{
        Name = [string]$_.Name
        DisplayName = [string]$_.DisplayName
        State = [string]$_.State
        StartMode = [string]$_.StartMode
        StartName = [string]$_.StartName
        PathName = [string]$_.PathName
    }
})
if ($null -eq $rows) { $rows = @() }
$rows | ConvertTo-Json -Depth 5 -Compress
''',
        "tasks": r'''
$rows = @(Get-ScheduledTask | ForEach-Object {
    [pscustomobject]@{
        TaskName = [string]$_.TaskName
        TaskPath = [string]$_.TaskPath
        State = [string]$_.State
        Author = [string]$_.Author
    }
})
if ($null -eq $rows) { $rows = @() }
$rows | ConvertTo-Json -Depth 5 -Compress
''',
        "startup": r'''
$rows = @(Get-CimInstance Win32_StartupCommand | ForEach-Object {
    [pscustomobject]@{
        Name = [string]$_.Name
        Command = [string]$_.Command
        Location = [string]$_.Location
        User = [string]$_.User
    }
})
if ($null -eq $rows) { $rows = @() }
$rows | ConvertTo-Json -Depth 5 -Compress
''',
        "devices": r'''
$rows = @(Get-PnpDevice | Where-Object { $_.Present -eq $true } | ForEach-Object {
    [pscustomobject]@{
        InstanceId = [string]$_.InstanceId
        FriendlyName = [string]$_.FriendlyName
        Class = [string]$_.Class
        Status = [string]$_.Status
        Manufacturer = [string]$_.Manufacturer
    }
})
if ($null -eq $rows) { $rows = @() }
$rows | ConvertTo-Json -Depth 5 -Compress
''',
    }

    def collect_snapshots(self) -> dict[str, list[SnapshotItem]]:
        self.last_errors.clear()
        if platform.system() != "Windows":
            return {}
        collectors: dict[str, Callable[[list[dict[str, Any]]], list[SnapshotItem]]] = {
            "updates": self._updates,
            "apps": self._apps,
            "drivers": self._drivers,
            "services": self._services,
            "tasks": self._tasks,
            "startup": self._startup,
            "devices": self._devices,
        }
        result: dict[str, list[SnapshotItem]] = {}
        for source, convert in collectors.items():
            try:
                rows = run_json(self.snapshot_scripts[source])
                result[source] = convert(rows)
            except (PowerShellError, OSError, TimeoutError) as exc:
                # A single unavailable Windows provider should not stop the
                # rest of the journal from updating.
                self.last_errors.append(f"{source}: {exc}")
                continue
        return result

    def _updates(self, rows: list[dict[str, Any]]) -> list[SnapshotItem]:
        return [
            SnapshotItem(
                source="updates",
                key=_text(row, "HotFixID"),
                subsystem="windows-update",
                display_name=f"Windows update {_text(row, 'HotFixID')}",
                payload={"id": _text(row, "HotFixID"), "description": _text(row, "Description"), "installed_on": _text(row, "InstalledOn")},
                severity="high",
                entity=_text(row, "HotFixID"),
                action_on_add="installed",
                action_on_update="updated",
            )
            for row in rows
            if _text(row, "HotFixID")
        ]

    def _apps(self, rows: list[dict[str, Any]]) -> list[SnapshotItem]:
        items: list[SnapshotItem] = []
        for row in rows:
            key = _text(row, "Key") or _text(row, "DisplayName")
            items.append(
                SnapshotItem(
                    source="apps",
                    key=key,
                    subsystem="application",
                    display_name=f"Application {_text(row, 'DisplayName', 'Unknown app')}",
                    payload={
                        "key": _text(row, "Key"),
                        "name": _text(row, "DisplayName"),
                        "version": _text(row, "DisplayVersion"),
                        "publisher": _text(row, "Publisher"),
                        "install_date": _text(row, "InstallDate"),
                    },
                    severity="low",
                    entity=_text(row, "DisplayName"),
                    action_on_add="installed",
                    action_on_update="updated",
                )
            )
        return items

    def _drivers(self, rows: list[dict[str, Any]]) -> list[SnapshotItem]:
        return [
            SnapshotItem(
                source="drivers",
                key=_text(row, "DeviceID"),
                subsystem=_subsystem_for_device(row),
                display_name=f"Driver for {_text(row, 'DeviceName', 'unknown device')}",
                payload={
                    "device_id": _text(row, "DeviceID"),
                    "device_name": _text(row, "DeviceName"),
                    "version": _text(row, "DriverVersion"),
                    "driver_date": _text(row, "DriverDate"),
                    "manufacturer": _text(row, "Manufacturer"),
                    "class": _text(row, "Class"),
                    "signed": bool(row.get("IsSigned", False)),
                },
                severity="high",
                entity=_text(row, "DeviceName"),
                action_on_add="installed",
                action_on_update="updated",
            )
            for row in rows
            if _text(row, "DeviceID")
        ]

    def _services(self, rows: list[dict[str, Any]]) -> list[SnapshotItem]:
        return [
            SnapshotItem(
                source="services",
                key=_text(row, "Name"),
                subsystem=_subsystem_for_service(row),
                display_name=f"Service {_text(row, 'DisplayName', _text(row, 'Name'))}",
                payload={
                    "name": _text(row, "Name"),
                    "display_name": _text(row, "DisplayName"),
                    "state": _text(row, "State"),
                    "start_mode": _text(row, "StartMode"),
                    "start_name": _text(row, "StartName"),
                    "path": _text(row, "PathName"),
                },
                severity="medium",
                entity=_text(row, "Name"),
                action_on_add="added",
                action_on_update="updated",
            )
            for row in rows
            if _text(row, "Name")
        ]

    def _tasks(self, rows: list[dict[str, Any]]) -> list[SnapshotItem]:
        return [
            SnapshotItem(
                source="tasks",
                key=f"{_text(row, 'TaskPath')}|{_text(row, 'TaskName')}",
                subsystem="startup",
                display_name=f"Scheduled task {_text(row, 'TaskPath')}{_text(row, 'TaskName')}",
                payload={
                    "name": _text(row, "TaskName"),
                    "path": _text(row, "TaskPath"),
                    "state": _text(row, "State"),
                    "author": _text(row, "Author"),
                },
                severity="medium",
                entity=_text(row, "TaskName"),
                action_on_add="added",
                action_on_update="updated",
            )
            for row in rows
            if _text(row, "TaskName")
        ]

    def _startup(self, rows: list[dict[str, Any]]) -> list[SnapshotItem]:
        return [
            SnapshotItem(
                source="startup",
                key=f"{_text(row, 'Location')}|{_text(row, 'Name')}|{_text(row, 'User')}",
                subsystem="startup",
                display_name=f"Startup entry {_text(row, 'Name')}",
                payload={
                    "name": _text(row, "Name"),
                    "command": _text(row, "Command"),
                    "location": _text(row, "Location"),
                    "user": _text(row, "User"),
                },
                severity="medium",
                entity=_text(row, "Name"),
                action_on_add="added",
                action_on_update="updated",
            )
            for row in rows
            if _text(row, "Name")
        ]

    def _devices(self, rows: list[dict[str, Any]]) -> list[SnapshotItem]:
        return [
            SnapshotItem(
                source="devices",
                key=_text(row, "InstanceId"),
                subsystem=_subsystem_for_device(row),
                display_name=f"Device {_text(row, 'FriendlyName', 'unknown device')}",
                payload={
                    "instance_id": _text(row, "InstanceId"),
                    "name": _text(row, "FriendlyName"),
                    "class": _text(row, "Class"),
                    "status": _text(row, "Status"),
                    "manufacturer": _text(row, "Manufacturer"),
                },
                severity="medium",
                entity=_text(row, "FriendlyName"),
                action_on_add="added",
                action_on_update="updated",
            )
            for row in rows
            if _text(row, "InstanceId")
        ]

    def collect_symptoms(self, since: datetime) -> list[Event]:
        if platform.system() != "Windows":
            return []
        start = (since - timedelta(minutes=2)).astimezone().isoformat()
        script = rf'''
$start = [DateTime]::Parse("{start}").ToUniversalTime()
$queries = @(
    @{{ LogName = "Application"; Id = @(1000, 1002) }},
    @{{ LogName = "System"; Id = @(41, 4101, 6008) }}
)
$rows = @()
foreach ($query in $queries) {{
    $rows += @(Get-WinEvent -FilterHashtable @{{ LogName = $query.LogName; Id = $query.Id; StartTime = $start }} -ErrorAction SilentlyContinue | Select-Object -First 300 | ForEach-Object {{
        $message = ""
        try {{ $message = $_.Message }} catch {{ $message = "" }}
        [pscustomobject]@{{
            TimeCreated = $_.TimeCreated.ToUniversalTime().ToString("o")
            Id = [int]$_.Id
            LogName = [string]$_.LogName
            ProviderName = [string]$_.ProviderName
            Level = [string]$_.LevelDisplayName
            RecordId = [string]$_.RecordId
            Message = if ($message.Length -gt 1600) {{ $message.Substring(0, 1600) }} else {{ $message }}
        }}
    }})
}}
$rows | Sort-Object TimeCreated | ConvertTo-Json -Depth 5 -Compress
'''
        try:
            rows = run_json(script, timeout=60)
        except (PowerShellError, OSError, TimeoutError) as exc:
            self.last_errors.append(f"eventlog: {exc}")
            return []
        events: list[Event] = []
        for row in rows:
            try:
                occurred_at = parse_datetime(_text(row, "TimeCreated"))
                event_number = int(row.get("Id", 0) or 0)
            except (AttributeError, TypeError, ValueError):
                # One malformed provider row must not make us discard the
                # valid Event Log rows that followed it.
                self.last_errors.append("eventlog: skipped malformed event row")
                continue
            log_name = _text(row, "LogName")
            record_id = _text(row, "RecordId")
            raw_message = _text(row, "Message")
            if record_id.isdecimal() and log_name in {"Application", "System"}:
                event_id = f"eventlog:{log_name}:{record_id}"
            else:
                # RecordId is normally present. When it is not, use a stable
                # opaque identity instead of collapsing all rows from a log
                # into the same deduplication key.
                fallback = "\x1f".join(
                    (
                        iso_datetime(occurred_at),
                        str(event_number),
                        log_name,
                        _text(row, "ProviderName"),
                        raw_message,
                    )
                )
                event_id = "eventlog:fallback:" + hashlib.sha256(fallback.encode("utf-8")).hexdigest()
            if event_number == 4101:
                title, subsystem, action, severity = "Display driver reset detected", "graphics", "driver_reset", "high"
            elif event_number == 41:
                title, subsystem, action, severity = "Unexpected restart detected", "general", "unexpected_restart", "critical"
            elif event_number == 6008:
                title, subsystem, action, severity = "Unexpected shutdown detected", "general", "unexpected_shutdown", "high"
            elif event_number == 1002:
                title, subsystem, action, severity = "Application hang detected", "application", "hang", "high"
            elif event_number == 1000:
                title, subsystem, action, severity = "Application crash detected", infer_subsystem(raw_message), "crash", "high"
            else:
                title, subsystem, action, severity = "Windows reliability event detected", infer_subsystem(raw_message), "reliability_event", "medium"
            application_name = extract_safe_application_name(raw_message) if event_number in {1000, 1002} else None
            details = {
                "event_id": event_number,
                "log_name": log_name,
                "provider": _text(row, "ProviderName"),
                "level": _text(row, "Level"),
                "record_id": record_id,
                "message": redact_text(raw_message),
            }
            if application_name:
                details["application_name"] = application_name
            events.append(
                Event(
                    occurred_at=occurred_at,
                    kind="symptom",
                    subsystem=subsystem,
                    action=action,
                    title=title,
                    entity=application_name or _text(row, "ProviderName"),
                    severity=severity,
                    source="eventlog",
                    details=details,
                    event_id=event_id,
                )
            )
        return events
