"""Bounded, allowlisted runtime diagnostics, including failures before SQLite opens."""
from __future__ import annotations

from collections import Counter
from datetime import datetime
from pathlib import Path
import ctypes
import os
import re

from .models import ensure_utc, iso_datetime

MAX_LOG_BYTES = 2 * 1024 * 1024
_WATCHER_LINE = re.compile(r"^(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d),\d+ (INFO|WARNING|ERROR) (.*)$", re.M)
_STARTUP_LINE = re.compile(r"^\[(\d{1,12})\] Difftrail backend startup failed:", re.M)


def failure_category(error: object) -> str:
    text = str(error).casefold()
    if ("schema version" in text and "not supported" in text) or "schema_incompatible" in text:
        return "schema_incompatible"
    if "scan is already running" in text or "scan_busy" in text:
        return "scan_busy"
    if "locked" in text or "disk" in text or "storage_error" in text:
        return "storage_error"
    return "runtime_error"


def companion_status() -> str:
    """Check this session's companion mutex; never return a PID or executable path."""
    if os.name != "nt":
        return "unsupported"
    try:
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.OpenMutexW.argtypes = [ctypes.c_ulong, ctypes.c_int, ctypes.c_wchar_p]
        kernel.OpenMutexW.restype = ctypes.c_void_p
        kernel.CloseHandle.argtypes = [ctypes.c_void_p]
        handle = kernel.OpenMutexW(0x00100000, False, "Local\\DifftrailStatusIcon")
        if not handle:
            return "not_running" if ctypes.get_last_error() == 2 else "unknown"
        kernel.CloseHandle(handle)
        return "running"
    except (OSError, AttributeError):
        return "unknown"


def runtime_health(database_path: Path, *, start: datetime, end: datetime) -> dict:
    start, end = ensure_utc(start), ensure_utc(end)
    counts: Counter[str] = Counter()
    categories: Counter[str] = Counter()
    times: list[datetime] = []
    failures: list[datetime] = []
    available = 0
    unreadable = 0
    truncated = False
    # Logs belong to the selected journal directory. Never mix a disposable
    # journal with the user's installed-runtime history.
    paths = [] if str(database_path) == ":memory:" else [
        (database_path.parent / name, kind)
        for name, kind in (("watcher.log.2", "watcher"), ("watcher.log.1", "watcher"),
                           ("watcher.log", "watcher"), ("startup-errors.log", "desktop"))
    ]
    for path, kind in paths:
        try:
            with path.open("rb") as stream:
                size = stream.seek(0, 2)
                offset = max(0, size - MAX_LOG_BYTES)
                stream.seek(offset)
                raw = stream.read(MAX_LOG_BYTES)
            available += 1
        except FileNotFoundError:
            continue
        except OSError:
            unreadable += 1
            continue
        if offset:
            truncated = True
            raw = raw.partition(b"\n")[2]
        text = raw.decode("utf-8", errors="replace")
        matches = list((_WATCHER_LINE if kind == "watcher" else _STARTUP_LINE).finditer(text))
        for index, match in enumerate(matches):
            try:
                timestamp = (datetime.strptime(match[1], "%Y-%m-%d %H:%M:%S").astimezone()
                             if kind == "watcher" else datetime.fromtimestamp(int(match[1])).astimezone())
                timestamp = ensure_utc(timestamp)
            except (ValueError, OverflowError, OSError):
                continue
            times.append(timestamp)
            if not start <= timestamp <= end:
                continue
            block = text[match.start():matches[index + 1].start() if index + 1 < len(matches) else len(text)]
            if kind == "desktop" or (match[2] == "ERROR" and "Background scan failed" in match[3]):
                counts[f"{kind}_failures"] += 1
                categories[failure_category(block)] += 1
                failures.append(timestamp)
            elif kind == "watcher" and "Background scan completed" in match[3]:
                counts["watcher_completions"] += 1
                if match[2] == "WARNING":
                    counts["watcher_partial"] += 1
    return {
        "status": "unavailable" if not available else "partial" if truncated or unreadable else "available",
        "watcher_failures": counts["watcher_failures"],
        "desktop_failures": counts["desktop_failures"],
        "watcher_completions": counts["watcher_completions"],
        "watcher_partial": counts["watcher_partial"],
        "failure_categories": dict(sorted(categories.items())),
        "last_failure_at": iso_datetime(max(failures)) if failures else None,
        "earliest_log_at": iso_datetime(min(times)) if times else None,
        "companion": companion_status(),
        "limits": "Retained local logs only; failures may precede a journal scan. Counts are not added to scan totals. Missing or rotated logs cannot prove uninterrupted operation.",
    }
