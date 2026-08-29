from __future__ import annotations

"""Small, privacy-safe host health snapshot for the local desktop UI."""

import ctypes
import os
from pathlib import Path
import shutil
import time
from typing import Any


class _MemoryStatusEx(ctypes.Structure):
    _fields_ = [
        ("length", ctypes.c_ulong),
        ("memory_load", ctypes.c_ulong),
        ("total_physical", ctypes.c_ulonglong),
        ("available_physical", ctypes.c_ulonglong),
        ("total_page_file", ctypes.c_ulonglong),
        ("available_page_file", ctypes.c_ulonglong),
        ("total_virtual", ctypes.c_ulonglong),
        ("available_virtual", ctypes.c_ulonglong),
        ("available_extended_virtual", ctypes.c_ulonglong),
    ]


def _windows_memory() -> tuple[int | None, int | None, float | None]:
    if os.name != "nt":
        return None, None, None
    status = _MemoryStatusEx()
    status.length = ctypes.sizeof(status)
    try:
        populated = ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status))
    except (AttributeError, OSError):
        return None, None, None
    if not populated:
        return None, None, None
    return (
        int(status.total_physical),
        int(status.available_physical),
        float(status.memory_load),
    )


def _windows_uptime_seconds() -> int | None:
    if os.name != "nt":
        return None
    try:
        get_tick_count = ctypes.windll.kernel32.GetTickCount64
        get_tick_count.restype = ctypes.c_ulonglong
        return max(0, int(get_tick_count() // 1000))
    except (AttributeError, OSError):
        return None


def _system_drive_usage() -> tuple[int | None, int | None, float | None]:
    if os.name == "nt":
        drive = os.environ.get("SystemDrive", "C:")
        root = Path(f"{drive}\\")
    else:
        root = Path("/")
    try:
        usage = shutil.disk_usage(root)
    except OSError:
        return None, None, None
    used_percent = (usage.used / usage.total * 100.0) if usage.total else None
    return int(usage.total), int(usage.free), round(used_percent, 1) if used_percent is not None else None


def system_health_snapshot() -> dict[str, Any]:
    """Return aggregate machine health values without names, paths, or process data."""

    memory_total, memory_available, memory_percent = _windows_memory()
    disk_total, disk_free, disk_percent = _system_drive_usage()
    return {
        "captured_at_epoch": int(time.time()),
        "uptime_seconds": _windows_uptime_seconds(),
        "memory_total_bytes": memory_total,
        "memory_available_bytes": memory_available,
        "memory_used_percent": memory_percent,
        "system_disk_total_bytes": disk_total,
        "system_disk_free_bytes": disk_free,
        "system_disk_used_percent": disk_percent,
    }
