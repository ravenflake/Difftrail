from __future__ import annotations

from datetime import datetime
from typing import Any

from .collectors.windows import WindowsCollector
from .db import Database
from .models import Event, SnapshotItem, utc_now
from .service import Scanner


class _NvidiaDriverSwitchFixture:
    """Normalized Windows-shaped records for a safe local replay.

    The fixture deliberately goes through WindowsCollector's row normalizers
    and Scanner rather than inserting finished events. It therefore exercises
    the same snapshot diff and evidence path as a real scan, without invoking
    PowerShell or changing Windows state.
    """

    def __init__(self) -> None:
        collector = WindowsCollector()
        self.phase = 0
        self.before = self._snapshots(collector, "31.0.15.5222", "06/01/2025 01:00:00", "nv_studio.inf_amd64_fixture")
        self.after = self._snapshots(collector, "32.0.16.1088", "07/22/2026 02:00:00", "nv_gameready.inf_amd64_fixture")
        self.last_errors: list[str] = []

    @staticmethod
    def _snapshots(
        collector: WindowsCollector,
        driver_version: str,
        driver_date: str,
        package_folder: str,
    ) -> dict[str, list[SnapshotItem]]:
        driver_rows: list[dict[str, Any]] = [
            {
                "DeviceID": r"PCI\VEN_10DE&DEV_2783&FIXTURE",
                "DeviceName": "NVIDIA GeForce RTX 4070 SUPER",
                "DriverVersion": driver_version,
                "DriverDate": driver_date,
                "Manufacturer": "NVIDIA",
                "Class": "{4d36e968-e325-11ce-bfc1-08002be10318}",
                "IsSigned": True,
            }
        ]
        service_rows: list[dict[str, Any]] = [
            {
                "Name": "NVDisplay.ContainerLocalSystem",
                "DisplayName": "NVIDIA Display Container LS",
                "State": "Running",
                "StartMode": "Auto",
                "StartName": "LocalSystem",
                "PathName": rf"C:\Windows\System32\DriverStore\FileRepository\{package_folder}\Display.NvContainer\NVDisplay.Container.exe",
            }
        ]
        return {
            "drivers": collector._drivers(driver_rows),
            "services": collector._services(service_rows),
        }

    def collect_snapshots(self) -> dict[str, list[SnapshotItem]]:
        return self.before if self.phase == 0 else self.after

    def collect_symptoms(self, since: datetime) -> list[Event]:
        if self.phase == 0:
            return []
        return [
            Event(
                occurred_at=utc_now(),
                kind="symptom",
                subsystem="graphics",
                action="driver_reset",
                title="Display driver reset detected",
                entity="NVIDIA GeForce RTX 4070 SUPER",
                severity="high",
                source="fixture:eventlog",
                details={"message": "Simulated display driver stopped responding and recovered."},
                event_id="fixture:nvidia-driver-reset",
            )
        ]


def simulate_nvidia_driver_switch(database: Database) -> dict[str, Any]:
    """Replay a driver-package transition into an empty local database."""

    if not database.is_empty():
        raise ValueError("Simulation requires an empty database; choose a new --db path.")
    fixture = _NvidiaDriverSwitchFixture()
    baseline = Scanner(database, fixture).scan()
    fixture.phase = 1
    change_scan = Scanner(database, fixture).scan()
    return {
        "scenario": "nvidia-driver-switch",
        "description": "Safe fixture replay of an NVIDIA display driver package transition.",
        "safety": "fixture data only; no PowerShell commands or Windows state changes",
        "baseline": baseline.as_dict(),
        "change_scan": change_scan.as_dict(),
        "next_command": f'python -m difftrail --db "{database.path}" investigate "graphics started failing" --subsystem graphics --json',
    }
