from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from datetime import timedelta
from typing import Any

from .collectors.base import Collector
from .collectors.windows import WindowsCollector
from .db import Database
from .models import utc_now
from .privacy import redact_text


LOGGER = logging.getLogger(__name__)


@dataclass(frozen=True)
class ScanResult:
    scan_id: str
    status: str
    sources: int
    state_events: int
    symptom_events: int
    errors: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "status": self.status,
            "sources": self.sources,
            "state_events": self.state_events,
            "symptom_events": self.symptom_events,
            "errors": list(self.errors),
        }


class Scanner:
    def __init__(self, database: Database, collector: Collector | None = None) -> None:
        self.database = database
        self.collector = collector or WindowsCollector()

    def scan(self) -> ScanResult:
        started = utc_now()
        scan_id = self.database.start_scan(started)
        state_events = 0
        symptom_events = 0
        errors: list[str] = []
        collector_errors = getattr(self.collector, "last_errors", None)
        if isinstance(collector_errors, list):
            collector_errors.clear()
        try:
            snapshots = self.collector.collect_snapshots()
            if not isinstance(snapshots, dict):
                raise ValueError("Collector returned an invalid snapshot payload")
        except Exception as exc:
            snapshots = {}
            errors.append(f"snapshots: {redact_text(str(exc))}")
        for source, items in snapshots.items():
            try:
                state_events += len(
                    self.database.apply_snapshot(source, items, occurred_at=started, scan_id=scan_id)
                )
            except Exception as exc:  # a bad provider must not lose the whole scan
                errors.append(f"{source}: {redact_text(str(exc))}")
        cursor = self.database.get_meta("symptoms:cursor")
        since = started - timedelta(days=7)
        if cursor:
            try:
                from .models import parse_datetime

                since = parse_datetime(cursor)
            except ValueError:
                pass
        try:
            symptoms = self.collector.collect_symptoms(since)
            symptom_events = self.database.save_events(symptoms, scan_id=scan_id)
            self.database.set_meta_for_active_scan(scan_id, "symptoms:cursor", started.isoformat())
        except Exception as exc:
            errors.append(f"symptoms: {redact_text(str(exc))}")
        try:
            # Retention is independent of the provider's current health. A
            # transient Event Log failure must not retain old raw messages.
            self.database.prune_sensitive_symptom_details(
                retain_days=self.database.retention_days(), as_of=started, scan_id=scan_id
            )
        except Exception as exc:
            errors.append(f"retention: {redact_text(str(exc))}")
        if isinstance(collector_errors, list):
            errors.extend(f"collector: {redact_text(str(error))}" for error in collector_errors)
        finished = utc_now()
        status = "partial" if errors else "ok"
        result = ScanResult(scan_id, status, len(snapshots), state_events, symptom_events, tuple(errors))
        self.database.finish_scan(scan_id, finished, status, result.as_dict())
        return result

    def watch(self, interval_seconds: int = 300) -> None:
        if interval_seconds < 15 or interval_seconds > 86_400:
            raise ValueError("The watcher interval must be between 15 and 86400 seconds")
        from .automation import run_automated_scan

        while True:
            try:
                run_automated_scan(self.database, self)
            except Exception:
                # A transient automation-write failure must not turn a
                # long-running watcher into a one-shot worker. Its cursor is
                # deliberately left behind for the next pass to retry.
                LOGGER.warning("Difftrail watcher pass failed; it will retry at the next interval.")
            time.sleep(interval_seconds)
