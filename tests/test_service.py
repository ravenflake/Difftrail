import unittest
from datetime import datetime, timezone

from difftrail.db import Database
from difftrail.models import Event, SnapshotItem
from difftrail.service import Scanner


class FakeCollector:
    def __init__(self) -> None:
        self.snapshots = {"services": [SnapshotItem("services", "demo", "startup", "Service Demo", {"state": "Stopped", "start_mode": "Auto"})]}

    def collect_snapshots(self):
        return self.snapshots

    def collect_symptoms(self, since: datetime):
        return [Event(datetime.now(timezone.utc), "symptom", "startup", "failure", "Service failure", source="fake", event_id="fake-symptom")]


class ServiceTests(unittest.TestCase):
    def test_scan_builds_quiet_baseline_then_records_events(self) -> None:
        with Database(":memory:") as database:
            collector = FakeCollector()
            first = Scanner(database, collector).scan()
            self.assertEqual(first.state_events, 0)
            self.assertEqual(first.symptom_events, 1)
            collector.snapshots["services"][0] = SnapshotItem("services", "demo", "startup", "Service Demo", {"state": "Running", "start_mode": "Manual"})
            second = Scanner(database, collector).scan()
            self.assertEqual(second.state_events, 1)
            self.assertEqual(database.count_events("change"), 1)

    def test_collector_failure_finishes_as_partial_scan(self) -> None:
        class BrokenCollector:
            def collect_snapshots(self):
                raise RuntimeError("provider unavailable")

            def collect_symptoms(self, since):
                raise RuntimeError("event log unavailable")

        with Database(":memory:") as database:
            result = Scanner(database, BrokenCollector()).scan()
            self.assertEqual(result.status, "partial")
            self.assertEqual(len(result.errors), 2)
            self.assertEqual(database.status()["last_scan"]["status"], "partial")

    def test_provider_diagnostics_make_an_otherwise_successful_scan_partial(self) -> None:
        class DegradedCollector:
            def __init__(self) -> None:
                self.last_errors = []

            def collect_snapshots(self):
                self.last_errors.append("drivers: provider unavailable")
                return {}

            def collect_symptoms(self, since):
                return []

        with Database(":memory:") as database:
            result = Scanner(database, DegradedCollector()).scan()
            self.assertEqual(result.status, "partial")
            self.assertIn("collector: drivers: provider unavailable", result.errors)
