import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

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

    def test_malformed_top_level_snapshots_finish_the_scan_as_partial(self) -> None:
        class MalformedCollector:
            def collect_snapshots(self):
                return None

            def collect_symptoms(self, since):
                return []

        with Database(":memory:") as database:
            result = Scanner(database, MalformedCollector()).scan()
            self.assertEqual(result.status, "partial")
            self.assertIn("invalid snapshot payload", " ".join(result.errors))
            scan = database.list_scans(limit=1)[0]
            self.assertEqual(scan["status"], "partial")
            self.assertIsNotNone(scan["finished_at"])

    def test_retention_runs_when_symptom_collection_fails(self) -> None:
        class BrokenSymptomsCollector:
            def collect_snapshots(self):
                return {}

            def collect_symptoms(self, since):
                raise RuntimeError("event log unavailable")

        with Database(":memory:") as database:
            database.save_events(
                [
                    Event(
                        datetime.now(timezone.utc) - timedelta(days=31),
                        "symptom",
                        "application",
                        "crash",
                        "Old crash",
                        source="eventlog",
                        details={"message": "sensitive legacy message"},
                    )
                ]
            )
            result = Scanner(database, BrokenSymptomsCollector()).scan()
            self.assertEqual(result.status, "partial")
            details = database.list_events(kind="symptom")[0].details
            self.assertNotIn("message", details)
            self.assertFalse(details["raw_message_retained"])

    def test_scan_finishes_when_symptom_cursor_metadata_write_fails(self) -> None:
        class EmptyCollector:
            def collect_snapshots(self):
                return {}

            def collect_symptoms(self, since):
                return []

        with Database(":memory:") as database:
            database.connection.execute(
                """
                CREATE TRIGGER fail_symptom_cursor_meta BEFORE INSERT ON meta
                WHEN NEW.key = 'symptoms:cursor'
                BEGIN SELECT RAISE(ABORT, 'injected symptom cursor metadata failure'); END
                """
            )
            database.connection.commit()

            result = Scanner(database, EmptyCollector()).scan()
            self.assertEqual(result.status, "partial")
            self.assertIn("symptoms:", " ".join(result.errors))
            scan = database.list_scans(limit=1)[0]
            self.assertEqual(scan["status"], "partial")
            self.assertIsNotNone(scan["finished_at"])

    def test_long_running_watcher_retries_after_automation_failure(self) -> None:
        with Database(":memory:") as database, patch(
            "difftrail.automation.run_automated_scan",
            side_effect=[RuntimeError("temporary write failure"), None, KeyboardInterrupt()],
        ) as run, patch("difftrail.service.time.sleep"):
            with self.assertRaises(KeyboardInterrupt):
                Scanner(database).watch(interval_seconds=15)

        self.assertEqual(run.call_count, 3)

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
