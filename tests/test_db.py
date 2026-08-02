import tempfile
import unittest
from datetime import timedelta
from pathlib import Path

from difftrail.db import Database
from difftrail.models import Event, IncidentRequest, SnapshotItem, utc_now


class DatabaseTests(unittest.TestCase):
    def test_first_snapshot_is_quiet_and_second_snapshot_emits_transition(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            with Database(Path(folder) / "journal.db") as database:
                now = utc_now()
                first = SnapshotItem("services", "svc", "startup", "Service Example", {"state": "Stopped"})
                self.assertEqual(database.apply_snapshot("services", [first], occurred_at=now), [])
                changed = SnapshotItem("services", "svc", "startup", "Service Example", {"state": "Running"})
                events = database.apply_snapshot("services", [changed], occurred_at=now + timedelta(minutes=5))
                self.assertEqual(len(events), 1)
                self.assertEqual(events[0].action, "updated")
                self.assertEqual(database.count_events("change"), 1)

    def test_incident_and_events_round_trip(self) -> None:
        with Database(":memory:") as database:
            now = utc_now()
            event = Event(now, "change", "graphics", "updated", "Display driver updated", source="test")
            database.save_events([event])
            request = IncidentRequest("graphics are crashing", now - timedelta(hours=1), now, "graphics", 7)
            incident = database.create_incident(request)
            database.update_incident_results(incident.id, [{"confidence": "High"}])
            self.assertEqual(database.count_events(), 1)
            self.assertEqual(database.recent_incidents()[0]["results"][0]["confidence"], "High")

    def test_duplicate_events_report_only_inserted_rows(self) -> None:
        with Database(":memory:") as database:
            now = utc_now()
            event = Event(now, "change", "graphics", "updated", "Display driver updated", source="test")
            self.assertEqual(database.save_events([event, event]), 1)
            self.assertEqual(database.count_events(), 1)

    def test_status_exposes_structured_last_scan_summary(self) -> None:
        with Database(":memory:") as database:
            now = utc_now()
            scan_id = database.start_scan(now)
            database.finish_scan(scan_id, now, "partial", {"errors": ["provider unavailable"]})
            status = database.status()
            self.assertEqual(status["last_scan"]["status"], "partial")
            self.assertEqual(status["last_scan"]["summary"]["errors"], ["provider unavailable"])

    def test_old_symptom_messages_are_pruned_but_event_remains(self) -> None:
        with Database(":memory:") as database:
            now = utc_now()
            old = Event(now - timedelta(days=31), "symptom", "application", "crash", "Application crash", source="test", details={"message": "private raw event text"})
            database.save_events([old])
            self.assertEqual(database.prune_sensitive_symptom_details(as_of=now), 1)
            stored = database.list_events(kind="symptom")[0]
            self.assertNotIn("message", stored.details)
            self.assertFalse(stored.details["raw_message_retained"])

    def test_search_source_status_and_retention_setting(self) -> None:
        with Database(":memory:") as database:
            database.set_retention_days(14)
            self.assertEqual(database.retention_days(), 14)
            now = utc_now()
            item = SnapshotItem("drivers", "gpu", "graphics", "GPU driver", {"version": "1"})
            database.apply_snapshot("drivers", [item], occurred_at=now)
            database.save_events([Event(now, "change", "graphics", "updated", "GPU driver updated", source="drivers")])
            self.assertEqual(len(database.list_events(search="GPU")), 1)
            source = next(item for item in database.source_status() if item["source"] == "drivers")
            self.assertEqual(source["status"], "capturing")
            self.assertEqual(source["item_count"], 1)
