import json
import unittest
from datetime import timedelta

from difftrail.db import Database
from difftrail.host_validation import build_host_validation_report
from difftrail.models import Event, IncidentRequest, utc_now


class HostValidationTests(unittest.TestCase):
    def test_report_aggregates_scans_overhead_and_labeled_top_three_outcome(self) -> None:
        now = utc_now()
        with Database(":memory:") as database:
            first_scan = database.start_scan(now - timedelta(days=6))
            database.finish_scan(
                first_scan,
                now - timedelta(days=6),
                "ok",
                {"sources": 7, "state_events": 0, "symptom_events": 0, "errors": []},
            )
            second_scan = database.start_scan(now - timedelta(days=1))
            database.finish_scan(
                second_scan,
                now - timedelta(days=1),
                "partial",
                {"sources": 6, "state_events": 2, "symptom_events": 1, "errors": ["drivers: provider unavailable"]},
            )
            database.save_events(
                [
                    Event(
                        now - timedelta(days=1),
                        "change",
                        "graphics",
                        "updated",
                        "Display driver updated",
                        source="drivers",
                        event_id="cause-event",
                    ),
                    Event(
                        now - timedelta(days=1),
                        "change",
                        "application",
                        "updated",
                        "Chat app updated",
                        source="apps",
                        event_id="distractor-event",
                    ),
                    Event(
                        now - timedelta(hours=23),
                        "symptom",
                        "graphics",
                        "driver_reset",
                        "Display driver reset",
                        source="eventlog",
                        event_id="symptom-event",
                    ),
                ]
            )
            incident = database.create_incident(
                IncidentRequest("graphics started failing", now - timedelta(days=1), now, "graphics", 7),
                created_at=now - timedelta(days=1),
            )
            database.update_incident_results(
                incident.id,
                [
                    {"event": {"id": "distractor-event"}},
                    {"event": {"id": "cause-event"}},
                ],
                assessment="candidate_found",
            )
            database.record_incident_feedback(incident.id, "correct", event_id="cause-event", recorded_at=now)
            database.record_overhead_measurement(
                {
                    "interval_seconds": 15,
                    "warmup_seconds": 8,
                    "sample_seconds": 10,
                    "startup_process_tree_cpu_percent": 1.5,
                    "process_tree_cpu_percent": 0.2,
                    "startup_rss_mb_peak": 120.0,
                    "rss_mb_mean": 30.0,
                    "rss_mb_peak": 32.0,
                    "startup_disk_read_mb": 2.0,
                    "startup_disk_write_mb": 0.0,
                    "disk_read_mb": 0.1,
                    "disk_write_mb": 0.0,
                },
                measured_at=now - timedelta(hours=2),
            )

            report = build_host_validation_report(database, days=7, as_of=now)

        self.assertEqual(report["scans"]["total"], 2)
        self.assertEqual(report["scans"]["quiet"], 1)
        self.assertEqual(report["scans"]["provider_error_count"], 1)
        self.assertEqual(report["scans"]["error_buckets"], {"drivers": 1})
        self.assertEqual(report["journal"]["changes"], 2)
        self.assertEqual(report["journal"]["changes_by_source"], {"apps": 1, "drivers": 1})
        self.assertEqual(report["overhead"]["measurements"], 1)
        self.assertEqual(report["investigations"]["correct_cause_top3_hits"], 1)
        self.assertEqual(report["investigations"]["correct_cause_top3_rate"], 1.0)
        self.assertEqual(report["investigations"]["assessment_distribution"], {"candidate_found": 1})
        self.assertNotIn("Display driver updated", json.dumps(report))
        self.assertNotIn("provider unavailable", json.dumps(report))

    def test_feedback_requires_a_real_event_for_correct_outcome(self) -> None:
        with Database(":memory:") as database:
            now = utc_now()
            incident = database.create_incident(IncidentRequest("a problem", now, now, "general", 7))
            with self.assertRaises(ValueError):
                database.record_incident_feedback(incident.id, "correct")
            with self.assertRaises(ValueError):
                database.record_incident_feedback(incident.id, "correct", event_id="missing")
