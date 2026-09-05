import json
import unittest
from datetime import timedelta

from difftrail.db import Database
from difftrail.host_validation import build_host_validation_report
from difftrail.models import Event, IncidentRequest, utc_now


class HostValidationTests(unittest.TestCase):
    def test_report_tolerates_nonfinite_scan_summary_counts(self) -> None:
        now = utc_now()
        with Database(":memory:") as database:
            scan_id = database.start_scan(now)
            database.finish_scan(
                scan_id,
                now,
                "ok",
                {
                    "sources": float("inf"),
                    "state_events": float("inf"),
                    "symptom_events": float("inf"),
                    "errors": [],
                },
            )

            report = build_host_validation_report(database, days=1, as_of=now)

        self.assertEqual(report["scans"]["reported_changes"], 0)
        self.assertEqual(report["scans"]["reported_symptoms"], 0)
        self.assertEqual(report["scans"]["sources_per_scan_mean"], 0.0)

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
            database.record_incident_feedback(
                incident.id,
                "confirmed_cause",
                event_id="cause-event",
                reason="independent_confirmation",
                recorded_at=now,
            )
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
        self.assertEqual(report["investigations"]["confirmed_cause_top1_hits"], 0)
        self.assertEqual(report["investigations"]["confirmed_cause_top3_hits"], 1)
        self.assertEqual(report["investigations"]["confirmed_cause_top3_rate"], 1.0)
        self.assertEqual(report["investigations"]["outcomes"]["confirmed_cause"], 1)
        self.assertEqual(
            report["investigations"]["rank_distribution_by_outcome"]["confirmed_cause"]["rank_2"],
            1,
        )
        self.assertEqual(
            report["investigations"]["reason_distribution"],
            {"independent_confirmation": 1},
        )
        self.assertEqual(report["investigations"]["assessment_distribution"], {"candidate_found": 1})
        self.assertNotIn("Display driver updated", json.dumps(report))
        self.assertNotIn("provider unavailable", json.dumps(report))

    def test_ranked_outcome_requires_a_ranked_lead(self) -> None:
        with Database(":memory:") as database:
            now = utc_now()
            incident = database.create_incident(IncidentRequest("a problem", now, now, "general", 7))
            with self.assertRaises(ValueError):
                database.record_incident_feedback(
                    incident.id, "confirmed_cause", reason="reproduced"
                )
            with self.assertRaises(ValueError):
                database.record_incident_feedback(
                    incident.id,
                    "confirmed_cause",
                    event_id="missing",
                    reason="reproduced",
                )

    def test_ranked_lead_feedback_survives_event_retention(self) -> None:
        with Database(":memory:") as database:
            now = utc_now()
            event = Event(
                now,
                "change",
                "application",
                "updated",
                "Application updated",
                source="apps",
                event_id="retained-lead",
            )
            database.save_events([event])
            incident = database.create_incident(
                IncidentRequest("the app stopped working", now, now, "application", 7)
            )
            database.update_incident_results(incident.id, [{"event": event.as_dict()}])
            database.connection.execute("DELETE FROM events WHERE id = ?", (event.event_id,))
            database.connection.commit()

            saved = database.record_incident_feedback(
                incident.id,
                "useful_lead",
                event_id=event.event_id,
                reason="guided_diagnostic",
            )

        self.assertEqual(saved["feedback"]["event_id"], "retained-lead")
        self.assertEqual(saved["feedback"]["rank"], 1)

    def test_outcome_validation_freezes_rank_and_records_privacy_safe_miss_reason(self) -> None:
        now = utc_now()
        with Database(":memory:") as database:
            confirmed = database.create_incident(
                IncidentRequest("a verified problem", now, now, "application", 7),
                created_at=now,
            )
            database.update_incident_results(
                confirmed.id,
                [
                    {"event": {"id": "distractor"}},
                    {"event": {"id": "actual-cause"}},
                ],
            )
            database.record_incident_feedback(
                confirmed.id,
                "confirmed_cause",
                event_id="actual-cause",
                reason="reproduced",
                recorded_at=now,
            )
            # Later review edits must not rewrite the rank observed when the
            # real-world outcome was recorded.
            database.update_incident_results(
                confirmed.id,
                [
                    {"event": {"id": "actual-cause"}},
                    {"event": {"id": "distractor"}},
                ],
            )

            missed = database.create_incident(
                IncidentRequest("another verified problem", now, now, "application", 7),
                created_at=now,
            )
            database.record_incident_feedback(
                missed.id,
                "uncaptured_cause",
                reason="between_scans",
                recorded_at=now,
            )
            report = build_host_validation_report(database, days=1, as_of=now)
            repeated_report = build_host_validation_report(database, days=1, as_of=now)

            with self.assertRaisesRegex(ValueError, "must not select"):
                database.record_incident_feedback(
                    missed.id,
                    "uncaptured_cause",
                    event_id="actual-cause",
                    reason="between_scans",
                )
            with self.assertRaisesRegex(ValueError, "reason for confirmed_cause"):
                database.record_incident_feedback(
                    confirmed.id,
                    "confirmed_cause",
                    event_id="actual-cause",
                    reason="between_scans",
                )

        metrics = report["investigations"]
        self.assertEqual(metrics, repeated_report["investigations"])
        self.assertEqual(metrics["known_cause_capture_rate"], 0.5)
        self.assertEqual(metrics["confirmed_cause_top3_rate"], 1.0)
        self.assertEqual(
            metrics["rank_distribution_by_outcome"]["confirmed_cause"]["rank_2"],
            1,
        )
        self.assertEqual(metrics["outcomes"]["uncaptured_cause"], 1)
        self.assertEqual(metrics["reason_distribution"], {"between_scans": 1, "reproduced": 1})
