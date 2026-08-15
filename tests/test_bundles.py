import json
import tempfile
import unittest
from pathlib import Path
from datetime import timedelta
from unittest.mock import patch

from difftrail.bundles import BUNDLE_FORMAT, export_bundle, load_bundle, validate_bundle, write_bundle
from difftrail.db import Database
from difftrail.models import Event, IncidentRequest, utc_now


class BundleTests(unittest.TestCase):
    def test_export_round_trip_excludes_sensitive_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            database_path = Path(folder) / "journal.db"
            with Database(database_path) as database:
                now = utc_now()
                database.save_events(
                    [
                        Event(
                            now,
                            "symptom",
                            "application",
                            "crash",
                            "Application crash detected",
                            entity="Example.exe",
                            source="eventlog",
                            details={
                                "message": r"Faulting application name: C:\Users\Raven\Game.exe",
                                "application_name": "Game.exe",
                                "process_id": 1234,
                            },
                        )
                    ]
                )
                bundle = export_bundle(database, days=30, as_of=now + timedelta(minutes=1))
                output = write_bundle(bundle, Path(folder) / "report.json", database_path=database_path)

            loaded, report = load_bundle(output)
            self.assertTrue(report["valid"])
            encoded = json.dumps(loaded["journal"])
            self.assertNotIn("Faulting application name", encoded)
            self.assertNotIn("C:\\Users\\Raven", encoded)
            self.assertNotIn("process_id", encoded)
            self.assertNotIn("start_name", encoded)

    def test_export_replaces_non_profile_absolute_paths_in_safe_metadata(self) -> None:
        with Database(":memory:") as database:
            now = utc_now()
            database.save_events(
                [
                    Event(
                        now,
                        "change",
                        "application",
                        "updated",
                        r"Tool C:\Program Files\Example\tool.exe updated",
                        entity=r"C:\Program Files\Example\tool.exe",
                        source="apps",
                    )
                ]
            )
            bundle = export_bundle(database, as_of=now + timedelta(minutes=1))
            encoded = json.dumps(bundle["journal"])
            self.assertNotIn(r"C:\Program Files", encoded)
            self.assertIn("<path>", encoded)

    def test_export_excludes_forward_slash_profile_paths(self) -> None:
        with Database(":memory:") as database:
            now = utc_now()
            database.save_events(
                [
                    Event(
                        now,
                        "change",
                        "application",
                        "updated",
                        "Tool C:/Users/Alice/Private/report.txt updated",
                        entity="C:/Users/Alice/Private/report.txt",
                        source="apps",
                    )
                ]
            )
            bundle = export_bundle(database, as_of=now + timedelta(minutes=1))
            encoded = json.dumps(bundle["journal"])
            self.assertNotIn("Alice", encoded)
            self.assertNotIn("C:/Users", encoded)
            self.assertIn("<path>", encoded)

    def test_export_excludes_forward_slash_unc_paths(self) -> None:
        with Database(":memory:") as database:
            now = utc_now()
            database.save_events(
                [
                    Event(
                        now,
                        "change",
                        "application",
                        "updated",
                        "Tool //server/share/private/report.txt updated",
                        entity="//server/share/private/report.txt",
                        source="apps",
                    )
                ]
            )
            bundle = export_bundle(database, as_of=now + timedelta(minutes=1))
            encoded = json.dumps(bundle["journal"])
            self.assertNotIn("//server/share", encoded)
            self.assertIn("<path>", encoded)

    def test_validator_rejects_deeply_nested_shapes_without_recursion_error(self) -> None:
        nested: object = "leaf"
        for _ in range(100):
            nested = {"nested": nested}
        report = validate_bundle({"format": BUNDLE_FORMAT, "format_version": 1, "journal": {}, "nested": nested})
        self.assertFalse(report["valid"])
        self.assertIn("Bundle nesting exceeds 64 levels", report["errors"])

    def test_export_keeps_more_than_the_ui_event_limit(self) -> None:
        with Database(":memory:") as database:
            now = utc_now()
            database.save_events(
                [
                    Event(
                        now - timedelta(seconds=10_001 - index),
                        "change",
                        "graphics",
                        "updated",
                        f"Synthetic event {index}",
                        source="test",
                        event_id=f"bundle-{index}",
                    )
                    for index in range(10_001)
                ]
            )
            bundle = export_bundle(database, as_of=now + timedelta(minutes=1))

            self.assertEqual(len(bundle["journal"]["events"]), 10_001)
            self.assertEqual(bundle["journal"]["event_summary"]["changes"], 10_001)
            self.assertFalse(bundle["journal"]["events_truncated"])

    def test_export_tolerates_malformed_aggregate_counts(self) -> None:
        with Database(":memory:") as database, patch.object(
            database,
            "event_summary",
            return_value={
                "changes": "not-a-count",
                "symptoms": float("inf"),
                "changes_by_source": {"safe": "not-a-count"},
                "changes_by_subsystem": {"general": float("inf")},
                "symptoms_by_subsystem": {},
            },
        ):
            bundle = export_bundle(database, as_of=utc_now())

        summary = bundle["journal"]["event_summary"]
        self.assertEqual(summary["changes"], 0)
        self.assertEqual(summary["symptoms"], 0)
        self.assertEqual(summary["changes_by_source"], {})
        self.assertEqual(summary["changes_by_subsystem"], {})

    def test_export_redacts_aggregate_labels_as_well_as_event_values(self) -> None:
        with Database(":memory:") as database:
            now = utc_now()
            database.save_events(
                [
                    Event(
                        now,
                        "change",
                        "general",
                        "updated",
                        "Synthetic change",
                        source="test",
                        event_id="aggregate-redaction",
                    )
                ]
            )
            database.connection.execute(
                "UPDATE events SET source = ?, subsystem = ? WHERE id = ?",
                (r"C:\Users\Alice\Secret", r"C:\Users\Alice\Subsystem", "aggregate-redaction"),
            )
            database.connection.commit()
            bundle = export_bundle(database, as_of=now + timedelta(minutes=1))

            encoded = json.dumps(bundle)
            self.assertNotIn("Alice", encoded)
            self.assertNotIn(r"C:\Users", encoded)
            self.assertTrue(validate_bundle(bundle)["valid"])

    def test_export_redacts_malformed_path_event_ids(self) -> None:
        with Database(":memory:") as database:
            now = utc_now()
            database.save_events(
                [
                    Event(
                        now,
                        "change",
                        "general",
                        "updated",
                        "Synthetic change",
                        source="test",
                        event_id=r"C:\Users\Alice\private-event",
                    )
                ]
            )
            bundle = export_bundle(database, as_of=now + timedelta(minutes=1))
            encoded = json.dumps(bundle)
            self.assertNotIn("Alice", encoded)
            self.assertNotIn(r"C:\Users", encoded)
            self.assertTrue(validate_bundle(bundle)["valid"])

    def test_export_preserves_urls_without_treating_them_as_unc_paths(self) -> None:
        with Database(":memory:") as database:
            now = utc_now()
            database.save_events(
                [
                    Event(
                        now,
                        "change",
                        "general",
                        "updated",
                        "See https://example.com/docs for details",
                        source="test",
                    )
                ]
            )
            bundle = export_bundle(database, as_of=now + timedelta(minutes=1))
            self.assertIn("https://example.com/docs", json.dumps(bundle))
            self.assertTrue(validate_bundle(bundle)["valid"])

    def test_validator_rejects_tampering_and_sensitive_fields(self) -> None:
        invalid = {
            "format": "difftrail-diagnostic-bundle",
            "format_version": 1,
            "integrity": {"sha256": "wrong"},
            "journal": {"events": [{"message": "secret"}]},
        }
        report = validate_bundle(invalid)
        self.assertFalse(report["valid"])
        self.assertTrue(any("Forbidden sensitive field" in error for error in report["errors"]))
        self.assertIn("Bundle integrity digest does not match its contents", report["errors"])

    def test_validator_does_not_echo_sensitive_field_names(self) -> None:
        report = validate_bundle(
            {
                "format": BUNDLE_FORMAT,
                "format_version": 1,
                "integrity": {"sha256": "wrong"},
                "journal": {r"C:\Users\Alice\private": {"message": "secret"}},
            }
        )
        self.assertFalse(report["valid"])
        self.assertNotIn("Alice", json.dumps(report))
        self.assertNotIn(r"C:\Users", json.dumps(report))

    def test_validator_reports_malformed_shapes_without_crashing(self) -> None:
        report = validate_bundle({"format": BUNDLE_FORMAT, "format_version": 1, "journal": None})
        self.assertFalse(report["valid"])
        self.assertIn("Journal must be an object", report["errors"])

    def test_bundle_cannot_overwrite_live_database(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "journal.db"
            with Database(path) as database:
                bundle = export_bundle(database)
                with self.assertRaises(ValueError):
                    write_bundle(bundle, path, database_path=path)
                with self.assertRaises(ValueError):
                    write_bundle(bundle, Path(f"{path}-wal"), database_path=path)
                with self.assertRaises(ValueError):
                    write_bundle(bundle, Path(f"{path}-shm"), database_path=path)

    def test_bundle_buckets_colonless_scan_errors_without_leaking_text(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "journal.db"
            with Database(path) as database:
                now = utc_now()
                scan_id = database.start_scan(now)
                database.finish_scan(scan_id, now, "partial", {"errors": ["private provider secret"]})
                bundle = export_bundle(database, as_of=now + timedelta(minutes=1))

            encoded = json.dumps(bundle)
            self.assertNotIn("private provider secret", encoded)
            self.assertEqual(bundle["journal"]["scans"][0]["summary"]["error_buckets"], ["other"])

    def test_incident_bundle_keeps_export_time_separate_from_period_end(self) -> None:
        with Database(":memory:") as database:
            now = utc_now()
            incident = database.create_incident(
                IncidentRequest("graphics failed", now - timedelta(hours=2), now, "graphics", 7)
            )
            exported_at = now + timedelta(hours=1)
            bundle = export_bundle(database, incident_id=incident.id, as_of=exported_at)
            self.assertEqual(bundle["exported_at"], exported_at.isoformat(timespec="seconds").replace("+00:00", "Z"))
            self.assertEqual(bundle["period"]["end"], now.isoformat(timespec="seconds").replace("+00:00", "Z"))

    def test_incident_bundle_preserves_candidate_tie_count(self) -> None:
        with Database(":memory:") as database:
            now = utc_now()
            incident = database.create_incident(
                IncidentRequest("graphics failed", now - timedelta(hours=2), now, "graphics", 7)
            )
            database.update_incident_results(
                incident.id,
                [
                    {
                        "score": 0.8,
                        "tie_count": 3,
                        "confidence": "Medium",
                        "event": Event(
                            now - timedelta(hours=1),
                            "change",
                            "graphics",
                            "updated",
                            "Display driver updated",
                            source="drivers",
                        ).as_dict(),
                        "evidence": [],
                        "counter_evidence": [],
                        "next_action": "Review the evidence.",
                        "safe_diagnostic": {},
                    }
                ],
            )

            bundle = export_bundle(database, incident_id=incident.id, as_of=now)

            self.assertEqual(bundle["investigations"][0]["results"][0]["tie_count"], 3)
