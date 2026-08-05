import json
import tempfile
import unittest
from pathlib import Path
from datetime import timedelta

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
