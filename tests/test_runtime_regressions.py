import contextlib
from datetime import datetime, timedelta, timezone
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from difftrail.collectors.windows import WindowsCollector
from difftrail.correlation import rank_candidates
from difftrail.automation import process_scan_events
from difftrail.db import Database
from difftrail.host_validation import build_host_validation_report
from difftrail.runtime_health import runtime_health
from difftrail.service import Scanner
from difftrail.models import Event, IncidentRequest
from types import SimpleNamespace
from difftrail.ui_api import serve
from difftrail.watcher import run_once, LOGGER


class DriverObservationTests(unittest.TestCase):
    def test_scanner_disconnect_reconnect_and_offline_version_change(self):
        row = {"DeviceID": "USB\\SYNTHETIC", "DeviceName": "Fixture audio", "DriverVersion": "1", "Class": "Audio"}
        device = {"InstanceId": row["DeviceID"], "FriendlyName": row["DeviceName"], "Class": "Audio"}
        collector = WindowsCollector()
        with Database(":memory:") as db, patch.object(collector, "collect_symptoms", return_value=[]), patch.object(collector, "collect_snapshots") as collect:
            collect.return_value = {"drivers": collector._drivers([row]), "devices": collector._devices([device])}
            scanner = Scanner(db, collector)
            self.assertEqual(scanner.scan().state_events, 0)
            old_seen = db.connection.execute("select last_seen_at from state_items where source='drivers'").fetchone()[0]
            collect.return_value = {"drivers": [], "devices": []}
            self.assertEqual(scanner.scan().state_events, 1)  # device only
            self.assertEqual(db.connection.execute("select last_seen_at from state_items where source='drivers'").fetchone()[0], old_seen)
            collect.return_value = {"drivers": collector._drivers([row]), "devices": collector._devices([device])}
            self.assertEqual(scanner.scan().state_events, 1)  # device only
            collect.return_value = {"drivers": [], "devices": []}
            scanner.scan()
            collect.return_value = {"drivers": collector._drivers([{**row, "DriverVersion": "2"}]), "devices": collector._devices([device])}
            self.assertEqual(scanner.scan().state_events, 2)
            events = list(db.connection.execute("select action,severity,details_json from events where source='drivers'"))
            self.assertEqual(len(events), 1)
            self.assertEqual(events[0]["action"], "updated")
            self.assertEqual(events[0]["severity"], "high")
            self.assertEqual(json.loads(events[0]["details_json"])["before"]["version"], "1")

    def test_new_association_is_context_and_failed_write_does_not_lose_update(self):
        collector = WindowsCollector()
        now = datetime.now(timezone.utc)
        row = {"DeviceID": "USB\\FIXTURE", "DeviceName": "Fixture device", "DriverVersion": "1"}
        with Database(":memory:") as db:
            db.apply_snapshot("drivers", [], occurred_at=now)
            events = db.apply_snapshot("drivers", collector._drivers([row]), occurred_at=now)
            self.assertEqual([(e.action, e.severity) for e in events], [("observed", "info")])
            process_scan_events(db, SimpleNamespace(errors=(), scan_id="fixture"), events)
            self.assertEqual(db.connection.execute("select count(*) from automation_notifications").fetchone()[0], 0)
            request = IncidentRequest("Fixture device failed", now, now, subsystem="driver")
            symptoms = [Event(now, "symptom", "driver", "driver_reset", "Fixture reset", source="eventlog")]
            ranked = rank_candidates([*events, *symptoms], request)
            self.assertEqual(ranked[0].confidence, "Low")
            self.assertTrue(any(item.signal == "first observed association" for item in ranked[0].counter_evidence))
            changed = collector._drivers([{**row, "DriverVersion": "2"}])
            with patch.object(db, "_insert_event_rows", side_effect=RuntimeError("fixture write failure")):
                with self.assertRaises(RuntimeError):
                    db.apply_snapshot("drivers", changed, occurred_at=now + timedelta(seconds=1))
            self.assertEqual(db.apply_snapshot("drivers", changed, occurred_at=now + timedelta(seconds=2))[0].details["before"]["version"], "1")


class RuntimeHealthTests(unittest.TestCase):
    def test_legacy_logs_count_prejournal_failures_without_private_text(self):
        now = datetime.now(timezone.utc).replace(microsecond=0)
        local = now.astimezone().strftime("%Y-%m-%d %H:%M:%S")
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "journal.db"
            (path.parent / "watcher.log").write_text(
                f"{local},001 ERROR Background scan failed\nTraceback C:\\Users\\Synthetic\\private\nRuntimeError: The Difftrail journal schema version 99 is not supported\n"
                f"{local},002 INFO Background scan completed: status=ok changes=0 symptoms=0 sources=8\n", encoding="utf-8")
            (path.parent / "startup-errors.log").write_text(f"[{int(now.timestamp())}] Difftrail backend startup failed:\nschema_incompatible\n", encoding="utf-8")
            with Database(path) as db:
                report = build_host_validation_report(db, days=1, as_of=now)
            self.assertEqual(report["scans"]["total"], 0)
            runtime = report["runtime"]
            self.assertEqual(runtime["watcher_failures"], 1)
            self.assertEqual(runtime["watcher_completions"], 1)
            self.assertEqual(runtime["desktop_failures"], 1)
            self.assertEqual(runtime["failure_categories"], {"schema_incompatible": 2})
            self.assertNotIn("Synthetic", json.dumps(report))
            self.assertNotIn("Traceback", json.dumps(report))

    def test_missing_and_truncated_logs_are_not_clean_uptime(self):
        now = datetime.now(timezone.utc)
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "journal.db"
            self.assertEqual(runtime_health(path, start=now-timedelta(days=1), end=now)["status"], "unavailable")
            (path.parent / "watcher.log").write_text("x" * 500)
            with patch("difftrail.runtime_health.MAX_LOG_BYTES", 100):
                report = runtime_health(path, start=now-timedelta(days=1), end=now)
            self.assertEqual(report["status"], "partial")

    def test_worker_failure_is_logged_even_if_database_cannot_open(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "journal.db"
            try:
                with patch("difftrail.watcher.Database", side_effect=RuntimeError("The Difftrail journal schema version 99 is not supported C:\\Users\\Synthetic")):
                    self.assertEqual(run_once(path), 1)
                text = (path.parent / "watcher.log").read_text()
                self.assertIn("schema_incompatible", text)
                self.assertNotIn("Synthetic", text)
                self.assertFalse(path.exists())
                self.assertFalse(path.with_name("watcher.active").exists())
            finally:
                for handler in list(LOGGER.handlers):
                    LOGGER.removeHandler(handler)
                    handler.close()

    def test_incompatible_backend_fails_before_binding_or_announcing_ready(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "journal.db"
            with Database(path) as db:
                db.set_meta("schema_version", "999")
            output = io.StringIO()
            with patch("difftrail.ui_api.UiServer") as server, contextlib.redirect_stdout(output):
                with self.assertRaisesRegex(ValueError, "Update the desktop and bundled watcher together"):
                    serve(path, port=0)
                server.assert_not_called()
            self.assertNotIn("ready", output.getvalue())


if __name__ == "__main__":
    unittest.main()
