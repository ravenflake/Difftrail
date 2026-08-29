import json
import unittest
from unittest.mock import patch

from difftrail.db import Database
from difftrail.models import Event, utc_now
from difftrail.simulation import simulate_nvidia_driver_switch
from difftrail.ui_api import build_bootstrap, create_investigation, record_overhead


class UiApiTests(unittest.TestCase):
    def test_bootstrap_exposes_privacy_safe_host_health(self) -> None:
        host = {
            "captured_at_epoch": 1,
            "uptime_seconds": 3600,
            "memory_total_bytes": 16_000,
            "memory_available_bytes": 8_000,
            "memory_used_percent": 50.0,
            "system_disk_total_bytes": 100_000,
            "system_disk_free_bytes": 40_000,
            "system_disk_used_percent": 60.0,
        }
        with (
            Database(":memory:") as database,
            patch("difftrail.ui_api.system_health_snapshot", return_value=host),
        ):
            payload = build_bootstrap(database)

        self.assertEqual(payload["status"]["host"], host)
        self.assertNotIn("path", json.dumps(payload["status"]["host"]).casefold())

    def test_bootstrap_exposes_real_journal_without_raw_event_details(self) -> None:
        with Database(":memory:") as database:
            simulate_nvidia_driver_switch(database)
            payload = build_bootstrap(database)

        self.assertEqual(payload["status"]["changes"], 2)
        self.assertEqual(len(payload["events"]), 3)
        self.assertTrue(all("details" not in event for event in payload["events"]))
        self.assertNotIn('"details":', json.dumps(payload))

    def test_bootstrap_status_hides_provider_error_text(self) -> None:
        with Database(":memory:") as database:
            now = utc_now()
            scan_id = database.start_scan(now)
            database.finish_scan(
                scan_id,
                now,
                "partial",
                {"errors": [r"drivers: C:\Users\Raven\private-provider.log"], "sources": 1},
            )
            payload = build_bootstrap(database)

        summary = payload["status"]["last_scan"]["summary"]
        self.assertEqual(summary["errors"], [])
        self.assertEqual(summary["error_count"], 1)
        self.assertNotIn("Raven", json.dumps(payload))

    def test_bootstrap_buckets_colonless_provider_errors(self) -> None:
        with Database(":memory:") as database:
            now = utc_now()
            scan_id = database.start_scan(now)
            database.finish_scan(scan_id, now, "partial", {"errors": ["private provider secret"]})
            payload = build_bootstrap(database)

        summary = payload["status"]["last_scan"]["summary"]
        self.assertEqual(summary["error_buckets"], ["other"])
        self.assertNotIn("private provider secret", json.dumps(payload))

    def test_investigation_response_is_ui_safe_and_persists_incident(self) -> None:
        with Database(":memory:") as database:
            simulate_nvidia_driver_switch(database)
            result = create_investigation(
                database,
                {
                    "description": "graphics started failing",
                    "subsystem": "graphics",
                    "lookback_days": 7,
                    "affected_entity": "ExampleGame.exe",
                    "suspected_change": "display driver update",
                },
            )

            self.assertTrue(result["incident"]["id"])
            self.assertEqual(result["summary"]["incident_id"], result["incident"]["id"])
            self.assertTrue(result["summary"]["hypotheses"])
            self.assertTrue(all("details" not in hypothesis["event"] for hypothesis in result["summary"]["hypotheses"]))
            lead_event = result["summary"]["hypotheses"][0]["event"]
            self.assertIn("version", lead_event["detail_summary"]["changed_fields"])
            self.assertNotIn("path", json.dumps(lead_event))
            self.assertEqual(result["incident"]["affected_entity"], "ExampleGame.exe")
            self.assertEqual(result["incident"]["suspected_change"], "display driver update")
            self.assertEqual(result["summary"]["affected_entity"], "ExampleGame.exe")
            stored = database.get_incident(result["incident"]["id"])
            self.assertEqual(stored["affected_entity"], "ExampleGame.exe")
            self.assertEqual(stored["suspected_change"], "display driver update")

    def test_bootstrap_exposes_safe_event_detail_summary_without_raw_message(self) -> None:
        with Database(":memory:") as database:
            database.save_events(
                [
                    Event(
                        utc_now(),
                        "symptom",
                        "application",
                        "crash",
                        "Application crash detected",
                        entity="Application Error",
                        source="eventlog",
                        details={
                            "event_id": 1000,
                            "log_name": "Application",
                            "provider": "Application Error",
                            "record_id": "42",
                            "message": r"Faulting application name: C:\Games\Example.exe, version 1.0",
                        },
                    )
                ]
            )
            event = build_bootstrap(database)["events"][0]

        self.assertEqual(event["entity"], "Application Error")
        self.assertEqual(event["detail_summary"]["application_name"], "Example.exe")
        self.assertEqual(event["detail_summary"]["event_id"], 1000)
        self.assertNotIn('"message":', json.dumps(event))
        self.assertNotIn("C:\\Games", json.dumps(event))

    def test_record_overhead_persists_numeric_report_without_process_id(self) -> None:
        report = {
            "status": "ok",
            "interval_seconds": 15,
            "warmup_seconds": 2,
            "sample_seconds": 5,
            "startup_process_tree_cpu_percent": 1.0,
            "process_tree_cpu_percent": 0.2,
            "startup_rss_mb_peak": 100.0,
            "rss_mb_mean": 30.0,
            "rss_mb_peak": 32.0,
            "startup_disk_read_mb": 1.0,
            "startup_disk_write_mb": 0.0,
            "disk_read_mb": 0.1,
            "disk_write_mb": 0.0,
            "sample_count": 3,
            "process_id": 1234,
            "scope": "watcher",
        }
        with Database(":memory:") as database, patch("difftrail.ui_api.measure_watcher_overhead", return_value=report):
            result = record_overhead(database)
            self.assertEqual(len(database.list_overhead_measurements()), 1)

        self.assertNotIn("process_id", result["report"])
        self.assertEqual(result["report"]["sample_seconds"], 5)
