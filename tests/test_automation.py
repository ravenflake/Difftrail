from __future__ import annotations

import unittest
from pathlib import Path
from subprocess import CompletedProcess
from types import SimpleNamespace
from unittest.mock import patch

from difftrail.automation import (
    automation_snapshot,
    load_automation_config,
    mark_notifications_read,
    process_scan_events,
    run_automated_scan,
    TASK_RESULT_HAS_NOT_RUN,
    _normalize_task_time,
    _run_task_script,
    _watcher_status_message,
    update_automation_config,
)
from difftrail.db import Database
from difftrail.models import Event, utc_now


class AutomationTests(unittest.TestCase):
    def test_config_is_validated_and_persisted(self) -> None:
        with Database(":memory:") as database:
            config = update_automation_config(
                database,
                {"interval_seconds": 900, "notify_on_changes": False},
            )
            self.assertEqual(config["interval_seconds"], 900)
            self.assertFalse(config["notify_on_changes"])
            self.assertEqual(load_automation_config(database), config)
            with self.assertRaises(ValueError):
                update_automation_config(database, {"interval_seconds": 10})
            with self.assertRaises(ValueError):
                update_automation_config(database, {"notify_on_crashes": "yes"})

    def test_high_severity_signal_creates_one_draft_and_notification(self) -> None:
        with Database(":memory:") as database:
            now = utc_now()
            event = Event(
                now,
                "symptom",
                "application",
                "crash",
                "Application crash detected",
                entity="Example.exe",
                severity="high",
                source="eventlog",
            )
            database.save_events([event])
            stored = database.list_events(limit=1)[0]
            result = SimpleNamespace(scan_id="scan-1", errors=())

            first = process_scan_events(database, result, [stored])
            second = process_scan_events(database, result, [stored])

            self.assertEqual(first, {"notifications": 1, "drafts": 1})
            self.assertEqual(second, {"notifications": 0, "drafts": 0})
            self.assertEqual(database.automation_draft_count(), 1)
            self.assertEqual(database.unread_automation_notification_count(), 1)
            snapshot = automation_snapshot(database)
            self.assertEqual(snapshot["notifications"]["recent"][0]["incident_id"], database.recent_incidents()[0]["id"])

            marked = mark_notifications_read(database)
            self.assertEqual(marked["notifications"]["unread"], 0)

    def test_automated_scan_processes_new_events_and_warnings(self) -> None:
        with Database(":memory:") as database:
            now = utc_now()

            class FakeScanner:
                def scan(self):
                    database.save_events(
                        [
                            Event(
                                now,
                                "change",
                                "drivers",
                                "updated",
                                "Display driver updated",
                                entity="Display driver",
                                severity="high",
                                source="drivers",
                            )
                        ]
                    )
                    return SimpleNamespace(scan_id="scan-2", errors=("provider unavailable",))

            result = run_automated_scan(database, FakeScanner())

            self.assertEqual(result.scan_id, "scan-2")
            self.assertEqual(database.unread_automation_notification_count(), 2)
            self.assertEqual(database.automation_draft_count(), 0)
            self.assertEqual({item["kind"] for item in database.list_automation_notifications()}, {"change", "warning"})

    def test_snapshot_keeps_task_status_separate_from_preferences(self) -> None:
        task_status = {
            "task_name": "Difftrail Watcher",
            "supported": True,
            "installed": True,
            "running": False,
            "state": "Ready",
            "last_run_at": None,
            "next_run_at": None,
            "last_task_result": 0,
            "message": None,
        }
        with Database(":memory:") as database, patch("difftrail.automation._task_status", return_value=task_status):
            snapshot = automation_snapshot(database)
            self.assertEqual(snapshot["config"]["interval_seconds"], 300)
            self.assertTrue(snapshot["watcher"]["installed"])
            self.assertEqual(snapshot["drafts"], 0)

    def test_access_denied_retries_task_installation_with_uac(self) -> None:
        denied = CompletedProcess(["powershell.exe"], 1, "", "Access is denied.")
        elevated = CompletedProcess(["powershell.exe"], 0, "", "")
        with patch("difftrail.automation._powershell_executable", return_value="powershell.exe"), patch(
            "difftrail.automation.subprocess.run", return_value=denied
        ), patch("difftrail.automation._run_elevated", return_value=elevated) as retry:
            _run_task_script(Path("install-watcher.ps1"), [])
            retry.assert_called_once()

    def test_task_scheduler_never_run_sentinel_is_hidden(self) -> None:
        self.assertIsNone(_normalize_task_time("1999-11-30T00:00:00"))
        self.assertEqual(_normalize_task_time("2026-08-02T10:15:00Z"), "2026-08-02T10:15:00Z")

    def test_task_that_has_never_run_is_reported_as_not_started(self) -> None:
        self.assertEqual(
            _watcher_status_message("Ready", TASK_RESULT_HAS_NOT_RUN),
            "The watcher is installed but has not started yet.",
        )
        self.assertIsNone(_watcher_status_message("Running", 0))

    def test_source_installer_starts_task_in_current_session(self) -> None:
        script = Path(__file__).parents[1] / "scripts" / "install-watcher.ps1"
        self.assertIn("Start-ScheduledTask", script.read_text(encoding="utf-8"))
