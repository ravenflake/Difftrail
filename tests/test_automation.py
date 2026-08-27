from __future__ import annotations

import json
import unittest
from datetime import timedelta
from pathlib import Path
from subprocess import CompletedProcess
from tempfile import TemporaryDirectory
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
    _fallback_task_action,
    _run_task_script,
    _watcher_task_needs_repair,
    _watcher_status_message,
    update_automation_config,
)
from difftrail.db import Database, _AUTOMATION_LINK_REPAIR_BATCH
from difftrail.models import Event, IncidentRequest, iso_datetime, utc_now


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
            draft = database.recent_incidents()[0]
            incident_id = draft["id"]
            self.assertEqual(snapshot["notifications"]["recent"][0]["incident_id"], incident_id)
            self.assertEqual(
                database.connection.execute(
                    "SELECT incident_id FROM automation_actions WHERE event_id = ? AND action = 'draft_investigation'",
                    (stored.event_id,),
                ).fetchone()[0],
                incident_id,
            )
            self.assertEqual(draft["description"], "Example.exe crashed")
            self.assertEqual(draft["affected_entity"], "Example.exe")

            marked = mark_notifications_read(database)
            self.assertEqual(marked["notifications"]["unread"], 0)

    def test_crash_drafts_are_distinguishable_by_application(self) -> None:
        with Database(":memory:") as database:
            now = utc_now()
            events = [
                Event(now, "symptom", "application", "crash", "Application crash detected", entity="First.exe", severity="high", source="eventlog", event_id="first-crash"),
                Event(now + timedelta(seconds=1), "symptom", "application", "crash", "Application crash detected", entity="Second.exe", severity="high", source="eventlog", event_id="second-crash"),
            ]

            process_scan_events(database, SimpleNamespace(scan_id="scan-crashes", errors=()), events)

            self.assertEqual(
                {incident["description"] for incident in database.recent_incidents()},
                {"First.exe crashed", "Second.exe crashed"},
            )

    def test_crash_draft_uses_safe_fallback_when_identity_is_missing(self) -> None:
        with Database(":memory:") as database:
            event = Event(
                utc_now(),
                "symptom",
                "application",
                "crash",
                "Application crash detected",
                entity="Application Error",
                severity="high",
                source="eventlog",
                event_id="missing-identity",
            )

            process_scan_events(database, SimpleNamespace(scan_id="scan-missing", errors=()), [event])

            draft = database.recent_incidents()[0]
            self.assertEqual(draft["description"], "Application crashed")
            self.assertIsNone(draft["affected_entity"])

    def test_crash_draft_title_drops_sensitive_path_and_command_line(self) -> None:
        with Database(":memory:") as database:
            event = Event(
                utc_now(),
                "symptom",
                "application",
                "crash",
                "Application crash detected",
                entity=r'"C:\Users\Alice\Private\Secret.exe" --token hunter2',
                severity="high",
                source="eventlog",
                event_id="sensitive-identity",
            )

            process_scan_events(database, SimpleNamespace(scan_id="scan-sensitive", errors=()), [event])

            draft = database.recent_incidents()[0]
            encoded = json.dumps(draft)
            self.assertEqual(draft["description"], "Secret.exe crashed")
            self.assertEqual(draft["affected_entity"], "Secret.exe")
            self.assertIn("Secret.exe crashed", encoded)
            self.assertNotIn("Alice", encoded)
            self.assertNotIn("hunter2", encoded)
            self.assertNotIn(r"C:\Users", encoded)

    def test_hang_draft_names_the_application_and_symptom(self) -> None:
        with Database(":memory:") as database:
            event = Event(
                utc_now(),
                "symptom",
                "application",
                "hang",
                "Application hang detected",
                entity="Editor.exe",
                severity="high",
                source="eventlog",
                event_id="app-hang",
            )

            process_scan_events(database, SimpleNamespace(scan_id="scan-hang", errors=()), [event])

            self.assertEqual(database.recent_incidents()[0]["description"], "Editor.exe stopped responding")

    def test_automation_snapshot_redacts_notification_paths(self) -> None:
        with Database(":memory:") as database:
            database.create_automation_notification(
                kind="change",
                title=r"Changed C:\Program Files\Secret\tool.exe",
                body=r"Observed at C:\Users\Alice\private\tool.exe",
                event_id=r"C:\Users\Alice\event",
            )

            encoded = json.dumps(automation_snapshot(database))
            self.assertNotIn("Alice", encoded)
            self.assertNotIn(r"C:\Users", encoded)
            self.assertNotIn(r"C:\Program Files", encoded)

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

    def test_automated_scan_finds_new_events_after_large_history(self) -> None:
        with Database(":memory:") as database:
            now = utc_now()
            old = now - timedelta(days=1)
            database.save_events(
                [
                    Event(old, "change", "graphics", "updated", f"old event {index}", severity="low", source="test")
                    for index in range(10_001)
                ]
            )

            class FakeScanner:
                def scan(self):
                    database.save_events(
                        [
                            Event(
                                now,
                                "change",
                                "graphics",
                                "updated",
                                "new high-severity change",
                                severity="high",
                                source="test",
                            )
                        ]
                    )
                    return SimpleNamespace(scan_id="scan-after-history", errors=())

            run_automated_scan(database, FakeScanner())

            self.assertEqual(database.unread_automation_notification_count(), 1)
            self.assertEqual(database.list_automation_notifications()[0]["kind"], "change")

    def test_hardware_refresh_burst_retains_events_without_notification_storm(self) -> None:
        with Database(":memory:") as database:
            events = [
                Event(utc_now(), "change", "driver", "updated", f"Driver {index} updated", severity="high", source="drivers", event_id=f"driver-{index}")
                for index in range(12)
            ]
            database.save_events(events)
            stored = database.list_events(limit=20)

            result = process_scan_events(database, SimpleNamespace(scan_id="hardware-wave", errors=()), stored)

            self.assertEqual(result, {"notifications": 0, "drafts": 0})
            self.assertEqual(database.count_events("change"), 12)
            self.assertEqual(database.unread_automation_notification_count(), 0)

    def test_automatic_crash_draft_includes_safe_entity_identity(self) -> None:
        with Database(":memory:") as database:
            event = Event(utc_now(), "symptom", "application", "crash", "Application crash detected", entity="Example.exe", severity="high", source="eventlog", event_id="named-crash")
            process_scan_events(database, SimpleNamespace(scan_id="named", errors=()), [event])
            self.assertIn("Example.exe", database.recent_incidents()[0]["description"])

    def test_automatic_crash_draft_redacts_title_paths(self) -> None:
        with Database(":memory:") as database:
            event = Event(
                utc_now(),
                "symptom",
                "application",
                "crash",
                r"Crash in C:\Program Files\Secret\tool.exe",
                severity="high",
                source="eventlog",
                event_id="path-title-crash",
            )
            process_scan_events(database, SimpleNamespace(scan_id="path-title", errors=()), [event])
            description = database.recent_incidents()[0]["description"]
            self.assertEqual(description, "Application crashed")
            self.assertNotIn(r"C:\Program Files\Secret\tool.exe", description)

    def test_legacy_null_draft_link_is_repaired_atomically(self) -> None:
        with Database(":memory:") as database:
            event = Event(utc_now(), "symptom", "application", "crash", "Application crash", entity="Example.exe", severity="high", source="eventlog", event_id="legacy-null-link")
            database.record_automation_action(event.event_id, "draft_investigation")

            result = process_scan_events(database, SimpleNamespace(scan_id="repair", errors=()), [event])

            self.assertEqual(result["drafts"], 1)
            incident_id = database.automation_action_incident_id(event.event_id, "draft_investigation")
            self.assertIsNotNone(incident_id)
            self.assertIsNotNone(database.get_incident(incident_id))

    def test_failed_notification_does_not_commit_its_idempotency_marker(self) -> None:
        with Database(":memory:") as database:
            event = Event(
                utc_now(),
                "change",
                "graphics",
                "updated",
                "Important driver change",
                severity="high",
                source="test",
                event_id="notification-retry",
            )
            result = SimpleNamespace(scan_id="scan-notification-retry", errors=())
            with patch.object(database, "create_automation_notification", side_effect=RuntimeError("disk full")):
                with self.assertRaisesRegex(RuntimeError, "disk full"):
                    process_scan_events(database, result, [event])

            actions = database.connection.execute("SELECT COUNT(*) FROM automation_actions").fetchone()[0]
            self.assertEqual(actions, 0)
            self.assertEqual(process_scan_events(database, result, [event]), {"notifications": 1, "drafts": 0})
            self.assertEqual(database.unread_automation_notification_count(), 1)

    def test_failed_draft_does_not_commit_its_idempotency_marker(self) -> None:
        with Database(":memory:") as database:
            event = Event(
                utc_now(),
                "symptom",
                "application",
                "crash",
                "Application crash",
                severity="high",
                source="eventlog",
                event_id="draft-retry",
            )
            result = SimpleNamespace(scan_id="scan-draft-retry", errors=())
            with patch("difftrail.automation.run_investigation", side_effect=RuntimeError("write failed")):
                with self.assertRaisesRegex(RuntimeError, "draft could not be persisted"):
                    process_scan_events(database, result, [event])

            actions = database.connection.execute(
                "SELECT COUNT(*) FROM automation_actions WHERE action = 'draft_investigation'"
            ).fetchone()[0]
            self.assertEqual(actions, 0)
            self.assertEqual(process_scan_events(database, result, [event])["drafts"], 1)
            notification = database.list_automation_notifications()[0]
            self.assertEqual(notification["incident_id"], database.recent_incidents()[0]["id"])

    def test_unlinked_automatic_draft_is_repaired_when_journal_reopens(self) -> None:
        with TemporaryDirectory() as folder:
            path = Path(folder) / "journal.db"
            now = utc_now()
            with Database(path) as database:
                event = Event(
                    now,
                    "symptom",
                    "application",
                    "crash",
                    "Application crash detected",
                    severity="high",
                    source="eventlog",
                    event_id="legacy-unlinked-draft",
                )
                database.save_events([event])
                incident = database.create_incident(
                    IncidentRequest("Automatic draft: Application crash detected", now, now, "application", 7),
                    status="draft",
                )
                database.record_automation_action(event.event_id, "draft_investigation")
                database.create_automation_notification(
                    kind="crash",
                    title="High-severity signal detected",
                    body="Review the evidence.",
                    event_id=event.event_id,
                )

            with Database(path) as reopened:
                action = reopened.connection.execute(
                    "SELECT incident_id FROM automation_actions WHERE event_id = ? AND action = 'draft_investigation'",
                    ("legacy-unlinked-draft",),
                ).fetchone()
                notification = reopened.list_automation_notifications()[0]
                self.assertEqual(action[0], incident.id)
                self.assertEqual(notification["incident_id"], incident.id)

    def test_unlinked_draft_repair_uses_complete_automatic_request(self) -> None:
        with TemporaryDirectory() as folder:
            path = Path(folder) / "journal.db"
            now = utc_now()
            with Database(path) as database:
                event = Event(
                    now,
                    "symptom",
                    "legacy-area",
                    "crash",
                    "Application crash detected",
                    entity="Example.exe",
                    severity="high",
                    source="eventlog",
                    event_id="complete-automatic-draft",
                )
                database.save_events([event])
                incident = database.create_incident(
                    IncidentRequest(
                        "Automatic draft: Application crash detected · Example.exe",
                        now,
                        now,
                        "general",
                        7,
                    ),
                    status="draft",
                )
                database.record_automation_action(event.event_id, "draft_investigation")

            with Database(path) as reopened:
                action = reopened.connection.execute(
                    "SELECT incident_id FROM automation_actions WHERE event_id = ?",
                    ("complete-automatic-draft",),
                ).fetchone()
                self.assertEqual(action[0], incident.id)

    def test_automation_link_repair_processes_bounded_batches(self) -> None:
        with TemporaryDirectory() as folder:
            path = Path(folder) / "journal.db"
            start = utc_now()
            with Database(path) as database:
                for index in range(_AUTOMATION_LINK_REPAIR_BATCH + 1):
                    database.record_automation_action(
                        f"batch-marker-{index}",
                        "draft_investigation",
                        created_at=start + timedelta(seconds=index),
                    )

                database._repair_automation_links()
                first_cursor = json.loads(database.get_meta("automation:link-repair-cursor") or "{}")
                self.assertEqual(
                    first_cursor["created_at"],
                    iso_datetime(start + timedelta(seconds=_AUTOMATION_LINK_REPAIR_BATCH - 1)),
                )

                database._repair_automation_links()
                second_cursor = json.loads(database.get_meta("automation:link-repair-cursor") or "{}")
                self.assertEqual(
                    second_cursor["created_at"],
                    iso_datetime(start + timedelta(seconds=_AUTOMATION_LINK_REPAIR_BATCH)),
                )

    def test_automation_link_repair_advances_past_unmatched_markers(self) -> None:
        with TemporaryDirectory() as folder:
            path = Path(folder) / "journal.db"
            with Database(path) as database:
                event = Event(
                    utc_now(),
                    "symptom",
                    "application",
                    "crash",
                    "Unmatched application crash",
                    severity="high",
                    source="eventlog",
                    event_id="unmatched-repair-marker",
                )
                database.save_events([event])
                database.record_automation_action(event.event_id, "draft_investigation")

                trace: list[str] = []
                database._repair_automation_links()
                cursor = json.loads(database.get_meta("automation:link-repair-cursor") or "{}")
                database.connection.set_trace_callback(trace.append)
                database._repair_automation_links()
                database.connection.set_trace_callback(None)

                self.assertEqual(cursor["id"], database.connection.execute(
                    "SELECT id FROM automation_actions WHERE event_id = ?",
                    (event.event_id,),
                ).fetchone()[0])
                self.assertFalse(any("SELECT title, subsystem, occurred_at" in statement for statement in trace))

    def test_failed_notification_retry_links_existing_draft(self) -> None:
        with Database(":memory:") as database:
            event = Event(
                utc_now(),
                "symptom",
                "application",
                "crash",
                "Application crash",
                severity="high",
                source="eventlog",
                event_id="notification-draft-link",
            )
            result = SimpleNamespace(scan_id="scan-notification-draft-link", errors=())
            with patch.object(database, "create_automation_notification", side_effect=RuntimeError("disk full")):
                with self.assertRaisesRegex(RuntimeError, "disk full"):
                    process_scan_events(database, result, [event])

            self.assertEqual(database.automation_draft_count(), 1)
            self.assertEqual(process_scan_events(database, result, [event]), {"notifications": 1, "drafts": 0})
            notification = database.list_automation_notifications()[0]
            self.assertEqual(notification["incident_id"], database.recent_incidents()[0]["id"])

    def test_automation_cursor_retries_events_after_a_post_scan_failure(self) -> None:
        with Database(":memory:") as database:
            now = utc_now()

            class FakeScanner:
                calls = 0

                def scan(self):
                    self.calls += 1
                    if self.calls == 1:
                        database.save_events(
                            [
                                Event(
                                    now,
                                    "change",
                                    "graphics",
                                    "updated",
                                    "New high-severity change",
                                    severity="high",
                                    source="test",
                                    event_id="cursor-retry",
                                )
                            ]
                        )
                    return SimpleNamespace(scan_id=f"scan-cursor-{self.calls}", errors=())

            scanner = FakeScanner()
            with patch.object(database, "create_automation_notification", side_effect=RuntimeError("disk full")):
                with self.assertRaisesRegex(RuntimeError, "disk full"):
                    run_automated_scan(database, scanner)

            self.assertEqual(database.get_meta("automation:event_rowid"), "0")
            run_automated_scan(database, scanner)
            self.assertEqual(database.unread_automation_notification_count(), 1)
            self.assertEqual(database.get_meta("automation:event_rowid"), "1")

    def test_invalid_automation_cursor_is_repaired_before_a_retryable_scan(self) -> None:
        with Database(":memory:") as database:
            now = utc_now()
            database.set_meta("automation:event_rowid", "not-a-number")

            class FakeScanner:
                calls = 0

                def scan(self):
                    self.calls += 1
                    if self.calls == 1:
                        database.save_events(
                            [
                                Event(
                                    now,
                                    "change",
                                    "graphics",
                                    "updated",
                                    "Retryable high-severity change",
                                    severity="high",
                                    source="test",
                                    event_id="invalid-cursor-retry",
                                )
                            ]
                        )
                    return SimpleNamespace(scan_id=f"scan-invalid-cursor-{self.calls}", errors=())

            scanner = FakeScanner()
            with patch.object(database, "create_automation_notification", side_effect=RuntimeError("disk full")):
                with self.assertRaisesRegex(RuntimeError, "disk full"):
                    run_automated_scan(database, scanner)

            self.assertEqual(database.get_meta("automation:event_rowid"), "0")
            run_automated_scan(database, scanner)
            self.assertEqual(database.unread_automation_notification_count(), 1)

    def test_automation_cursor_does_not_skip_events_added_during_processing(self) -> None:
        with TemporaryDirectory() as folder:
            path = Path(folder) / "journal.db"
            now = utc_now()
            with Database(path) as database:
                class FakeScanner:
                    calls = 0

                    def scan(self):
                        self.calls += 1
                        if self.calls == 1:
                            database.save_events(
                                [
                                    Event(
                                        now,
                                        "change",
                                        "graphics",
                                        "updated",
                                        "First high-severity change",
                                        severity="high",
                                        source="test",
                                        event_id="cursor-first",
                                    )
                                ]
                            )
                        return SimpleNamespace(scan_id=f"scan-cursor-race-{self.calls}", errors=())

                def insert_concurrent_event(current: Database, result, events):
                    with Database(path) as concurrent:
                        concurrent.save_events(
                            [
                                Event(
                                    now,
                                    "change",
                                    "graphics",
                                    "updated",
                                    "Second high-severity change",
                                    severity="high",
                                    source="test",
                                    event_id="cursor-second",
                                )
                            ]
                        )
                    return process_scan_events(current, result, events)

                scanner = FakeScanner()
                with patch("difftrail.automation.process_scan_events", side_effect=insert_concurrent_event):
                    run_automated_scan(database, scanner)

                self.assertEqual(database.get_meta("automation:event_rowid"), "1")
                run_automated_scan(database, scanner)
                event_ids = {item["event_id"] for item in database.list_automation_notifications()}
                self.assertEqual(event_ids, {"cursor-first", "cursor-second"})

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
            "Background scans are scheduled but have not run yet.",
        )
        self.assertIsNone(_watcher_status_message("Running", 0))

    def test_ready_task_with_successful_run_is_reported_as_scheduled(self) -> None:
        self.assertEqual(_watcher_status_message("Ready", 0), "Background scans are scheduled.")

    def test_legacy_task_is_reported_as_needing_repair(self) -> None:
        self.assertEqual(
            _watcher_status_message("Ready", 0, needs_repair=True),
            "The background watcher needs to be updated.",
        )

    def test_task_status_requires_exact_watcher_arguments(self) -> None:
        database = Path(r"C:\Data\journal.db")
        frozen_executable = Path(r"C:\Difftrail\difftrail-watcher.exe")

        self.assertFalse(
            _watcher_task_needs_repair(
                r"C:\Python\pythonw.exe",
                r'-m difftrail.watcher --db "C:\Data\journal.db"',
                has_repetition=True,
                expected_database=database,
            )
        )
        for arguments in (
            r'-m other_module --db "C:\Data\journal.db" difftrail.watcher.backup',
            r'-m difftrail.watcher --db "C:\Data\journal.db.bak"',
            r'-m difftrail.watcher --db "C:\Data\prefix-journal.db"',
            r'-m difftrail.watcher --db "C:\Data\journal.db" --db "C:\Other\journal.db"',
            r'--db "C:\Data\journal.db" -m other_module',
        ):
            with self.subTest(arguments=arguments):
                self.assertTrue(
                    _watcher_task_needs_repair(
                        r"C:\Python\pythonw.exe",
                        arguments,
                        has_repetition=True,
                        expected_database=database,
                    )
                )

        self.assertFalse(
            _watcher_task_needs_repair(
                str(frozen_executable),
                r'--db "C:\Data\journal.db"',
                has_repetition=True,
                expected_database=database,
                expected_executable=frozen_executable,
            )
        )
        self.assertTrue(
            _watcher_task_needs_repair(
                r"C:\Other\difftrail-watcher.exe",
                r'--db "C:\Data\journal.db"',
                has_repetition=True,
                expected_database=database,
                expected_executable=frozen_executable,
            )
        )

    def test_fallback_task_uses_the_headless_one_shot_worker(self) -> None:
        with TemporaryDirectory() as directory:
            with Database(Path(directory) / "journal.db") as database, patch(
                "difftrail.automation._watcher_executable", return_value=Path("pythonw.exe")
            ):
                action = _fallback_task_action(database)
        self.assertIn("difftrail.watcher", action)
        self.assertNotIn(" watch ", action)

    def test_source_installer_starts_task_in_current_session(self) -> None:
        script = Path(__file__).parents[1] / "scripts" / "install-watcher.ps1"
        self.assertIn("Start-ScheduledTask", script.read_text(encoding="utf-8"))
        contents = script.read_text(encoding="utf-8")
        self.assertIn("pythonw.exe", contents)
        automation_source = Path(__file__).parents[1].joinpath("difftrail", "automation.py").read_text(encoding="utf-8")
        self.assertIn("windowless Python interpreter", automation_source)
        self.assertIn("_watcher_task_needs_repair", automation_source)
        self.assertIn("New-ScheduledTaskTrigger", contents)
        self.assertIn("-RepetitionInterval", contents)
        self.assertIn("[Math]::Max(60, $IntervalSeconds)", contents)
        self.assertIn("AddSeconds($scheduledIntervalSeconds)", contents)
        self.assertIn("required to install the Difftrail watcher", contents)
        self.assertIn("-Hidden", contents)
        self.assertIn("-RestartCount", contents)
        self.assertIn("difftrail.watcher", contents)
