import json
import sqlite3
import tempfile
import threading
import unittest
from datetime import timedelta
from pathlib import Path

from difftrail.db import BASE_SCHEMA, Database, _hash
from difftrail.models import Event, IncidentRequest, SnapshotItem, utc_now


class DatabaseTests(unittest.TestCase):
    def test_fresh_journal_records_numbered_migrations(self) -> None:
        with Database(":memory:") as database:
            schema = database.schema_status()
            self.assertEqual(schema["current_version"], schema["supported_version"])
            self.assertEqual([item["version"] for item in schema["migrations"]], [1, 2, 3, 4, 5, 6])

    def test_stale_scan_is_detected_and_recovered_without_deleting_it(self) -> None:
        with Database(":memory:") as database:
            now = utc_now()
            scan_id = database.start_scan(now - timedelta(hours=1))
            diagnostics = database.journal_diagnostics(now=now)
            self.assertEqual(diagnostics["scans"]["stale_running"][0]["id"], scan_id)
            self.assertFalse(diagnostics["ok"])
            self.assertEqual(database.recover_stale_scans(now=now), 1)
            row = database.list_scans()[0]
            self.assertEqual(row["status"], "interrupted")
            self.assertEqual(row["summary"]["recovery"]["reason"], "stale_running_scan")

    def test_slow_scan_can_finish_after_provisional_stale_recovery(self) -> None:
        with Database(":memory:") as database:
            now = utc_now()
            slow_scan = database.start_scan(now - timedelta(hours=1))
            replacement_scan = database.start_scan(now)

            database.finish_scan(
                slow_scan,
                now + timedelta(minutes=1),
                "ok",
                {"sources": 7, "state_events": 2, "symptom_events": 0, "errors": []},
            )

            rows = {
                row["id"]: row
                for row in database.connection.execute("SELECT id, status FROM scans").fetchall()
            }
            self.assertEqual(rows[slow_scan]["status"], "ok")
            self.assertEqual(rows[replacement_scan]["status"], "running")

    def test_active_scan_blocks_a_second_scan(self) -> None:
        with Database(":memory:") as database:
            now = utc_now()
            database.start_scan(now)
            with self.assertRaisesRegex(RuntimeError, "already running"):
                database.start_scan(now + timedelta(seconds=1))
    def test_old_journal_gets_additive_feedback_columns(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "legacy.db"
            connection = sqlite3.connect(path)
            connection.execute(
                """
                CREATE TABLE incidents (
                    id TEXT PRIMARY KEY,
                    created_at TEXT NOT NULL,
                    description TEXT NOT NULL,
                    subsystem TEXT NOT NULL,
                    onset_start TEXT NOT NULL,
                    onset_end TEXT NOT NULL,
                    lookback_days INTEGER NOT NULL,
                    status TEXT NOT NULL,
                    result_json TEXT NOT NULL DEFAULT '[]'
                )
                """
            )
            connection.commit()
            connection.close()

            with Database(path) as database:
                columns = {
                    row[1]
                    for row in database.connection.execute("PRAGMA table_info(incidents)").fetchall()
                }
                self.assertTrue({"feedback_outcome", "feedback_event_id", "feedback_at"}.issubset(columns))

    def test_current_legacy_journal_gets_assessment_migration(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "legacy-current.db"
            connection = sqlite3.connect(path)
            connection.executescript(BASE_SCHEMA)
            connection.execute(
                "INSERT INTO meta(key, value) VALUES (?, ?)",
                ("migration:safe-application-entities", "1"),
            )
            connection.commit()
            connection.close()

            with Database(path) as database:
                schema = database.schema_status()
                self.assertEqual(schema["current_version"], 6)
                columns = {
                    row[1]
                    for row in database.connection.execute("PRAGMA table_info(incidents)").fetchall()
                }
                self.assertTrue({"assessment", "assessment_reasons_json", "coverage_json"}.issubset(columns))
                event_indexes = {
                    row[1]
                    for row in database.connection.execute("PRAGMA index_list(events)").fetchall()
                }
                scan_indexes = {
                    row[1]
                    for row in database.connection.execute("PRAGMA index_list(scans)").fetchall()
                }
                self.assertIn("idx_events_source_occurred_at", event_indexes)
                self.assertIn("idx_scans_status_started_at", scan_indexes)

    def test_v013_journal_is_re_sanitized_on_upgrade(self) -> None:
        legacy_path = r"C:\Users\<user> Doe\Games\Example Game.exe"
        safe_path = r"C:\Users\<user>"
        safe_message = r"The program C:\Users\<user> version 1.0 stopped interacting."
        timestamp = "2026-08-09T12:00:00Z"
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "v013-journal.db"
            connection = sqlite3.connect(path)
            connection.executescript(BASE_SCHEMA)
            connection.executescript(
                """
                ALTER TABLE incidents ADD COLUMN assessment TEXT NOT NULL DEFAULT 'insufficient_evidence';
                ALTER TABLE incidents ADD COLUMN assessment_reasons_json TEXT NOT NULL DEFAULT '[]';
                ALTER TABLE incidents ADD COLUMN coverage_json TEXT NOT NULL DEFAULT '{}';
                """
            )
            connection.executemany(
                "INSERT INTO meta(key, value) VALUES (?, ?)",
                [("schema_version", "5"), ("migration:safe-application-entities", "1")],
            )
            connection.execute(
                """
                INSERT INTO events
                (id, occurred_at, kind, subsystem, action, title, entity, severity, source,
                 details_json, fingerprint, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    "legacy-event",
                    timestamp,
                    "symptom",
                    "application",
                    "crash",
                    f"Crash in {legacy_path}",
                    f"Application Error at {legacy_path}",
                    "high",
                    "eventlog",
                    json.dumps({"message": f'Faulting application name: "{legacy_path}", version 1.0'}),
                    "legacy-fingerprint",
                    timestamp,
                ),
            )
            connection.execute(
                """
                INSERT INTO state_items(source, item_key, payload_json, payload_hash, last_seen_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                ("apps", "legacy-app", json.dumps({"install_location": legacy_path}), "legacy-hash", timestamp),
            )
            connection.execute(
                """
                INSERT INTO events
                (id, occurred_at, kind, subsystem, action, title, entity, severity, source,
                 details_json, fingerprint, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    "already-safe-event",
                    timestamp,
                    "symptom",
                    "application",
                    "hang",
                    safe_message,
                    "Application Hang",
                    "high",
                    "eventlog",
                    json.dumps({"message": safe_message}),
                    "already-safe-fingerprint",
                    timestamp,
                ),
            )
            connection.execute(
                "INSERT INTO scans(id, started_at, finished_at, status, summary_json) VALUES (?, ?, ?, ?, ?)",
                ("legacy-scan", timestamp, timestamp, "ok", json.dumps({"errors": [legacy_path]})),
            )
            connection.execute(
                """
                INSERT INTO incidents
                (id, created_at, description, subsystem, onset_start, onset_end, lookback_days, status,
                 result_json, feedback_outcome, feedback_event_id, feedback_at, assessment,
                 assessment_reasons_json, coverage_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    "legacy-incident",
                    timestamp,
                    f"Crash after opening {legacy_path}",
                    "application",
                    timestamp,
                    timestamp,
                    7,
                    "investigating",
                    json.dumps([{"evidence": legacy_path}]),
                    "correct",
                    "legacy-event",
                    timestamp,
                    "insufficient_evidence",
                    json.dumps([f"Review {legacy_path}"]),
                    json.dumps({"path": legacy_path}),
                ),
            )
            connection.execute(
                """
                INSERT INTO automation_notifications
                (id, created_at, kind, title, body, event_id, incident_id, read_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    "legacy-notification",
                    timestamp,
                    "warning",
                    f"Problem in {legacy_path}",
                    f"Review {legacy_path}",
                    "legacy-event",
                    "legacy-incident",
                    None,
                ),
            )
            connection.commit()
            connection.close()

            with Database(path) as database:
                self.assertEqual(database.schema_status()["current_version"], 6)
                events = {event.event_id: event for event in database.list_events(kind="symptom")}
                self.assertEqual(set(events), {"legacy-event", "already-safe-event"})
                event = events["legacy-event"]
                already_safe_event = events["already-safe-event"]
                state = database.connection.execute(
                    "SELECT payload_json, payload_hash FROM state_items WHERE source = ? AND item_key = ?",
                    ("apps", "legacy-app"),
                ).fetchone()
                scan = database.list_scans()[0]
                incident = database.get_incident("legacy-incident")
                notification = database.list_automation_notifications()[0]

                self.assertIsNotNone(state)
                self.assertIsNotNone(incident)
                self.assertEqual(event.fingerprint, "legacy-fingerprint")
                self.assertEqual(event.title, f"Crash in {safe_path}")
                self.assertEqual(event.entity, f"Application Error at {safe_path}")
                self.assertEqual(event.details["message"], f'Faulting application name: "{safe_path}", version 1.0')
                self.assertEqual(already_safe_event.title, safe_message)
                self.assertEqual(already_safe_event.details["message"], safe_message)
                state_payload = json.loads(state["payload_json"])
                self.assertEqual(state_payload["install_location"], safe_path)
                self.assertEqual(state["payload_hash"], _hash(state_payload))
                self.assertEqual(scan["summary"], {"errors": [safe_path]})
                self.assertEqual(incident["description"], f"Crash after opening {safe_path}")
                self.assertEqual(incident["results"], [{"evidence": safe_path}])
                self.assertEqual(incident["assessment_reasons"], [f"Review {safe_path}"])
                self.assertEqual(incident["coverage"], {"path": safe_path})
                self.assertEqual(
                    incident["feedback"],
                    {"outcome": "correct", "event_id": "legacy-event", "recorded_at": timestamp},
                )
                self.assertEqual(
                    notification,
                    {
                        "id": "legacy-notification",
                        "created_at": timestamp,
                        "kind": "warning",
                        "title": f"Problem in {safe_path}",
                        "body": f"Review {safe_path}",
                        "event_id": "legacy-event",
                        "incident_id": "legacy-incident",
                        "read_at": None,
                    },
                )

    def test_concurrent_first_opens_finish_with_one_complete_schema(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "concurrent.db"
            errors: list[Exception] = []
            barrier = threading.Barrier(2)

            def open_and_close() -> None:
                try:
                    barrier.wait(timeout=10)
                    with Database(path) as database:
                        self.assertEqual(database.schema_status()["current_version"], 6)
                except Exception as exc:  # capture thread failures for the test thread
                    errors.append(exc)

            threads = [threading.Thread(target=open_and_close) for _ in range(2)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(timeout=10)
            self.assertFalse(any(thread.is_alive() for thread in threads))
            self.assertEqual(errors, [])
            with Database(path) as database:
                self.assertTrue(database.schema_status()["up_to_date"])

    def test_event_time_filters_are_applied_before_limit(self) -> None:
        with Database(":memory:") as database:
            now = utc_now()
            database.save_events(
                [
                    Event(now - timedelta(days=2), "change", "graphics", "updated", "Old change", event_id="old"),
                    Event(now - timedelta(hours=1), "change", "graphics", "updated", "Recent change", event_id="recent"),
                ]
            )

            events = database.list_events(
                limit=1,
                ascending=True,
                since=now - timedelta(days=1),
                until=now,
            )

            self.assertEqual([event.event_id for event in events], ["recent"])

    def test_status_skips_integrity_scan_until_explicitly_requested(self) -> None:
        with Database(":memory:") as database:
            status = database.status()
            self.assertEqual(status["journal"]["integrity"], "not checked")
            self.assertEqual(database.journal_diagnostics()["integrity"], "ok")

    def test_incident_json_parser_handles_missing_legacy_columns(self) -> None:
        with Database(":memory:") as database:
            row = database.connection.execute(
                """
                SELECT
                    'incident' AS id,
                    '2026-08-01T00:00:00Z' AS created_at,
                    'problem' AS description,
                    'general' AS subsystem,
                    '2026-08-01T00:00:00Z' AS onset_start,
                    '2026-08-01T00:00:00Z' AS onset_end,
                    7 AS lookback_days,
                    'investigating' AS status,
                    '[]' AS result_json,
                    NULL AS feedback_outcome,
                    NULL AS feedback_event_id,
                    NULL AS feedback_at
                """
            ).fetchone()

            incident = Database._incident_row(row)

            self.assertEqual(incident["assessment"], "insufficient_evidence")
            self.assertEqual(incident["assessment_reasons"], [])
            self.assertEqual(incident["coverage"], {})

    def test_investigation_coverage_aggregates_all_overlapping_scans(self) -> None:
        with Database(":memory:") as database:
            now = utc_now()
            older = database.start_scan(now - timedelta(days=2))
            database.finish_scan(
                older,
                now - timedelta(days=2),
                "partial",
                {"errors": ["drivers: provider unavailable"]},
            )
            latest = database.start_scan(now - timedelta(hours=1))
            database.finish_scan(latest, now - timedelta(hours=1), "ok", {"errors": []})

            coverage = database.investigation_coverage(
                "graphics",
                since=now - timedelta(days=3),
                until=now,
            )

            self.assertTrue(coverage["limited"])
            self.assertEqual(coverage["scan_count"], 2)
            self.assertEqual(coverage["provider_warning_count"], 1)
            self.assertEqual(coverage["scan_status_counts"], {"ok": 1, "partial": 1})

    def test_first_snapshot_is_quiet_and_second_snapshot_emits_transition(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            with Database(Path(folder) / "journal.db") as database:
                now = utc_now()
                first = SnapshotItem("services", "svc", "startup", "Service Example", {"state": "Stopped", "start_mode": "Auto"})
                self.assertEqual(database.apply_snapshot("services", [first], occurred_at=now), [])
                changed = SnapshotItem("services", "svc", "startup", "Service Example", {"state": "Running", "start_mode": "Manual"})
                events = database.apply_snapshot("services", [changed], occurred_at=now + timedelta(minutes=5))
                self.assertEqual(len(events), 1)
                self.assertEqual(events[0].action, "updated")
                self.assertEqual(database.count_events("change"), 1)

    def test_runtime_state_and_localized_display_fields_do_not_create_changes(self) -> None:
        with Database(":memory:") as database:
            now = utc_now()
            service = SnapshotItem(
                "services",
                "svc",
                "startup",
                "Service Example",
                {"display_name": "Service Example", "state": "Stopped", "start_mode": "Auto"},
            )
            database.apply_snapshot("services", [service], occurred_at=now)
            stable = SnapshotItem(
                "services",
                "svc",
                "startup",
                "Service Example",
                {"display_name": "Service Example", "state": "Running", "start_mode": "Auto"},
            )
            self.assertEqual(database.apply_snapshot("services", [stable], occurred_at=now + timedelta(minutes=1)), [])

    def test_bits_trigger_oscillation_is_quiet_but_real_config_change_is_recorded(self) -> None:
        with Database(":memory:") as database:
            now = utc_now()
            running = SnapshotItem(
                "services",
                "BITS",
                "startup",
                "Service Background Intelligent Transfer Service",
                {"name": "BITS", "state": "Running", "start_mode": "Auto", "start_name": "LocalSystem"},
            )
            stopped = SnapshotItem(
                "services",
                "BITS",
                "startup",
                "Service Background Intelligent Transfer Service",
                {"name": "BITS", "state": "Stopped", "start_mode": "Manual", "start_name": "LocalSystem"},
            )
            self.assertEqual(database.apply_snapshot("services", [running], occurred_at=now), [])
            self.assertEqual(database.apply_snapshot("services", [stopped], occurred_at=now + timedelta(minutes=5)), [])
            self.assertEqual(database.apply_snapshot("services", [running], occurred_at=now + timedelta(minutes=10)), [])
            disabled = SnapshotItem(
                "services",
                "BITS",
                "startup",
                "Service Background Intelligent Transfer Service",
                {"name": "BITS", "state": "Running", "start_mode": "Disabled", "start_name": "LocalSystem"},
            )
            self.assertEqual(len(database.apply_snapshot("services", [disabled], occurred_at=now + timedelta(minutes=15))), 1)
            self.assertEqual(database.count_events("change"), 1)

    def test_legacy_eventlog_entities_are_backfilled_on_reopen(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "journal.db"
            event = Event(
                utc_now(),
                "symptom",
                "application",
                "crash",
                "Application crash detected",
                entity="Application Error",
                source="eventlog",
                details={"message": r"Faulting application name: C:\Games\Example.exe, version 1.0"},
            )
            with Database(path) as database:
                database.save_events([event])
                database.connection.execute(
                    "DELETE FROM meta WHERE key = ?",
                    ("migration:safe-application-entities",),
                )
                database.connection.commit()

            with Database(path) as database:
                stored = database.list_events(kind="symptom")[0]
                self.assertEqual(stored.entity, "Example.exe")
                self.assertEqual(stored.details["application_name"], "Example.exe")

    def test_legacy_app_keys_are_migrated_without_false_events(self) -> None:
        with Database(":memory:") as database:
            now = utc_now()
            old = SnapshotItem(
                "apps",
                "Steam App 1|Game?",
                "application",
                "Application Game?",
                {"key": "Steam App 1", "name": "Game?", "publisher": "Publisher?", "version": "1"},
            )
            database.apply_snapshot("apps", [old], occurred_at=now)
            current = SnapshotItem(
                "apps",
                "Steam App 1",
                "application",
                "Application Game™",
                {"key": "Steam App 1", "name": "Game™", "publisher": "Publisher", "version": "1"},
            )
            self.assertEqual(database.apply_snapshot("apps", [current], occurred_at=now + timedelta(minutes=1)), [])
            apps_status = next(item for item in database.source_status() if item["source"] == "apps")
            self.assertEqual(apps_status["item_count"], 1)

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

    def test_legacy_device_event_area_is_normalized_when_read(self) -> None:
        with Database(":memory:") as database:
            now = utc_now()
            event = Event(
                now,
                "change",
                "graphics",
                "added",
                "Device LG monitor audio endpoint added",
                entity="LG monitor (NVIDIA High Definition Audio)",
                source="devices",
                details={"after": {"name": "LG monitor (NVIDIA High Definition Audio)"}},
            )
            database.save_events([event])
            self.assertEqual(database.list_events()[0].subsystem, "audio")

    def test_legacy_nvidia_service_event_area_is_normalized_when_read(self) -> None:
        with Database(":memory:") as database:
            now = utc_now()
            event = Event(
                now,
                "change",
                "startup",
                "updated",
                "Service NVIDIA Display Container LS updated",
                entity="NVDisplay.ContainerLocalSystem",
                source="services",
                details={
                    "before": {"path": r"C:\Windows\System32\DriverStore\FileRepository\nv_old\Display.NvContainer\NVDisplay.Container.exe"},
                    "after": {"path": r"C:\Windows\System32\DriverStore\FileRepository\nv_new\Display.NvContainer\NVDisplay.Container.exe"},
                },
            )
            database.save_events([event])
            self.assertEqual(database.list_events()[0].subsystem, "graphics")

    def test_status_exposes_structured_last_scan_summary(self) -> None:
        with Database(":memory:") as database:
            now = utc_now()
            scan_id = database.start_scan(now)
            database.finish_scan(scan_id, now, "partial", {"errors": ["provider unavailable"]})
            database.connection.execute(
                "UPDATE scans SET summary_json = ? WHERE id = ?",
                (json.dumps({"errors": [r"drivers: C:\Users\Raven\private.log"]}), scan_id),
            )
            database.connection.commit()
            status = database.status()
            self.assertEqual(status["last_scan"]["status"], "partial")
            self.assertNotIn("Raven", json.dumps(status["last_scan"]["summary"]))

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
