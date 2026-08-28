import json
import sqlite3
import tempfile
import threading
import unittest
from datetime import timedelta
from pathlib import Path
from unittest.mock import patch

from difftrail.db import BASE_SCHEMA, Database, _hash
from difftrail.models import Event, IncidentRequest, SnapshotItem, utc_now


class DatabaseTests(unittest.TestCase):
    def test_fresh_journal_records_numbered_migrations(self) -> None:
        with Database(":memory:") as database:
            schema = database.schema_status()
            self.assertEqual(schema["current_version"], schema["supported_version"])
            self.assertEqual([item["version"] for item in schema["migrations"]], [1, 2, 3, 4, 5, 6, 7])

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

    def test_stale_scan_owner_cannot_finish_after_replacement(self) -> None:
        with Database(":memory:") as database:
            now = utc_now()
            slow_scan = database.start_scan(now - timedelta(hours=1))
            replacement_scan = database.start_scan(now)

            with self.assertRaisesRegex(RuntimeError, "lease is no longer active"):
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
            self.assertEqual(rows[slow_scan]["status"], "interrupted")
            self.assertEqual(rows[replacement_scan]["status"], "running")

    def test_replaced_stale_scan_cannot_write_snapshot_state(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "journal.db"
            now = utc_now()
            with Database(path) as old_owner, Database(path) as replacement:
                old_scan = old_owner.start_scan(now - timedelta(hours=1))
                new_scan = replacement.start_scan(now)
                old_item = SnapshotItem("apps", "old", "application", "Old", {"version": "1"})
                new_item = SnapshotItem("apps", "new", "application", "New", {"version": "2"})

                with self.assertRaisesRegex(RuntimeError, "lease is no longer active"):
                    old_owner.apply_snapshot("apps", [old_item], occurred_at=now, scan_id=old_scan)
                replacement.apply_snapshot("apps", [new_item], occurred_at=now, scan_id=new_scan)
                replacement.finish_scan(new_scan, now, "ok", {"errors": []})

                rows = old_owner.connection.execute(
                    "SELECT item_key FROM state_items WHERE source = 'apps'"
                ).fetchall()
                self.assertEqual([row["item_key"] for row in rows], ["new"])

    def test_scan_lease_check_keeps_the_write_lock_until_snapshot_write(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "journal.db"
            now = utc_now()
            with Database(path) as owner:
                scan_id = owner.start_scan(now)
                contender = sqlite3.connect(path, timeout=0)
                contender.execute("PRAGMA busy_timeout = 0")
                takeover = {"succeeded": False, "blocked": False}
                original_get_meta = owner.get_meta

                def get_meta_with_takeover(key: str, default: str | None = None) -> str | None:
                    value = original_get_meta(key, default)
                    if key == "scan:active":
                        try:
                            contender.execute(
                                "UPDATE scans SET status = 'interrupted' WHERE id = ?", (scan_id,)
                            )
                            contender.execute(
                                "UPDATE meta SET value = ? WHERE key = 'scan:active'", ("replacement",)
                            )
                            contender.commit()
                            takeover["succeeded"] = True
                        except sqlite3.OperationalError:
                            contender.rollback()
                            takeover["blocked"] = True
                    return value

                item = SnapshotItem("apps", "owned", "application", "Owned", {"version": "1"})
                try:
                    with patch.object(owner, "get_meta", side_effect=get_meta_with_takeover):
                        owner.apply_snapshot("apps", [item], occurred_at=now, scan_id=scan_id)
                finally:
                    contender.close()

                self.assertTrue(takeover["blocked"])
                self.assertFalse(takeover["succeeded"])
                rows = owner.connection.execute(
                    "SELECT item_key FROM state_items WHERE source = 'apps'"
                ).fetchall()
                self.assertEqual([row["item_key"] for row in rows], ["owned"])

    def test_active_scan_blocks_a_second_scan(self) -> None:
        with Database(":memory:") as database:
            now = utc_now()
            database.start_scan(now)
            with self.assertRaisesRegex(RuntimeError, "already running"):
                database.start_scan(now + timedelta(seconds=1))

    def test_concurrent_scan_starts_on_one_connection_get_a_clean_conflict(self) -> None:
        with Database(":memory:") as database:
            now = utc_now()
            barrier = threading.Barrier(2)
            outcomes: list[str] = []

            def start() -> None:
                try:
                    barrier.wait(timeout=5)
                    database.start_scan(now)
                    outcomes.append("started")
                except RuntimeError as exc:
                    outcomes.append(str(exc))

            threads = [threading.Thread(target=start) for _ in range(2)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(timeout=5)

            self.assertFalse(any(thread.is_alive() for thread in threads))
            self.assertEqual(outcomes.count("started"), 1)
            self.assertEqual(sum("already running" in outcome for outcome in outcomes), 1)

    def test_invalid_snapshot_state_is_reset_for_a_quiet_resync(self) -> None:
        with Database(":memory:") as database:
            now = utc_now()
            item = SnapshotItem("apps", "example", "application", "Example", {"version": "1"})
            database.apply_snapshot("apps", [item], occurred_at=now)
            database.connection.execute(
                "UPDATE state_items SET payload_json = ? WHERE source = ? AND item_key = ?",
                ("[]", "apps", "example"),
            )
            database.connection.commit()

            with self.assertRaisesRegex(RuntimeError, "has been reset"):
                database.apply_snapshot("apps", [item], occurred_at=now + timedelta(minutes=1))

            self.assertEqual(
                database.connection.execute("SELECT COUNT(*) FROM state_items WHERE source = 'apps'").fetchone()[0],
                0,
            )
            self.assertIsNone(database.get_meta("source:apps:initialized"))
            self.assertEqual(database.apply_snapshot("apps", [item], occurred_at=now + timedelta(minutes=2)), [])

    def test_existing_driver_state_is_quietly_rebaselined_for_installed_inventory(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "driver-inventory.db"
            now = utc_now()
            item = SnapshotItem(
                "drivers",
                "PCI\\GPU",
                "graphics",
                "Driver for GPU",
                {"device_id": "PCI\\GPU", "version": "1.0"},
            )
            with Database(path) as database:
                database.apply_snapshot("drivers", [item], occurred_at=now)
                database.connection.execute(
                    "DELETE FROM meta WHERE key = ?",
                    ("migration:installed-driver-inventory",),
                )
                database.connection.commit()

            with Database(path) as database:
                self.assertEqual(
                    database.connection.execute(
                        "SELECT COUNT(*) FROM state_items WHERE source = 'drivers'"
                    ).fetchone()[0],
                    0,
                )
                self.assertIsNone(database.get_meta("source:drivers:initialized"))
                self.assertEqual(database.get_meta("migration:installed-driver-inventory"), "1")
                self.assertEqual(
                    database.apply_snapshot(
                        "drivers",
                        [item],
                        occurred_at=now + timedelta(minutes=1),
                    ),
                    [],
                )

    def test_deep_persisted_event_details_are_ignored_on_read(self) -> None:
        with Database(":memory:") as database:
            now = utc_now()
            database.save_events([Event(now, "symptom", "general", "failure", "Deep details", event_id="deep")])
            deep_json = '{"nested":' * 100 + '"leaf"' + "}" * 100
            database.connection.execute("UPDATE events SET details_json = ? WHERE id = ?", (deep_json, "deep"))
            database.connection.commit()
            self.assertEqual(database.list_events(limit=1)[0].details, {})

    def test_v5_deep_json_migrates_without_blocking_database_open(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "deep-v5.db"
            deep_json = '{"nested":' * 100 + '"leaf"' + "}" * 100
            connection = sqlite3.connect(path)
            connection.executescript(BASE_SCHEMA)
            connection.executescript(
                """
                ALTER TABLE incidents ADD COLUMN assessment TEXT NOT NULL DEFAULT 'insufficient_evidence';
                ALTER TABLE incidents ADD COLUMN assessment_reasons_json TEXT NOT NULL DEFAULT '[]';
                ALTER TABLE incidents ADD COLUMN coverage_json TEXT NOT NULL DEFAULT '{}';
                """
            )
            connection.execute("INSERT INTO meta(key, value) VALUES (?, ?)", ("schema_version", "5"))
            connection.execute(
                """
                INSERT INTO events
                (id, occurred_at, kind, subsystem, action, title, entity, severity, source,
                 details_json, fingerprint, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    "deep-legacy",
                    "2026-08-10T10:00:00Z",
                    "symptom",
                    "general",
                    "failure",
                    "Legacy details",
                    "",
                    "medium",
                    "eventlog",
                    deep_json,
                    "deep-legacy",
                    "2026-08-10T10:00:00Z",
                ),
            )
            connection.commit()
            connection.close()

            with Database(path) as database:
                self.assertEqual(database.schema_status()["current_version"], 7)
                self.assertEqual(database.list_events(limit=1)[0].details, {})

    def test_ascending_event_limit_keeps_the_most_recent_evidence(self) -> None:
        with Database(":memory:") as database:
            now = utc_now()
            database.save_events(
                [
                    Event(now - timedelta(minutes=2), "change", "general", "changed", "first", event_id="first"),
                    Event(now - timedelta(minutes=1), "change", "general", "changed", "second", event_id="second"),
                    Event(now, "change", "general", "changed", "third", event_id="third"),
                ]
            )
            events = database.list_events(limit=10, maximum_limit=2, ascending=True)
            self.assertEqual([event.event_id for event in events], ["second", "third"])

    def test_journal_with_only_scan_history_is_not_empty_for_simulation(self) -> None:
        with Database(":memory:") as database:
            database.start_scan(utc_now())
            self.assertFalse(database.is_empty())
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
                self.assertTrue(
                    {
                        "feedback_outcome",
                        "feedback_event_id",
                        "feedback_at",
                        "affected_entity",
                        "suspected_change",
                    }.issubset(columns)
                )

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
                self.assertEqual(schema["current_version"], 7)
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

    def test_v6_journal_adds_optional_context_without_rewriting_existing_drafts(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "v6-context.db"
            legacy_schema = BASE_SCHEMA.replace(
                "    feedback_at TEXT,\n    affected_entity TEXT,\n    suspected_change TEXT\n",
                "    feedback_at TEXT\n",
            )
            connection = sqlite3.connect(path)
            connection.executescript(legacy_schema)
            connection.executescript(
                """
                ALTER TABLE incidents ADD COLUMN assessment TEXT NOT NULL DEFAULT 'insufficient_evidence';
                ALTER TABLE incidents ADD COLUMN assessment_reasons_json TEXT NOT NULL DEFAULT '[]';
                ALTER TABLE incidents ADD COLUMN coverage_json TEXT NOT NULL DEFAULT '{}';
                """
            )
            connection.executemany(
                "INSERT INTO meta(key, value) VALUES (?, ?)",
                [("schema_version", "6"), ("migration:safe-application-entities", "1")],
            )
            connection.execute(
                """
                INSERT INTO incidents
                (id, created_at, description, subsystem, onset_start, onset_end, lookback_days, status,
                 result_json, assessment, assessment_reasons_json, coverage_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    "old-draft",
                    "2026-08-15T12:00:00Z",
                    "Automatic draft: Application crash detected",
                    "application",
                    "2026-08-15T12:00:00Z",
                    "2026-08-15T12:00:00Z",
                    7,
                    "draft",
                    "[]",
                    "insufficient_evidence",
                    "[]",
                    "{}",
                ),
            )
            connection.commit()
            connection.close()

            with Database(path) as database:
                incident = database.get_incident("old-draft")
                current_version = database.schema_status()["current_version"]
                columns = {
                    row[1]
                    for row in database.connection.execute("PRAGMA table_info(incidents)").fetchall()
                }

            self.assertEqual(current_version, 7)
            self.assertTrue({"affected_entity", "suspected_change"}.issubset(columns))
            self.assertEqual(incident["description"], "Automatic draft: Application crash detected")
            self.assertIsNone(incident["affected_entity"])
            self.assertIsNone(incident["suspected_change"])

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
                self.assertEqual(database.schema_status()["current_version"], 7)
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
                        self.assertEqual(database.schema_status()["current_version"], 7)
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

    def test_per_user_service_suffix_rotation_keeps_a_stable_baseline(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            with Database(Path(folder) / "journal.db") as database:
                now = utc_now()
                before = SnapshotItem(
                    "services",
                    "OneSyncSvc_c837b",
                    "startup",
                    "Service OneSyncSvc_c837b",
                    {
                        "name": "OneSyncSvc_c837b",
                        "display_name": "OneSyncSvc_c837b",
                        "state": "Stopped",
                        "start_mode": "Manual",
                        "start_name": "",
                        "path": r"C:\Windows\System32\svchost.exe -k UnistackSvcGroup",
                    },
                )
                database.apply_snapshot("services", [before], occurred_at=now)
                after = SnapshotItem(
                    "services",
                    "OneSyncSvc",
                    "startup",
                    "Service OneSyncSvc",
                    {
                        "name": "OneSyncSvc_c1a2e",
                        "display_name": "OneSyncSvc_c1a2e",
                        "state": "Stopped",
                        "start_mode": "Manual",
                        "start_name": "",
                        "path": r"C:\Windows\System32\svchost.exe -k UnistackSvcGroup",
                        "per_user_service": True,
                        "service_base_name": "OneSyncSvc",
                        "service_instance_suffix": "c1a2e",
                        "service_type": "Share Process",
                    },
                )
                self.assertEqual(database.apply_snapshot("services", [after], occurred_at=now + timedelta(minutes=5)), [])
                self.assertEqual(database.count_events("change"), 0)

    def test_unrelated_suffixed_service_does_not_match_a_per_user_family(self) -> None:
        with Database(":memory:") as database:
            now = utc_now()
            before = SnapshotItem(
                "services",
                "Vendor_abcd",
                "startup",
                "Service Vendor",
                {
                    "name": "Vendor_abcd",
                    "start_mode": "Manual",
                    "per_user_service": True,
                    "service_base_name": "Vendor",
                    "service_instance_suffix": "abcd",
                },
            )
            database.apply_snapshot("services", [before], occurred_at=now)

            unrelated = SnapshotItem(
                "services",
                "Vendor_abcd",
                "startup",
                "Service Vendor",
                {"name": "Vendor_abcd", "start_mode": "Manual"},
            )
            events = database.apply_snapshot(
                "services",
                [unrelated],
                occurred_at=now + timedelta(minutes=1),
            )

            self.assertEqual(len(events), 1)
            self.assertEqual(events[0].action, "updated")

    def test_snapshot_state_rolls_back_when_event_write_fails(self) -> None:
        with Database(":memory:") as database:
            now = utc_now()
            baseline = SnapshotItem("services", "svc", "startup", "Service Example", {"start_mode": "Auto"})
            changed = SnapshotItem("services", "svc", "startup", "Service Example", {"start_mode": "Manual"})
            database.apply_snapshot("services", [baseline], occurred_at=now)
            database.connection.execute(
                "CREATE TRIGGER fail_event_insert BEFORE INSERT ON events "
                "BEGIN SELECT RAISE(ABORT, 'injected event write failure'); END"
            )
            database.connection.commit()

            with self.assertRaises(sqlite3.IntegrityError):
                database.apply_snapshot("services", [changed], occurred_at=now + timedelta(minutes=1))

            stored_payload = json.loads(
                database.connection.execute(
                    "SELECT payload_json FROM state_items WHERE source = ? AND item_key = ?",
                    ("services", "svc"),
                ).fetchone()[0]
            )
            self.assertEqual(stored_payload["start_mode"], "Auto")
            database.connection.execute("DROP TRIGGER fail_event_insert")
            database.connection.commit()

            retry_events = database.apply_snapshot("services", [changed], occurred_at=now + timedelta(minutes=2))
            self.assertEqual(len(retry_events), 1)
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

    def test_field_service_burst_is_quiet_when_meaningful_state_is_identical(self) -> None:
        with Database(":memory:") as database:
            now = utc_now()
            baseline = [
                SnapshotItem(
                    "services", f"service-{index}", "startup", f"Service {index}",
                    {"name": f"service-{index}", "display_name": f"Service {index}", "state": "Stopped", "start_mode": "Manual", "start_name": "LocalSystem", "path": rf"C:\\Windows\\service{index}.exe"},
                )
                for index in range(24)
            ]
            database.apply_snapshot("services", baseline, occurred_at=now)
            observed_again = [
                SnapshotItem(
                    item.source,
                    item.key,
                    item.subsystem,
                    item.display_name,
                    {**item.payload, "start_name": f" {item.payload['start_name']} ", "path": f"{item.payload['path']}???   "},
                )
                for item in baseline
            ]

            self.assertEqual(database.apply_snapshot("services", observed_again, occurred_at=now + timedelta(minutes=1)), [])
            self.assertEqual(database.count_events("change"), 0)

            changed = list(observed_again)
            changed[0] = SnapshotItem(
                "services", changed[0].key, "startup", changed[0].display_name,
                {**changed[0].payload, "start_mode": "Disabled"},
            )
            events = database.apply_snapshot("services", changed, occurred_at=now + timedelta(minutes=2))
            self.assertEqual(len(events), 1)
            self.assertEqual(events[0].details["before"]["start_mode"], "Manual")
            self.assertEqual(events[0].details["after"]["start_mode"], "Disabled")

    def test_bulk_per_user_service_suffix_rotation_becomes_one_evidence_event(self) -> None:
        with Database(":memory:") as database:
            now = utc_now()
            families = ["cbdhsvc", "WpnUserService", "UserDataSvc", "UnistoreSvc"]
            old = [
                SnapshotItem(
                    "services",
                    base,
                    "startup",
                    f"Service {base}",
                    {
                        "name": f"{base}_a1234",
                        "start_mode": "Manual",
                        "path": "svchost.exe",
                        "service_type": "Share Process",
                        "per_user_service": True,
                        "service_base_name": base,
                        "service_instance_suffix": "a1234",
                    },
                )
                for base in families
            ]
            new = [
                SnapshotItem(
                    "services",
                    base,
                    "startup",
                    f"Service {base}",
                    {
                        **item.payload,
                        "name": f"{base}_d7351",
                        "service_instance_suffix": "d7351",
                    },
                )
                for base, item in zip(families, old)
            ]
            database.apply_snapshot("services", old, occurred_at=now)
            events = database.apply_snapshot("services", new, occurred_at=now + timedelta(minutes=1))

            self.assertEqual(len(events), 1)
            self.assertEqual(events[0].action, "refreshed")
            self.assertEqual(events[0].details["instance_count"], 4)
            self.assertEqual(len(events[0].details["evidence"]), 4)
            self.assertEqual(database.count_events("change"), 1)

    def test_concurrent_per_user_service_rotations_preserve_instances_and_config_changes(self) -> None:
        def instance(suffix: str, start_mode: str = "Manual") -> SnapshotItem:
            name = f"WpnUserService_{suffix}"
            return SnapshotItem(
                "services",
                name,
                "startup",
                "Service WpnUserService",
                {
                    "name": name,
                    "start_mode": start_mode,
                    "path": "svchost.exe",
                    "service_type": "Share Process",
                    "per_user_service": True,
                    "service_base_name": "WpnUserService",
                    "service_instance_suffix": suffix,
                },
            )

        with Database(":memory:") as database:
            now = utc_now()
            database.apply_snapshot(
                "services",
                [instance("a1234"), instance("b1234")],
                occurred_at=now,
            )
            self.assertEqual(
                database.apply_snapshot(
                    "services",
                    [instance("c1234"), instance("d1234")],
                    occurred_at=now + timedelta(minutes=1),
                ),
                [],
            )
            self.assertEqual(
                database.connection.execute(
                    "SELECT COUNT(*) FROM state_items WHERE source = 'services'"
                ).fetchone()[0],
                2,
            )

            changed = database.apply_snapshot(
                "services",
                [instance("e1234", "Auto"), instance("f1234")],
                occurred_at=now + timedelta(minutes=2),
            )
            self.assertEqual([event.action for event in changed], ["updated"])
            self.assertEqual(changed[0].details["after"]["start_mode"], "Auto")

            removed = database.apply_snapshot(
                "services",
                [instance("e1234", "Auto")],
                occurred_at=now + timedelta(minutes=3),
            )
            self.assertEqual([event.action for event in removed], ["removed"])

    def test_third_party_hex_suffix_rotation_remains_an_add_and_remove(self) -> None:
        with Database(":memory:") as database:
            now = utc_now()
            old = SnapshotItem(
                "services",
                "Example_abcd",
                "startup",
                "Service Example",
                {"name": "Example_abcd", "path": r"C:\Program Files\Example\service.exe"},
            )
            new = SnapshotItem(
                "services",
                "Example_dead",
                "startup",
                "Service Example",
                {"name": "Example_dead", "path": r"C:\Program Files\Example\service.exe"},
            )
            database.apply_snapshot("services", [old], occurred_at=now)

            events = database.apply_snapshot(
                "services", [new], occurred_at=now + timedelta(minutes=1)
            )

            self.assertEqual(sorted(event.action for event in events), ["added", "removed"])
            self.assertFalse(
                any(event.details.get("refresh_kind") for event in events)
            )

    def test_single_suffixed_service_install_and_persistent_change_remain_visible(self) -> None:
        with Database(":memory:") as database:
            now = utc_now()
            database.apply_snapshot("services", [], occurred_at=now)
            installed = SnapshotItem("services", "ExampleSvc_a1234", "startup", "Service Example", {"name": "ExampleSvc_a1234", "start_mode": "Manual"})
            install_events = database.apply_snapshot("services", [installed], occurred_at=now + timedelta(minutes=1))
            self.assertEqual([event.action for event in install_events], ["added"])
            configured = SnapshotItem("services", installed.key, "startup", installed.display_name, {**installed.payload, "start_mode": "Auto"})
            update_events = database.apply_snapshot("services", [configured], occurred_at=now + timedelta(minutes=2))
            self.assertEqual([event.action for event in update_events], ["updated"])

    def test_legacy_suffixed_service_key_migrates_quietly_to_logical_key(self) -> None:
        with Database(":memory:") as database:
            now = utc_now()
            old = SnapshotItem(
                "services",
                "WpnUserService_a1234",
                "startup",
                "Service Push",
                {
                    "name": "WpnUserService_a1234",
                    "start_mode": "Manual",
                    "path": "svchost.exe",
                    "service_type": "Share Process",
                },
            )
            database.apply_snapshot("services", [old], occurred_at=now)
            current = SnapshotItem(
                "services",
                "WpnUserService",
                "startup",
                "Service Push",
                {
                    "name": "WpnUserService_d7351",
                    "start_mode": "Manual",
                    "path": "svchost.exe",
                    "service_type": "Share Process",
                    "per_user_service": True,
                    "service_base_name": "WpnUserService",
                    "service_instance_suffix": "d7351",
                },
            )

            self.assertEqual(database.apply_snapshot("services", [current], occurred_at=now + timedelta(minutes=1)), [])
            row = database.connection.execute("SELECT item_key FROM state_items WHERE source = 'services'").fetchone()
            self.assertEqual(row["item_key"], "WpnUserService")

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
            request = IncidentRequest(
                "graphics are crashing",
                now - timedelta(hours=1),
                now,
                "graphics",
                7,
                affected_entity="ExampleGame.exe",
                suspected_change="graphics driver update",
            )
            incident = database.create_incident(request)
            database.update_incident_results(incident.id, [{"confidence": "High"}])
            self.assertEqual(database.count_events(), 1)
            self.assertEqual(database.recent_incidents()[0]["results"][0]["confidence"], "High")
            self.assertEqual(database.recent_incidents()[0]["affected_entity"], "ExampleGame.exe")
            self.assertEqual(database.recent_incidents()[0]["suspected_change"], "graphics driver update")

    def test_delete_incident_preserves_events_and_unlinks_automation_references(self) -> None:
        with Database(":memory:") as database:
            now = utc_now()
            event = Event(now, "symptom", "application", "crash", "Application crash", event_id="event-for-deletion")
            database.save_events([event])
            incident = database.create_incident(
                IncidentRequest("graphics are crashing", now - timedelta(hours=1), now, "graphics", 7)
            )
            database.record_automation_action(
                "event-for-deletion",
                "draft_investigation",
                incident_id=incident.id,
            )
            database.create_automation_notification(
                kind="crash",
                title="High-severity signal detected",
                body="Review the evidence.",
                event_id="event-for-deletion",
                incident_id=incident.id,
            )

            self.assertTrue(database.delete_incident(incident.id))
            self.assertIsNone(database.get_incident(incident.id))
            self.assertEqual(database.count_events(), 1)
            self.assertIsNone(database.automation_action_incident_id("event-for-deletion", "draft_investigation"))
            self.assertIsNone(database.list_automation_notifications()[0]["incident_id"])
            self.assertFalse(database.delete_incident(incident.id))

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

    def test_malformed_old_symptom_details_are_removed_without_blocking_pruning(self) -> None:
        with Database(":memory:") as database:
            now = utc_now()
            database.save_events(
                [Event(now - timedelta(days=31), "symptom", "application", "crash", "Application crash", source="test")]
            )
            database.connection.execute(
                "UPDATE events SET details_json = ? WHERE kind = 'symptom'",
                ("{not valid json with raw detail}",),
            )
            database.connection.commit()

            self.assertEqual(database.prune_sensitive_symptom_details(as_of=now), 1)
            stored = database.list_events(kind="symptom")[0]
            self.assertEqual(stored.details, {"raw_message_retained": False})

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
