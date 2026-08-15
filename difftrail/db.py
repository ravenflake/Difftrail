from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
import uuid
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Iterable

from .assessment import ASSESSMENT_STATES, NEUTRAL_ASSESSMENT
from .models import Event, Incident, IncidentRequest, SnapshotItem, ensure_utc, iso_datetime, parse_datetime, utc_now
from .privacy import (
    extract_safe_application_name,
    redact_legacy_text,
    redact_legacy_value,
    redact_text,
    redact_value,
)
from .service_identity import is_per_user_service_payload, service_base_name


DEFAULT_RETENTION_DAYS = 30
DATABASE_SCHEMA_VERSION = 6
STALE_SCAN_AFTER = timedelta(minutes=15)
MAX_PERSISTED_JSON_NESTING = 64
VALID_SCAN_STATUSES = frozenset({"running", "ok", "partial", "failed", "interrupted"})
VALID_INVESTIGATION_ASSESSMENTS = ASSESSMENT_STATES
_DATABASE_INITIALIZATION_LOCK = threading.RLock()
_AUTOMATION_LINK_REPAIR_CURSOR = "automation:link-repair-cursor"


# These fields describe runtime state or localized display metadata rather
# than a durable configuration change. They remain in event details for
# inspection, but do not decide whether a snapshot item changed.
IGNORED_SNAPSHOT_FIELDS: dict[str, frozenset[str]] = {
    "apps": frozenset({"name", "publisher"}),
    "drivers": frozenset({"device_name", "manufacturer"}),
    "services": frozenset({"display_name", "state"}),
    "tasks": frozenset({"state"}),
    "devices": frozenset({"name", "manufacturer", "status"}),
}

# BITS is a trigger-start service. Win32_Service can report its trigger state
# as an Auto/Running or Manual/Stopped pair between scans even when no durable
# service configuration changed. Keep the raw values in event details, but do
# not turn this known oscillation into a journal event.
TRIGGER_START_SERVICES = frozenset({"bits"})
MIN_PER_USER_SERVICE_REFRESH_PAIRS = 4


REMOVED_SUBSYSTEMS = {
    "updates": "windows-update",
    "apps": "application",
    "drivers": "driver",
    "services": "startup",
    "tasks": "startup",
    "startup": "startup",
    "devices": "device",
}


BASE_SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS events (
    id TEXT PRIMARY KEY,
    occurred_at TEXT NOT NULL,
    kind TEXT NOT NULL CHECK(kind IN ('change', 'symptom')),
    subsystem TEXT NOT NULL,
    action TEXT NOT NULL,
    title TEXT NOT NULL,
    entity TEXT NOT NULL DEFAULT '',
    severity TEXT NOT NULL,
    source TEXT NOT NULL,
    details_json TEXT NOT NULL DEFAULT '{}',
    fingerprint TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_events_occurred_at ON events(occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_events_kind_subsystem ON events(kind, subsystem, occurred_at DESC);
CREATE UNIQUE INDEX IF NOT EXISTS idx_events_fingerprint ON events(fingerprint);

CREATE TABLE IF NOT EXISTS state_items (
    source TEXT NOT NULL,
    item_key TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    payload_hash TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    PRIMARY KEY(source, item_key)
);

CREATE TABLE IF NOT EXISTS scans (
    id TEXT PRIMARY KEY,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    status TEXT NOT NULL,
    summary_json TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS incidents (
    id TEXT PRIMARY KEY,
    created_at TEXT NOT NULL,
    description TEXT NOT NULL,
    subsystem TEXT NOT NULL,
    onset_start TEXT NOT NULL,
    onset_end TEXT NOT NULL,
    lookback_days INTEGER NOT NULL,
    status TEXT NOT NULL,
    result_json TEXT NOT NULL DEFAULT '[]',
    feedback_outcome TEXT,
    feedback_event_id TEXT,
    feedback_at TEXT
);

CREATE TABLE IF NOT EXISTS overhead_measurements (
    id TEXT PRIMARY KEY,
    measured_at TEXT NOT NULL,
    interval_seconds INTEGER NOT NULL,
    warmup_seconds REAL NOT NULL,
    sample_seconds REAL NOT NULL,
    startup_process_tree_cpu_percent REAL NOT NULL,
    process_tree_cpu_percent REAL NOT NULL,
    startup_rss_mb_peak REAL NOT NULL,
    rss_mb_mean REAL NOT NULL,
    rss_mb_peak REAL NOT NULL,
    startup_disk_read_mb REAL NOT NULL,
    startup_disk_write_mb REAL NOT NULL,
    disk_read_mb REAL NOT NULL,
    disk_write_mb REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS automation_actions (
    id TEXT PRIMARY KEY,
    event_id TEXT NOT NULL,
    action TEXT NOT NULL,
    created_at TEXT NOT NULL,
    incident_id TEXT,
    UNIQUE(event_id, action)
);

CREATE TABLE IF NOT EXISTS automation_notifications (
    id TEXT PRIMARY KEY,
    created_at TEXT NOT NULL,
    kind TEXT NOT NULL,
    title TEXT NOT NULL,
    body TEXT NOT NULL,
    event_id TEXT,
    incident_id TEXT,
    read_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_scans_started_at ON scans(started_at DESC);
CREATE INDEX IF NOT EXISTS idx_incidents_created_at ON incidents(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_overhead_measured_at ON overhead_measurements(measured_at DESC);
CREATE INDEX IF NOT EXISTS idx_automation_notifications_created_at ON automation_notifications(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_automation_notifications_unread ON automation_notifications(read_at, created_at DESC);
"""


def _execute_script_statements(connection: sqlite3.Connection, script: str) -> None:
    """Execute a simple SQL script statement-by-statement inside a caller transaction."""

    statement = ""
    for line in script.splitlines(keepends=True):
        statement += line
        if sqlite3.complete_statement(statement):
            sql = statement.strip()
            if sql:
                connection.execute(sql)
            statement = ""
    if statement.strip():
        connection.execute(statement)


def _table_columns(connection: sqlite3.Connection, table: str) -> set[str]:
    return {
        str(row[0])
        for row in connection.execute("SELECT name FROM pragma_table_info(?)", (table,)).fetchall()
    }


def _canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)


def _hash(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _json_nesting_is_safe(value: Any, *, maximum: int = MAX_PERSISTED_JSON_NESTING) -> bool:
    """Bound legacy JSON traversal before it reaches recursive serializers."""

    stack: list[tuple[Any, int]] = [(value, 0)]
    while stack:
        current, depth = stack.pop()
        if depth > maximum:
            return False
        if isinstance(current, dict):
            stack.extend((child, depth + 1) for child in current.values())
        elif isinstance(current, list):
            stack.extend((child, depth + 1) for child in current)
    return True


def _redact_stored_json(value: str | None) -> tuple[str, Any | None]:
    """Return a redacted stored JSON document without rewriting unchanged rows."""

    encoded = value or ""
    try:
        parsed = json.loads(encoded)
    except (json.JSONDecodeError, RecursionError):
        # Invalid legacy JSON cannot be safely interpreted or redacted. Drop
        # it instead of leaving a potentially sensitive payload that can make
        # every later scan fail.
        return "{}", None
    if not _json_nesting_is_safe(parsed):
        return "{}", None
    try:
        redacted = redact_legacy_value(parsed)
    except RecursionError:
        return "{}", None
    return (_canonical_json(redacted) if redacted != parsed else encoded, redacted)


def _comparison_value(source: str, key: str, value: Any) -> Any:
    if isinstance(value, dict):
        return {str(child_key): _comparison_value(source, str(child_key), child_value) for child_key, child_value in value.items()}
    if isinstance(value, list):
        return [_comparison_value(source, key, child) for child in value]
    if not isinstance(value, str):
        return value
    normalized = value.replace("\x00", "").replace("\ufffd", "").replace("\ufffe", "").replace("\uffff", "")
    # These fields are known to arrive with padding/replacement question
    # marks from a few registry/service providers. A Windows path cannot
    # contain a literal question mark, and version/date padding is not data.
    if (source == "apps" and key in {"install_date", "version"}) or (source == "services" and key == "path"):
        normalized = normalized.rstrip("?").rstrip()
    if source == "services":
        normalized = normalized.strip()
    return normalized


def _comparison_payload(source: str, payload: dict[str, Any]) -> dict[str, Any]:
    safe_payload = _comparison_value(source, "", redact_value(payload))
    ignored = IGNORED_SNAPSHOT_FIELDS.get(source, frozenset())
    if source == "services" and is_per_user_service_payload(safe_payload):
        # The suffixed name and LUID identify a user session. They are not a
        # durable service configuration change and would otherwise turn every
        # sign-in/session refresh into an add/remove storm.
        ignored = ignored | frozenset(
            {
                "name",
                "service_instance_suffix",
                "per_user_service",
                "service_base_name",
            }
        )
    return {key: value for key, value in safe_payload.items() if key not in ignored}


def _per_user_service_family(payload: dict[str, Any], key: str) -> str | None:
    """Return a trusted logical family only for metadata-qualified user services."""

    if not is_per_user_service_payload(payload):
        return None
    explicit = str(payload.get("service_base_name", "")).strip()
    name = str(payload.get("name", key)).strip()
    return (
        explicit
        or service_base_name(
            name,
            path=str(payload.get("path", "")),
            service_type=str(payload.get("service_type", "")),
            trusted=payload.get("per_user_service") is True,
        )
    ).casefold()


def _paired_per_user_service_family(
    before: dict[str, Any],
    after: dict[str, Any],
    before_key: str,
    after_key: str,
) -> str | None:
    """Return the shared family when at least one side has trusted metadata."""

    before_family = _per_user_service_family(before, before_key)
    after_family = _per_user_service_family(after, after_key)
    if before_family and after_family:
        return before_family if before_family == after_family else None
    trusted_family = before_family or after_family
    if trusted_family is None:
        return None
    other_payload = after if before_family else before
    other_key = after_key if before_family else before_key
    other_name = str(other_payload.get("name", other_key)).strip()
    other_family = service_base_name(
        other_name,
        path=str(other_payload.get("path", "")),
        service_type=str(other_payload.get("service_type", "")),
        trusted=other_payload.get("per_user_service") is True,
    ).casefold()
    return trusted_family if other_family == trusted_family else None


def _normalize_per_user_service_pair(
    before: dict[str, Any],
    after: dict[str, Any],
    before_comparison: dict[str, Any],
    after_comparison: dict[str, Any],
    before_key: str,
    after_key: str,
) -> tuple[dict[str, Any], dict[str, Any], str | None]:
    """Remove session identity symmetrically while retaining configuration."""

    family = _paired_per_user_service_family(before, after, before_key, after_key)
    if family is None:
        return before_comparison, after_comparison, None
    before_normalized = dict(before_comparison)
    after_normalized = dict(after_comparison)
    for field in ("name", "per_user_service", "service_base_name", "service_instance_suffix"):
        before_normalized.pop(field, None)
        after_normalized.pop(field, None)
    # Historical snapshots predate ServiceType collection. Quiet that one-time
    # schema migration, but compare ServiceType once both sides contain it.
    if "service_type" not in before or "service_type" not in after:
        before_normalized.pop("service_type", None)
        after_normalized.pop("service_type", None)
    return before_normalized, after_normalized, family


def _is_bits_trigger_oscillation(source: str, before: dict[str, Any], after: dict[str, Any]) -> bool:
    if source != "services":
        return False
    if str(before.get("name", "")).casefold() not in TRIGGER_START_SERVICES:
        return False
    if str(after.get("name", "")).casefold() not in TRIGGER_START_SERVICES:
        return False
    modes = {str(before.get("start_mode", "")).casefold(), str(after.get("start_mode", "")).casefold()}
    states = {str(before.get("state", "")).casefold(), str(after.get("state", "")).casefold()}
    return modes == {"auto", "manual"} and states == {"running", "stopped"}


def _event_subsystem(source: str, stored_subsystem: str, title: str, entity: str, details: dict[str, Any]) -> str:
    """Normalize source-only/legacy event areas when reading the journal."""

    context_parts = [title, entity]
    for value in details.values():
        if isinstance(value, dict):
            context_parts.extend(str(item) for item in value.values())
    context = " ".join(context_parts).casefold()
    if source in {"devices", "drivers", "services"}:
        if any(token in context for token in ("audio", "sound", "speaker", "microphone", "realtek")):
            return "audio"
        if any(token in context for token in ("display", "graphics", "nvidia", "radeon", "geforce", "amd gpu")):
            return "graphics"
        if any(token in context for token in ("bluetooth", "wi-fi", "wifi", "wireless", "ethernet", "network")):
            return "network"
    return REMOVED_SUBSYSTEMS.get(stored_subsystem, stored_subsystem)


class Database:
    """Small SQLite repository for normalized local evidence."""

    def __init__(self, path: str | Path) -> None:
        self._scan_lock = threading.RLock()
        self.path = Path(path) if str(path) != ":memory:" else Path(":memory:")
        database_target = ":memory:" if str(path) == ":memory:" else str(self.path)
        if database_target != ":memory:":
            self.path.parent.mkdir(parents=True, exist_ok=True)
        # SQLite serializes schema writes, but concurrent first opens can still
        # race in connection pragmas and leave one constructor with a locked
        # database. Initialization is short and infrequent, so serialize it in
        # process and clean up a connection if setup fails before __enter__.
        with _DATABASE_INITIALIZATION_LOCK:
            try:
                self.connection = sqlite3.connect(database_target, timeout=30, check_same_thread=False)
                self.connection.row_factory = sqlite3.Row
                self.connection.execute("PRAGMA foreign_keys = ON")
                self.connection.execute("PRAGMA busy_timeout = 30000")
                if database_target != ":memory:":
                    self.connection.execute("PRAGMA journal_mode = WAL")
                self.connection.execute("PRAGMA synchronous = NORMAL")
                self._run_migrations()
                # This compatibility backfill intentionally remains safe to rerun. It
                # also repairs a journal where an older build's marker was lost without
                # changing the schema version or deleting any evidence.
                self._backfill_safe_application_entities()
                self._repair_automation_links()
            except Exception:
                connection = getattr(self, "connection", None)
                if connection is not None:
                    connection.close()
                raise

    def _run_migrations(self) -> None:
        """Apply numbered, transactional migrations to fresh and legacy journals."""

        self.connection.execute(
            """
            CREATE TABLE IF NOT EXISTS schema_migrations (
                version INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                applied_at TEXT NOT NULL
            )
            """
        )
        self.connection.execute(
            """
            CREATE TABLE IF NOT EXISTS meta (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )
            """
        )
        self.connection.commit()

        stored_version = self.get_meta("schema_version")
        if stored_version is None:
            inferred = self._infer_legacy_schema_version()
            self._record_legacy_baseline(inferred)
            current_version = inferred
        else:
            try:
                current_version = int(stored_version)
            except (TypeError, ValueError) as exc:
                raise RuntimeError("The Difftrail journal has an invalid schema version") from exc
            if current_version < 0 or current_version > DATABASE_SCHEMA_VERSION:
                raise RuntimeError(
                    f"The Difftrail journal schema version {current_version} is not supported"
                )

        migrations: dict[int, tuple[str, Any]] = {
            1: ("base journal tables", lambda: _execute_script_statements(self.connection, BASE_SCHEMA)),
            2: ("incident feedback fields", self._migration_incident_feedback),
            3: ("safe application entity backfill", self._migration_safe_application_entities),
            4: ("journal lookup indexes", self._migration_lookup_indexes),
            5: ("investigation assessment fields", self._migration_investigation_assessment),
            6: ("legacy journal privacy re-sanitization", self._migration_redact_legacy_journal),
        }
        for version in range(current_version + 1, DATABASE_SCHEMA_VERSION + 1):
            name, callback = migrations[version]
            self._apply_migration(version, name, callback)

        if self.get_meta("schema_version") != str(DATABASE_SCHEMA_VERSION):
            self.set_meta("schema_version", str(DATABASE_SCHEMA_VERSION))

    def _infer_legacy_schema_version(self) -> int:
        tables = {
            str(row[0])
            for row in self.connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            ).fetchall()
        }
        required_tables = {"meta", "events", "state_items", "scans", "incidents"}
        if not required_tables.issubset(tables):
            return 0
        incident_columns = _table_columns(self.connection, "incidents")
        if not {"feedback_outcome", "feedback_event_id", "feedback_at"}.issubset(incident_columns):
            return 1
        if self.get_meta("migration:safe-application-entities") != "1":
            return 2
        # The safe-application marker only proves migration 3. Migration 4
        # owns the lookup indexes and must still run for these journals.
        return 3

    def _record_legacy_baseline(self, version: int) -> None:
        if version <= 0:
            return
        timestamp = iso_datetime(utc_now())
        for applied_version in range(1, version + 1):
            self.connection.execute(
                "INSERT OR IGNORE INTO schema_migrations(version, name, applied_at) VALUES (?, ?, ?)",
                (applied_version, f"legacy baseline v{applied_version}", timestamp),
            )
        self.connection.execute(
            "INSERT INTO meta(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            ("schema_version", str(version)),
        )
        self.connection.commit()

    def _apply_migration(self, version: int, name: str, callback: Any) -> None:
        """Run one migration atomically so an interrupted migration can retry."""

        try:
            self.connection.execute("BEGIN IMMEDIATE")
            already_applied = self.connection.execute(
                "SELECT 1 FROM schema_migrations WHERE version = ?",
                (version,),
            ).fetchone()
            if already_applied:
                self.connection.commit()
                return
            callback()
            self.connection.execute(
                "INSERT OR IGNORE INTO schema_migrations(version, name, applied_at) VALUES (?, ?, ?)",
                (version, name, iso_datetime(utc_now())),
            )
            self.connection.execute(
                "INSERT INTO meta(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                ("schema_version", str(version)),
            )
            self.connection.commit()
        except Exception:
            self.connection.rollback()
            raise

    def _migration_incident_feedback(self) -> None:
        columns = _table_columns(self.connection, "incidents")
        statements = {
            "feedback_outcome": "ALTER TABLE incidents ADD COLUMN feedback_outcome TEXT",
            "feedback_event_id": "ALTER TABLE incidents ADD COLUMN feedback_event_id TEXT",
            "feedback_at": "ALTER TABLE incidents ADD COLUMN feedback_at TEXT",
        }
        for name, statement in statements.items():
            if name not in columns:
                self.connection.execute(statement)

    def _migration_safe_application_entities(self) -> None:
        self._backfill_safe_application_entities(commit=False)

    def _migration_lookup_indexes(self) -> None:
        self.connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_scans_status_started_at ON scans(status, started_at DESC)"
        )
        self.connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_events_source_occurred_at ON events(source, occurred_at DESC)"
        )

    def _migration_investigation_assessment(self) -> None:
        columns = _table_columns(self.connection, "incidents")
        if "assessment" not in columns:
            self.connection.execute(
                "ALTER TABLE incidents ADD COLUMN assessment TEXT NOT NULL DEFAULT 'insufficient_evidence'"
            )
        if "assessment_reasons_json" not in columns:
            self.connection.execute(
                "ALTER TABLE incidents ADD COLUMN assessment_reasons_json TEXT NOT NULL DEFAULT '[]'"
            )
        if "coverage_json" not in columns:
            self.connection.execute(
                "ALTER TABLE incidents ADD COLUMN coverage_json TEXT NOT NULL DEFAULT '{}'"
            )

    def _migration_redact_legacy_journal(self) -> None:
        """Apply the current profile-path redaction to data written by older builds."""

        event_updates: list[tuple[str, str, str, str]] = []
        for row in self.connection.execute("SELECT id, title, entity, details_json FROM events").fetchall():
            title = redact_legacy_text(str(row["title"] or ""))
            entity = redact_legacy_text(str(row["entity"] or ""))
            details_json, _ = _redact_stored_json(row["details_json"])
            if (title, entity, details_json) != (row["title"], row["entity"], row["details_json"]):
                event_updates.append((title, entity, details_json, row["id"]))
        if event_updates:
            # Event identifiers and fingerprints are durable feedback/deduplication
            # keys, so privacy normalization must not replace either one.
            self.connection.executemany(
                "UPDATE events SET title = ?, entity = ?, details_json = ? WHERE id = ?",
                event_updates,
            )

        state_updates: list[tuple[str, str, str, str]] = []
        invalid_state_sources: set[str] = set()
        for row in self.connection.execute(
            "SELECT source, item_key, payload_json, payload_hash FROM state_items"
        ).fetchall():
            payload_json, payload = _redact_stored_json(row["payload_json"])
            if not isinstance(payload, dict):
                invalid_state_sources.add(str(row["source"]))
                continue
            if payload_json != row["payload_json"]:
                payload_hash = _hash(payload)
                state_updates.append((payload_json, payload_hash, row["source"], row["item_key"]))
        if state_updates:
            self.connection.executemany(
                "UPDATE state_items SET payload_json = ?, payload_hash = ? WHERE source = ? AND item_key = ?",
                state_updates,
            )
        for source in invalid_state_sources:
            # A partial source state cannot produce a trustworthy diff. Reset
            # it so the next successful provider read establishes a quiet
            # baseline rather than emitting a storm of false removals.
            self.connection.execute("DELETE FROM state_items WHERE source = ?", (source,))
            self.connection.execute("DELETE FROM meta WHERE key = ?", (f"source:{source}:initialized",))

        scan_updates: list[tuple[str, str]] = []
        for row in self.connection.execute("SELECT id, summary_json FROM scans").fetchall():
            summary_json, _ = _redact_stored_json(row["summary_json"])
            if summary_json != row["summary_json"]:
                scan_updates.append((summary_json, row["id"]))
        if scan_updates:
            self.connection.executemany("UPDATE scans SET summary_json = ? WHERE id = ?", scan_updates)

        incident_updates: list[tuple[str, str, str, str, str]] = []
        for row in self.connection.execute(
            "SELECT id, description, result_json, assessment_reasons_json, coverage_json FROM incidents"
        ).fetchall():
            description = redact_legacy_text(str(row["description"] or ""))
            result_json, _ = _redact_stored_json(row["result_json"])
            assessment_reasons_json, _ = _redact_stored_json(row["assessment_reasons_json"])
            coverage_json, _ = _redact_stored_json(row["coverage_json"])
            if (description, result_json, assessment_reasons_json, coverage_json) != (
                row["description"],
                row["result_json"],
                row["assessment_reasons_json"],
                row["coverage_json"],
            ):
                incident_updates.append(
                    (description, result_json, assessment_reasons_json, coverage_json, row["id"])
                )
        if incident_updates:
            self.connection.executemany(
                """
                UPDATE incidents
                SET description = ?, result_json = ?, assessment_reasons_json = ?, coverage_json = ?
                WHERE id = ?
                """,
                incident_updates,
            )

        notification_updates: list[tuple[str, str, str, str]] = []
        for row in self.connection.execute("SELECT id, kind, title, body FROM automation_notifications").fetchall():
            kind = redact_legacy_text(str(row["kind"] or ""))
            title = redact_legacy_text(str(row["title"] or ""))
            body = redact_legacy_text(str(row["body"] or ""))
            if (kind, title, body) != (row["kind"], row["title"], row["body"]):
                notification_updates.append((kind, title, body, row["id"]))
        if notification_updates:
            self.connection.executemany(
                "UPDATE automation_notifications SET kind = ?, title = ?, body = ? WHERE id = ?",
                notification_updates,
            )

    def _backfill_safe_application_entities(self, *, commit: bool = True) -> None:
        """Add parsed executable labels to older local symptom records."""

        if self.get_meta("migration:safe-application-entities") == "1":
            return
        rows = self.connection.execute(
            "SELECT id, entity, details_json FROM events WHERE kind = 'symptom' AND source = 'eventlog'"
        ).fetchall()
        updates: list[tuple[str, str, str]] = []
        generic_entities = {"", "Application Error", "Application Hang"}
        for row in rows:
            if row["entity"] not in generic_entities:
                continue
            try:
                details = json.loads(row["details_json"] or "{}")
            except (json.JSONDecodeError, RecursionError):
                continue
            if not isinstance(details, dict) or not _json_nesting_is_safe(details):
                continue
            application_name = details.get("application_name") or extract_safe_application_name(str(details.get("message", "")))
            if not application_name:
                continue
            details["application_name"] = application_name
            updates.append((application_name, _canonical_json(details), row["id"]))
        if updates:
            self.connection.executemany("UPDATE events SET entity = ?, details_json = ? WHERE id = ?", updates)
        self.connection.execute(
            "INSERT INTO meta(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            ("migration:safe-application-entities", "1"),
        )
        # When called outside a migration, persist the marker immediately. A
        # migration caller already owns the transaction and opts out.
        if commit:
            self.connection.commit()

    def _repair_automation_links(self, *, commit: bool = True) -> None:
        """Repair unlinked automatic drafts in one bounded write transaction.

        Older watcher races could persist the idempotency marker and draft but
        lose the association between them. A durable ``created_at``/``id``
        cursor prevents unmatched legacy markers from being rescanned on every
        database open. Candidate validation and both link updates share an
        immediate transaction so incident deletion cannot interleave and leave
        a dangling link.
        """

        had_transaction = self.connection.in_transaction
        if not had_transaction:
            self.connection.execute("BEGIN IMMEDIATE")
        try:
            cursor_value = self.get_meta(_AUTOMATION_LINK_REPAIR_CURSOR)
            cursor_created_at = ""
            cursor_id = ""
            if cursor_value:
                try:
                    parsed_cursor = json.loads(cursor_value)
                except (json.JSONDecodeError, TypeError):
                    parsed_cursor = None
                if isinstance(parsed_cursor, dict):
                    cursor_created_at = str(parsed_cursor.get("created_at", ""))
                    cursor_id = str(parsed_cursor.get("id", ""))

            if cursor_created_at and cursor_id:
                rows = self.connection.execute(
                    """
                    SELECT id, event_id, created_at
                    FROM automation_actions
                    WHERE action = 'draft_investigation'
                      AND incident_id IS NULL
                      AND (created_at > ? OR (created_at = ? AND id > ?))
                    ORDER BY created_at ASC, id ASC
                    """,
                    (cursor_created_at, cursor_created_at, cursor_id),
                ).fetchall()
            else:
                rows = self.connection.execute(
                    """
                    SELECT id, event_id, created_at
                    FROM automation_actions
                    WHERE action = 'draft_investigation' AND incident_id IS NULL
                    ORDER BY created_at ASC, id ASC
                    """
                ).fetchall()

            action_updates: list[tuple[str, str, str]] = []
            for row in rows:
                event = self.connection.execute(
                    "SELECT title, subsystem, occurred_at FROM events WHERE id = ?",
                    (row["event_id"],),
                ).fetchone()
                if event is None:
                    continue
                candidates = self.connection.execute(
                    """
                    SELECT id
                    FROM incidents
                    WHERE description = ?
                      AND subsystem = ?
                      AND onset_start = ?
                      AND onset_end = ?
                      AND lookback_days = 7
                      AND status = 'draft'
                    ORDER BY created_at DESC
                    """,
                    (
                        f"Automatic draft: {event['title']}",
                        event["subsystem"],
                        event["occurred_at"],
                        event["occurred_at"],
                    ),
                ).fetchall()
                if len(candidates) == 1:
                    action_updates.append(
                        (str(candidates[0]["id"]), str(row["event_id"]), str(row["id"]))
                    )
            for incident_id, event_id, action_id in action_updates:
                self.connection.execute(
                    """
                    UPDATE automation_actions
                    SET incident_id = ?
                    WHERE id = ? AND event_id = ? AND action = 'draft_investigation'
                      AND incident_id IS NULL
                      AND EXISTS (SELECT 1 FROM incidents WHERE id = ?)
                    """,
                    (incident_id, action_id, event_id, incident_id),
                )
                self.connection.execute(
                    """
                    UPDATE automation_notifications
                    SET incident_id = ?
                    WHERE event_id = ? AND kind = 'crash' AND incident_id IS NULL
                      AND EXISTS (SELECT 1 FROM incidents WHERE id = ?)
                    """,
                    (incident_id, event_id, incident_id),
                )

            if rows:
                last = rows[-1]
                self._set_meta_without_commit(
                    _AUTOMATION_LINK_REPAIR_CURSOR,
                    _canonical_json({"created_at": str(last["created_at"]), "id": str(last["id"])}),
                )
            if commit:
                self.connection.commit()
        except Exception:
            if not had_transaction:
                self.connection.rollback()
            raise

    def close(self) -> None:
        self.connection.close()

    def __enter__(self) -> "Database":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def get_meta(self, key: str, default: str | None = None) -> str | None:
        row = self.connection.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
        return str(row[0]) if row else default

    def retention_days(self) -> int:
        value = self.get_meta("retention:symptom_days", str(DEFAULT_RETENTION_DAYS))
        try:
            return max(1, min(int(value or DEFAULT_RETENTION_DAYS), 3650))
        except ValueError:
            return DEFAULT_RETENTION_DAYS

    def set_retention_days(self, days: int) -> None:
        if days < 1 or days > 3650:
            raise ValueError("Retention must be between 1 and 3650 days")
        self.set_meta("retention:symptom_days", str(days))

    def set_meta(self, key: str, value: str) -> None:
        self._set_meta_without_commit(key, value)
        self.connection.commit()

    def _set_meta_without_commit(self, key: str, value: str) -> None:
        """Persist metadata inside the caller's transaction."""

        self.connection.execute(
            "INSERT INTO meta(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, value),
        )

    def set_meta_for_active_scan(self, scan_id: str, key: str, value: str) -> None:
        """Set scan-owned metadata only while the scan still holds its lease."""

        with self.connection:
            self._assert_scan_lease(scan_id)
            self._set_meta_without_commit(key, value)

    def record_automation_action(
        self,
        event_id: str,
        action: str,
        *,
        incident_id: str | None = None,
        created_at: datetime | None = None,
        commit: bool = True,
    ) -> bool:
        """Record an automation action once so retries remain idempotent."""

        cursor = self.connection.execute(
            """
            INSERT OR IGNORE INTO automation_actions
            (id, event_id, action, created_at, incident_id)
            VALUES (?, ?, ?, ?, ?)
            """,
            (str(uuid.uuid4()), event_id, action, iso_datetime(created_at or utc_now()), incident_id),
        )
        if commit:
            self.connection.commit()
        return cursor.rowcount == 1

    def automation_action_incident_id(self, event_id: str, action: str) -> str | None:
        """Return an existing automation action's draft link, if any."""

        row = self.connection.execute(
            "SELECT incident_id FROM automation_actions WHERE event_id = ? AND action = ?",
            (event_id, action),
        ).fetchone()
        return str(row["incident_id"]) if row and row["incident_id"] is not None else None

    def link_automation_action_to_incident(
        self,
        event_id: str,
        action: str,
        incident_id: str,
        *,
        commit: bool = True,
    ) -> int:
        """Attach a retry-created draft without overwriting an existing link."""

        cursor = self.connection.execute(
            """
            UPDATE automation_actions
            SET incident_id = ?
            WHERE event_id = ? AND action = ? AND incident_id IS NULL
            """,
            (incident_id, event_id, action),
        )
        if commit:
            self.connection.commit()
        return int(cursor.rowcount)

    def link_automation_notification_to_incident(
        self,
        event_id: str,
        kind: str,
        incident_id: str,
        *,
        commit: bool = True,
    ) -> int:
        """Attach a retry-created draft to an already delivered notification."""

        cursor = self.connection.execute(
            """
            UPDATE automation_notifications
            SET incident_id = ?
            WHERE event_id = ? AND kind = ? AND incident_id IS NULL
            """,
            (incident_id, event_id, kind),
        )
        if commit:
            self.connection.commit()
        return int(cursor.rowcount)

    def create_automation_notification(
        self,
        *,
        kind: str,
        title: str,
        body: str,
        event_id: str | None = None,
        incident_id: str | None = None,
        created_at: datetime | None = None,
        commit: bool = True,
    ) -> str:
        """Persist a safe, local notification for the desktop inbox."""

        notification_id = str(uuid.uuid4())
        self.connection.execute(
            """
            INSERT INTO automation_notifications
            (id, created_at, kind, title, body, event_id, incident_id, read_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, NULL)
            """,
            (
                notification_id,
                iso_datetime(created_at or utc_now()),
                redact_text(kind),
                redact_text(title),
                redact_text(body),
                event_id,
                incident_id,
            ),
        )
        if commit:
            self.connection.commit()
        return notification_id

    def list_automation_notifications(
        self,
        *,
        limit: int = 25,
        unread_only: bool = False,
    ) -> list[dict[str, Any]]:
        clauses = ["1 = 1"]
        params: list[Any] = []
        if unread_only:
            clauses.append("read_at IS NULL")
        params.append(max(1, min(limit, 100)))
        rows = self.connection.execute(
            f"""
            SELECT id, created_at, kind, title, body, event_id, incident_id, read_at
            FROM automation_notifications
            WHERE {' AND '.join(clauses)}
            ORDER BY created_at DESC
            LIMIT ?
            """,
            params,
        ).fetchall()
        return [dict(row) for row in rows]

    def unread_automation_notification_count(self) -> int:
        row = self.connection.execute(
            "SELECT COUNT(*) FROM automation_notifications WHERE read_at IS NULL"
        ).fetchone()
        return int(row[0])

    def mark_automation_notifications_read(
        self,
        ids: Iterable[str] | None = None,
        *,
        read_at: datetime | None = None,
    ) -> int:
        timestamp = iso_datetime(read_at or utc_now())
        if ids is None:
            cursor = self.connection.execute(
                "UPDATE automation_notifications SET read_at = ? WHERE read_at IS NULL",
                (timestamp,),
            )
        else:
            selected = [str(item) for item in ids if str(item)]
            if not selected:
                return 0
            placeholders = ", ".join("?" for _ in selected)
            cursor = self.connection.execute(
                f"UPDATE automation_notifications SET read_at = ? WHERE read_at IS NULL AND id IN ({placeholders})",
                [timestamp, *selected],
            )
        self.connection.commit()
        return int(cursor.rowcount)

    def automation_draft_count(self) -> int:
        row = self.connection.execute(
            "SELECT COUNT(*) FROM incidents WHERE status = 'draft'"
        ).fetchone()
        return int(row[0])

    def _safe_event(self, event: Event) -> tuple[Event, str, str]:
        safe_title = redact_text(str(event.title))
        safe_entity = redact_text(str(event.entity))
        safe_subsystem = redact_text(str(event.subsystem))
        safe_action = redact_text(str(event.action))
        safe_source = redact_text(str(event.source))
        safe_details = redact_value(event.details)
        fingerprint_payload = {
            "occurred_at": iso_datetime(event.occurred_at),
            "kind": event.kind,
            "subsystem": safe_subsystem,
            "action": safe_action,
            "title": safe_title,
            "entity": safe_entity,
            "source": safe_source,
            "details": safe_details,
        }
        fingerprint = event.fingerprint or _hash(fingerprint_payload)
        event_id = event.event_id or fingerprint
        return (
            Event(
                occurred_at=ensure_utc(event.occurred_at),
                kind=event.kind,
                subsystem=safe_subsystem,
                action=safe_action,
                title=safe_title,
                entity=safe_entity,
                severity=event.severity,
                source=safe_source,
                details=safe_details,
                event_id=event_id,
                fingerprint=fingerprint,
            ),
            event_id,
            fingerprint,
        )

    def _event_rows(self, events: Iterable[Event]) -> list[tuple[Any, ...]]:
        rows = []
        for event in events:
            safe_event, event_id, fingerprint = self._safe_event(event)
            rows.append(
                (
                    event_id,
                    iso_datetime(safe_event.occurred_at),
                    safe_event.kind,
                    safe_event.subsystem,
                    safe_event.action,
                    safe_event.title,
                    safe_event.entity,
                    safe_event.severity,
                    safe_event.source,
                    _canonical_json(safe_event.details),
                    fingerprint,
                    iso_datetime(datetime.now(safe_event.occurred_at.tzinfo)),
                )
            )
        return rows

    def _insert_event_rows(self, rows: Iterable[tuple[Any, ...]]) -> int:
        """Insert normalized event rows without opening or closing a transaction."""

        rows = list(rows)
        if not rows:
            return 0
        before_changes = self.connection.total_changes
        self.connection.executemany(
            """
            INSERT OR IGNORE INTO events
            (id, occurred_at, kind, subsystem, action, title, entity, severity, source,
             details_json, fingerprint, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            rows,
        )
        return self.connection.total_changes - before_changes

    def save_events(self, events: Iterable[Event], *, scan_id: str | None = None) -> int:
        rows = self._event_rows(events)
        if not rows:
            return 0
        with self.connection:
            if scan_id is not None:
                self._assert_scan_lease(scan_id)
            return self._insert_event_rows(rows)

    @staticmethod
    def _row_to_event(row: sqlite3.Row) -> Event:
        try:
            details = json.loads(row["details_json"] or "{}")
        except (json.JSONDecodeError, RecursionError):
            details = {}
        if not isinstance(details, dict) or not _json_nesting_is_safe(details):
            details = {}
        return Event(
            occurred_at=parse_datetime(row["occurred_at"]),
            kind=row["kind"],
            subsystem=_event_subsystem(row["source"], row["subsystem"], row["title"], row["entity"], details),
            action=row["action"],
            title=row["title"],
            entity=row["entity"],
            severity=row["severity"],
            source=row["source"],
            details=details,
            event_id=row["id"],
            fingerprint=row["fingerprint"],
        )

    def list_events(
        self,
        *,
        limit: int = 100,
        kind: str | None = None,
        subsystem: str | None = None,
        search: str | None = None,
        since: datetime | None = None,
        until: datetime | None = None,
        ascending: bool = False,
        maximum_limit: int = 10_000,
    ) -> list[Event]:
        clauses: list[str] = []
        params: list[Any] = []
        if kind and kind != "all":
            clauses.append("kind = ?")
            params.append(kind)
        if subsystem and subsystem != "all":
            clauses.append("subsystem = ?")
            params.append(subsystem)
        if since is not None:
            clauses.append("occurred_at >= ?")
            params.append(iso_datetime(since))
        if until is not None:
            clauses.append("occurred_at <= ?")
            params.append(iso_datetime(until))
        if search and search.strip():
            needle = f"%{search.strip()}%"
            clauses.append("(title LIKE ? OR entity LIKE ? OR details_json LIKE ?)")
            params.extend([needle, needle, needle])
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        if maximum_limit < 1:
            raise ValueError("maximum_limit must be positive")
        params.append(max(1, min(limit, maximum_limit, 100_000)))
        if ascending:
            # For an overfull historical window, retain the events nearest to
            # the present/incident and then return that bounded slice in
            # chronological order. The old ASC LIMIT query silently selected
            # the oldest evidence instead.
            rows = self.connection.execute(
                f"""
                SELECT * FROM (
                    SELECT *, rowid AS _event_rowid
                    FROM events {where}
                    ORDER BY occurred_at DESC, rowid DESC
                    LIMIT ?
                )
                ORDER BY occurred_at ASC, _event_rowid ASC
                """,
                params,
            ).fetchall()
        else:
            rows = self.connection.execute(
                f"SELECT * FROM events {where} ORDER BY occurred_at DESC, rowid DESC LIMIT ?", params
            ).fetchall()
        return [self._row_to_event(row) for row in rows]

    def count_events(self, kind: str | None = None) -> int:
        if kind and kind != "all":
            row = self.connection.execute("SELECT COUNT(*) FROM events WHERE kind = ?", (kind,)).fetchone()
        else:
            row = self.connection.execute("SELECT COUNT(*) FROM events").fetchone()
        return int(row[0])

    def event_rowid_watermark(self) -> int:
        """Return the newest physical event row marker for a scan-local delta."""

        row = self.connection.execute("SELECT COALESCE(MAX(rowid), 0) FROM events").fetchone()
        return int(row[0])

    def list_events_after_rowid(
        self,
        rowid: int,
        *,
        through_rowid: int | None = None,
    ) -> list[Event]:
        """Return a bounded physical journal delta in insertion order."""

        clauses = ["rowid > ?"]
        params: list[Any] = [max(0, int(rowid))]
        if through_rowid is not None:
            clauses.append("rowid <= ?")
            params.append(max(0, int(through_rowid)))
        rows = self.connection.execute(
            f"SELECT * FROM events WHERE {' AND '.join(clauses)} ORDER BY rowid ASC",
            params,
        ).fetchall()
        return [self._row_to_event(row) for row in rows]

    def event_summary(
        self,
        *,
        since: datetime | None = None,
        until: datetime | None = None,
    ) -> dict[str, Any]:
        """Return aggregate event counts without materializing raw evidence."""

        clauses: list[str] = []
        params: list[Any] = []
        if since is not None:
            clauses.append("occurred_at >= ?")
            params.append(iso_datetime(since))
        if until is not None:
            clauses.append("occurred_at <= ?")
            params.append(iso_datetime(until))
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        rows = self.connection.execute(
            f"""
            SELECT kind, source, subsystem, COUNT(*) AS event_count
            FROM events
            {where}
            GROUP BY kind, source, subsystem
            """,
            params,
        ).fetchall()
        changes_by_source: dict[str, int] = {}
        changes_by_subsystem: dict[str, int] = {}
        symptoms_by_subsystem: dict[str, int] = {}
        changes = 0
        symptoms = 0
        for row in rows:
            count = int(row["event_count"])
            if row["kind"] == "change":
                changes += count
                changes_by_source[row["source"]] = changes_by_source.get(row["source"], 0) + count
                changes_by_subsystem[row["subsystem"]] = changes_by_subsystem.get(row["subsystem"], 0) + count
            elif row["kind"] == "symptom":
                symptoms += count
                symptoms_by_subsystem[row["subsystem"]] = symptoms_by_subsystem.get(row["subsystem"], 0) + count
        return {
            "changes": changes,
            "symptoms": symptoms,
            "changes_by_source": dict(sorted(changes_by_source.items())),
            "changes_by_subsystem": dict(sorted(changes_by_subsystem.items())),
            "symptoms_by_subsystem": dict(sorted(symptoms_by_subsystem.items())),
        }

    def is_empty(self) -> bool:
        """Return whether this database is safe to use for a fixture replay."""

        row = self.connection.execute(
            """
            SELECT
                (SELECT COUNT(*) FROM events)
                + (SELECT COUNT(*) FROM state_items)
                + (SELECT COUNT(*) FROM incidents)
                + (SELECT COUNT(*) FROM scans)
                + (SELECT COUNT(*) FROM overhead_measurements)
                + (SELECT COUNT(*) FROM automation_actions)
                + (SELECT COUNT(*) FROM automation_notifications)
            """
        ).fetchone()
        return int(row[0]) == 0

    def apply_snapshot(
        self,
        source: str,
        items: Iterable[SnapshotItem],
        *,
        occurred_at: datetime,
        baseline_if_empty: bool = True,
        scan_id: str | None = None,
    ) -> list[Event]:
        """Diff a complete source snapshot against the last one.

        A source is quiet on its first successful snapshot. This is the baseline
        behavior that prevents a new installation from generating a storm of
        false "changes".
        """

        now = ensure_utc(occurred_at)
        current = {item.key: item for item in items}
        previous_rows = self.connection.execute(
            "SELECT item_key, payload_json FROM state_items WHERE source = ?", (source,)
        ).fetchall()
        initialized_key = f"source:{source}:initialized"
        previous: dict[str, dict[str, Any]] = {}
        invalid_state = False
        for row in previous_rows:
            try:
                payload = json.loads(row["payload_json"])
            except (json.JSONDecodeError, RecursionError):
                invalid_state = True
                break
            if not isinstance(payload, dict) or not _json_nesting_is_safe(payload):
                invalid_state = True
                break
            previous[str(row["item_key"])] = payload
        if invalid_state:
            with self.connection:
                if scan_id is not None:
                    self._assert_scan_lease(scan_id)
                self.connection.execute("DELETE FROM state_items WHERE source = ?", (source,))
                self.connection.execute("DELETE FROM meta WHERE key = ?", (initialized_key,))
            raise RuntimeError(
                f"Stored snapshot state for {source} was invalid and has been reset; it will baseline on the next scan"
            )
        initialized = self.get_meta(initialized_key) == "1"

        generated: list[Event] = []
        matched_previous_keys: set[str] = set()
        service_refresh_evidence: list[dict[str, Any]] = []
        if not initialized and baseline_if_empty:
            with self.connection:
                if scan_id is not None:
                    self._assert_scan_lease(scan_id)
                self._replace_state(source, current, now)
                self._set_meta_without_commit(initialized_key, "1")
            return generated

        for key, item in current.items():
            previous_key = key if key in previous else self._legacy_snapshot_key(
                item, previous, matched_previous_keys, source
            )
            old_payload = previous.get(previous_key) if previous_key is not None else None
            safe_payload = redact_value(item.payload)
            comparison_payload = _comparison_payload(source, item.payload)
            if old_payload is None:
                action = item.action_on_add
            else:
                old_comparison_payload = _comparison_payload(source, old_payload)
                service_family: str | None = None
                if source == "services":
                    old_comparison_payload, comparison_payload, service_family = (
                        _normalize_per_user_service_pair(
                            old_payload,
                            safe_payload,
                            old_comparison_payload,
                            comparison_payload,
                            previous_key or key,
                            key,
                        )
                    )
                if _is_bits_trigger_oscillation(source, old_payload, safe_payload):
                    old_comparison_payload = dict(old_comparison_payload)
                    comparison_payload = dict(comparison_payload)
                    old_comparison_payload.pop("start_mode", None)
                    comparison_payload.pop("start_mode", None)
                changed = _hash(old_comparison_payload) != _hash(comparison_payload)
                if changed:
                    action = item.action_on_update
                else:
                    old_name = str(old_payload.get("name", previous_key or key)).strip()
                    new_name = str(safe_payload.get("name", key)).strip()
                    if (
                        service_family is not None
                        and old_name.casefold() != new_name.casefold()
                    ):
                        service_refresh_evidence.append(
                            {
                                "service_family": service_family,
                                "removed": old_name,
                                "added": new_name,
                                "before": old_payload,
                                "after": safe_payload,
                            }
                        )
                    matched_previous_keys.add(previous_key)
                    continue
            if previous_key is not None:
                matched_previous_keys.add(previous_key)
            title_action = {
                "installed": "installed",
                "updated": "updated",
                "added": "added",
                "changed": "changed",
            }.get(action, action)
            generated.append(
                Event(
                    occurred_at=now,
                    kind="change",
                    subsystem=item.subsystem,
                    action=action,
                    title=f"{item.display_name} {title_action}",
                    entity=item.entity or item.display_name,
                    severity=item.severity,
                    source=source,
                    details={"key": key, "before": old_payload, "after": safe_payload},
                )
            )

        for key, old_payload in previous.items():
            if key not in matched_previous_keys:
                generated.append(
                    Event(
                        occurred_at=now,
                        kind="change",
                        subsystem=REMOVED_SUBSYSTEMS.get(source, source),
                        action="removed",
                        title=f"{source.replace('-', ' ').title()} item removed",
                        entity=key,
                        severity="medium",
                        source=source,
                        details={"key": key, "before": old_payload, "after": None},
                    )
                )

        if len(service_refresh_evidence) >= MIN_PER_USER_SERVICE_REFRESH_PAIRS:
            generated.append(
                Event(
                    occurred_at=now,
                    kind="change",
                    subsystem="startup",
                    action="refreshed",
                    title=(
                        "Windows per-user services refreshed "
                        f"({len(service_refresh_evidence)} instances)"
                    ),
                    entity="Windows per-user services",
                    severity="info",
                    source="services",
                    details={
                        "refresh_kind": "per_user_service_instances",
                        "instance_count": len(service_refresh_evidence),
                        "evidence": service_refresh_evidence,
                    },
                )
            )

        # State replacement, its source marker, and the generated evidence
        # are one durable unit. If the event insert fails (for example, from
        # disk pressure), a retry must still see the previous state and emit
        # the transition rather than silently losing it.
        event_rows = self._event_rows(generated)
        with self.connection:
            if scan_id is not None:
                self._assert_scan_lease(scan_id)
            self._replace_state(source, current, now)
            self._set_meta_without_commit(initialized_key, "1")
            self._insert_event_rows(event_rows)
        return generated

    @staticmethod
    def _legacy_snapshot_key(
        item: SnapshotItem,
        previous: dict[str, dict[str, Any]],
        matched_previous_keys: set[str],
        source: str,
    ) -> str | None:
        """Match state written before app/service keys were made stable."""

        if source == "apps":
            current_key = item.key
            candidates = [
                key
                for key in previous
                if key not in matched_previous_keys and key.split("|", 1)[0] == current_key
            ]
        elif source == "services":
            current_family = _per_user_service_family(item.payload, item.key)
            if current_family is None:
                return None
            candidates = [
                key
                for key, payload in previous.items()
                if key not in matched_previous_keys
                and _per_user_service_family(payload, key) == current_family
            ]
        else:
            return None
        if source == "services" and candidates:
            current_comparison = _comparison_payload(source, item.payload)
            equivalent = []
            for key in candidates:
                old_comparison = _comparison_payload(source, previous[key])
                old_comparison, normalized_current, _ = _normalize_per_user_service_pair(
                    previous[key],
                    item.payload,
                    old_comparison,
                    current_comparison,
                    key,
                    item.key,
                )
                if _hash(old_comparison) == _hash(normalized_current):
                    equivalent.append(key)
            if equivalent:
                candidates = equivalent
        return sorted(candidates, key=str.casefold)[0] if candidates else None

    def _replace_state(self, source: str, current: dict[str, SnapshotItem], now: datetime) -> None:
        timestamp = iso_datetime(now)
        self.connection.execute("DELETE FROM state_items WHERE source = ?", (source,))
        self.connection.executemany(
            """
            INSERT INTO state_items(source, item_key, payload_json, payload_hash, last_seen_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            [
                (
                    source,
                    item.key,
                    _canonical_json(redact_value(item.payload)),
                    _hash(redact_value(item.payload)),
                    timestamp,
                )
                for item in current.values()
            ],
        )

    def start_scan(self, started_at: datetime) -> str:
        # sqlite3 connections configured for cross-thread access still need
        # lifecycle serialization. Without this, two callers can issue BEGIN
        # concurrently on one connection and receive an opaque SQLite error
        # instead of the public "scan already running" result.
        with self._scan_lock:
            scan_id = str(uuid.uuid4())
            started = ensure_utc(started_at)
            try:
                self.connection.execute("BEGIN IMMEDIATE")
                self._recover_stale_scans_locked(started, STALE_SCAN_AFTER)
                self._clear_expired_scan_lease()
                running = self.connection.execute(
                    "SELECT id, started_at FROM scans WHERE status = 'running' ORDER BY started_at ASC"
                ).fetchall()
                if running:
                    oldest = parse_datetime(running[0]["started_at"])
                    raise RuntimeError(
                        f"A scan is already running (started {iso_datetime(oldest)}); wait for it to finish"
                    )
                self.connection.execute(
                    "INSERT INTO scans(id, started_at, status) VALUES (?, ?, ?)",
                    (scan_id, iso_datetime(started), "running"),
                )
                self._set_meta_without_commit("scan:active", scan_id)
                self.connection.commit()
                return scan_id
            except Exception:
                self.connection.rollback()
                raise

    def finish_scan(self, scan_id: str, finished_at: datetime, status: str, summary: dict[str, Any]) -> None:
        if status not in VALID_SCAN_STATUSES - {"running"}:
            raise ValueError(f"Unsupported scan status: {status}")
        encoded_summary = _canonical_json(redact_value(summary))
        with self._scan_lock:
            with self.connection:
                self._assert_scan_lease(scan_id)
                cursor = self.connection.execute(
                    "UPDATE scans SET finished_at = ?, status = ?, summary_json = ? WHERE id = ? AND status = 'running'",
                    (iso_datetime(finished_at), status, encoded_summary, scan_id),
                )
                if cursor.rowcount != 1:
                    raise ValueError(f"Unknown or already finished scan: {scan_id}")
                if self.get_meta("scan:active") == scan_id:
                    self.connection.execute("DELETE FROM meta WHERE key = 'scan:active'")

    @staticmethod
    def _scan_summary(value: str | None) -> dict[str, Any]:
        try:
            parsed = json.loads(value or "{}")
        except (json.JSONDecodeError, RecursionError):
            return {}
        return parsed if isinstance(parsed, dict) and _json_nesting_is_safe(parsed) else {}

    def _assert_scan_lease(self, scan_id: str) -> None:
        # ``with self.connection`` starts a transaction only on its first
        # write. Take the write lock before the lease reads so a replacement
        # scan cannot take over between this check and the owned mutation.
        if not self.connection.in_transaction:
            self.connection.execute("BEGIN IMMEDIATE")
        row = self.connection.execute("SELECT status FROM scans WHERE id = ?", (scan_id,)).fetchone()
        active = self.get_meta("scan:active")
        if not row or row["status"] != "running" or (active is not None and active != scan_id):
            raise RuntimeError("Scan lease is no longer active")

    def _clear_expired_scan_lease(self) -> None:
        active = self.get_meta("scan:active")
        if active is None:
            return
        row = self.connection.execute("SELECT status FROM scans WHERE id = ?", (active,)).fetchone()
        if not row or row["status"] != "running":
            self.connection.execute("DELETE FROM meta WHERE key = 'scan:active'")

    def _recover_stale_scans_locked(self, now: datetime, stale_after: timedelta) -> int:
        cutoff = ensure_utc(now) - stale_after
        rows = self.connection.execute(
            "SELECT id, started_at, summary_json FROM scans WHERE status = 'running' AND started_at < ?",
            (iso_datetime(cutoff),),
        ).fetchall()
        for row in rows:
            summary = self._scan_summary(row["summary_json"])
            summary.update(
                {
                    "status": "interrupted",
                    "recovery": {
                        "reason": "stale_running_scan",
                        "detected_at": iso_datetime(now),
                    },
                }
            )
            self.connection.execute(
                """
                UPDATE scans
                SET finished_at = ?, status = 'interrupted', summary_json = ?
                WHERE id = ? AND status = 'running'
                """,
                (iso_datetime(now), _canonical_json(summary), row["id"]),
            )
        self._clear_expired_scan_lease()
        return len(rows)

    def recover_stale_scans(
        self,
        *,
        now: datetime | None = None,
        stale_after: timedelta = STALE_SCAN_AFTER,
    ) -> int:
        """Mark abandoned running scans as interrupted without deleting their rows."""

        if stale_after <= timedelta(0):
            raise ValueError("stale_after must be positive")
        current = ensure_utc(now or utc_now())
        with self._scan_lock:
            try:
                self.connection.execute("BEGIN IMMEDIATE")
                recovered = self._recover_stale_scans_locked(current, stale_after)
                self.connection.commit()
                return recovered
            except Exception:
                self.connection.rollback()
                raise

    def schema_status(self) -> dict[str, Any]:
        raw_version = self.get_meta("schema_version", "0") or "0"
        try:
            current_version = int(raw_version)
        except ValueError:
            current_version = 0
        migrations = [
            dict(row)
            for row in self.connection.execute(
                "SELECT version, name, applied_at FROM schema_migrations ORDER BY version ASC"
            ).fetchall()
        ]
        return {
            "current_version": current_version,
            "supported_version": DATABASE_SCHEMA_VERSION,
            "up_to_date": current_version == DATABASE_SCHEMA_VERSION,
            "migrations": migrations,
        }

    def _journal_health_snapshot(
        self,
        *,
        now: datetime | None = None,
        stale_after: timedelta = STALE_SCAN_AFTER,
        integrity: str = "not checked",
    ) -> dict[str, Any]:
        current = ensure_utc(now or utc_now())
        schema = self.schema_status()
        running_rows = self.connection.execute(
            "SELECT id, started_at FROM scans WHERE status = 'running' ORDER BY started_at ASC"
        ).fetchall()
        cutoff = current - stale_after
        stale = [
            {"id": row["id"], "started_at": row["started_at"]}
            for row in running_rows
            if parse_datetime(row["started_at"]) < cutoff
        ]
        structurally_healthy = schema["up_to_date"] and not stale
        healthy = structurally_healthy and (integrity in {"ok", "not checked"})
        return {
            "ok": healthy,
            "integrity": integrity,
            "schema": schema,
            "scans": {
                "running": len(running_rows),
                "stale_running": stale,
                "stale_after_seconds": int(stale_after.total_seconds()),
            },
            "journal": {
                "events": self.count_events(),
                "state_items": int(self.connection.execute("SELECT COUNT(*) FROM state_items").fetchone()[0]),
                "incidents": int(self.connection.execute("SELECT COUNT(*) FROM incidents").fetchone()[0]),
            },
        }

    def journal_diagnostics(
        self,
        *,
        now: datetime | None = None,
        stale_after: timedelta = STALE_SCAN_AFTER,
    ) -> dict[str, Any]:
        """Run explicit, non-destructive health checks for the local journal."""

        integrity_row = self.connection.execute("PRAGMA integrity_check").fetchone()
        integrity = str(integrity_row[0]) if integrity_row else "unknown"
        return self._journal_health_snapshot(now=now, stale_after=stale_after, integrity=integrity)

    def create_incident(
        self,
        request: IncidentRequest,
        *,
        created_at: datetime | None = None,
        status: str = "investigating",
        incident_id: str | None = None,
        commit: bool = True,
    ) -> Incident:
        if not status.strip():
            raise ValueError("Incident status must not be empty")
        if incident_id is not None and not incident_id.strip():
            raise ValueError("Incident id must not be empty")
        incident = Incident(id=incident_id or str(uuid.uuid4()), created_at=created_at or utc_now(), request=request, status=status)
        self.connection.execute(
            """
            INSERT INTO incidents
            (id, created_at, description, subsystem, onset_start, onset_end, lookback_days, status, result_json,
             assessment, assessment_reasons_json, coverage_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                incident.id,
                iso_datetime(incident.created_at),
                redact_text(request.description),
                request.subsystem,
                iso_datetime(request.onset_start),
                iso_datetime(request.onset_end),
                request.lookback_days,
                incident.status,
                "[]",
                NEUTRAL_ASSESSMENT,
                "[]",
                "{}",
            ),
        )
        if commit:
            self.connection.commit()
        return incident

    def update_incident_results(
        self,
        incident_id: str,
        results: list[dict[str, Any]],
        status: str = "investigating",
        *,
        assessment: str = NEUTRAL_ASSESSMENT,
        assessment_reasons: Iterable[str] = (),
        coverage: dict[str, Any] | None = None,
        commit: bool = True,
    ) -> None:
        if assessment not in VALID_INVESTIGATION_ASSESSMENTS:
            raise ValueError(f"Unsupported investigation assessment: {assessment}")
        if coverage is None:
            coverage = {}
        cursor = self.connection.execute(
            """
            UPDATE incidents
            SET status = ?, result_json = ?, assessment = ?, assessment_reasons_json = ?, coverage_json = ?
            WHERE id = ?
            """,
            (
                status,
                _canonical_json(redact_value(results)),
                assessment,
                _canonical_json([redact_text(str(reason)) for reason in assessment_reasons]),
                _canonical_json(redact_value(coverage)),
                incident_id,
            ),
        )
        if cursor.rowcount != 1:
            raise ValueError(f"Unknown incident: {incident_id}")
        if commit:
            self.connection.commit()

    def record_incident_feedback(
        self,
        incident_id: str,
        outcome: str,
        *,
        event_id: str | None = None,
        recorded_at: datetime | None = None,
    ) -> dict[str, Any]:
        """Record a user's local assessment of an investigation result."""

        if outcome not in {"correct", "incorrect", "unknown"}:
            raise ValueError("outcome must be correct, incorrect, or unknown")
        incident = self.get_incident(incident_id)
        if incident is None:
            raise ValueError(f"Unknown incident: {incident_id}")
        if outcome == "correct" and not event_id:
            raise ValueError("A correct outcome requires --event-id for top-three measurement")
        if event_id:
            event_row = self.connection.execute("SELECT id FROM events WHERE id = ?", (event_id,)).fetchone()
            if event_row is None:
                raise ValueError(f"Unknown event: {event_id}")
        timestamp = iso_datetime(recorded_at or utc_now())
        self.connection.execute(
            """
            UPDATE incidents
            SET feedback_outcome = ?, feedback_event_id = ?, feedback_at = ?
            WHERE id = ?
            """,
            (outcome, event_id, timestamp, incident_id),
        )
        self.connection.commit()
        updated = self.get_incident(incident_id)
        if updated is None:  # pragma: no cover - the row was checked above
            raise ValueError(f"Unknown incident: {incident_id}")
        return updated

    def delete_incident(self, incident_id: str) -> bool:
        """Remove an investigation and clear automation links to it."""

        with self.connection:
            if not self.connection.in_transaction:
                self.connection.execute("BEGIN IMMEDIATE")
            self.connection.execute(
                "UPDATE automation_actions SET incident_id = NULL WHERE incident_id = ?",
                (incident_id,),
            )
            self.connection.execute(
                "UPDATE automation_notifications SET incident_id = NULL WHERE incident_id = ?",
                (incident_id,),
            )
            cursor = self.connection.execute("DELETE FROM incidents WHERE id = ?", (incident_id,))
        return cursor.rowcount == 1

    @staticmethod
    def _incident_row(row: sqlite3.Row) -> dict[str, Any]:
        def parse_json(name: str, default: Any) -> Any:
            try:
                value = json.loads(row[name] or "")
            except (KeyError, IndexError, TypeError, json.JSONDecodeError, RecursionError):
                return default
            return value if _json_nesting_is_safe(value) else default

        assessment = row["assessment"] if "assessment" in row.keys() else NEUTRAL_ASSESSMENT
        if assessment not in VALID_INVESTIGATION_ASSESSMENTS:
            assessment = NEUTRAL_ASSESSMENT
        reasons = parse_json("assessment_reasons_json", [])
        if not isinstance(reasons, list):
            reasons = []
        coverage = parse_json("coverage_json", {})
        if not isinstance(coverage, dict):
            coverage = {}
        results = parse_json("result_json", [])
        if not isinstance(results, list):
            results = []

        return {
            "id": row["id"],
            "created_at": row["created_at"],
            "description": row["description"],
            "subsystem": row["subsystem"],
            "onset_start": row["onset_start"],
            "onset_end": row["onset_end"],
            "lookback_days": row["lookback_days"],
            "status": row["status"],
            "assessment": assessment,
            "assessment_reasons": reasons,
            "coverage": coverage,
            "results": results,
            "feedback": {
                "outcome": row["feedback_outcome"],
                "event_id": row["feedback_event_id"],
                "recorded_at": row["feedback_at"],
            },
        }

    def get_incident(self, incident_id: str) -> dict[str, Any] | None:
        row = self.connection.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,)).fetchone()
        return self._incident_row(row) if row else None

    def find_incident_id(self, request: IncidentRequest, *, status: str | None = None) -> str | None:
        """Return an incident matching the complete request, if it is unique."""

        clauses = [
            "description = ?",
            "subsystem = ?",
            "onset_start = ?",
            "onset_end = ?",
            "lookback_days = ?",
        ]
        params: list[Any] = [
            request.description,
            request.subsystem,
            iso_datetime(request.onset_start),
            iso_datetime(request.onset_end),
            request.lookback_days,
        ]
        if status is not None:
            clauses.append("status = ?")
            params.append(status)
        rows = self.connection.execute(
            f"SELECT id FROM incidents WHERE {' AND '.join(clauses)} ORDER BY created_at DESC",
            params,
        ).fetchall()
        return str(rows[0]["id"]) if len(rows) == 1 else None

    def list_incidents(
        self,
        *,
        since: datetime | None = None,
        until: datetime | None = None,
        limit: int = 10_000,
    ) -> list[dict[str, Any]]:
        clauses: list[str] = []
        params: list[Any] = []
        if since is not None:
            clauses.append("created_at >= ?")
            params.append(iso_datetime(since))
        if until is not None:
            clauses.append("created_at <= ?")
            params.append(iso_datetime(until))
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        params.append(max(1, min(limit, 100_000)))
        rows = self.connection.execute(
            f"SELECT * FROM incidents {where} ORDER BY created_at DESC LIMIT ?", params
        ).fetchall()
        return [self._incident_row(row) for row in rows]

    def list_scans(
        self,
        *,
        since: datetime | None = None,
        until: datetime | None = None,
        limit: int = 100_000,
    ) -> list[dict[str, Any]]:
        clauses: list[str] = []
        params: list[Any] = []
        if since is not None:
            clauses.append("started_at >= ?")
            params.append(iso_datetime(since))
        if until is not None:
            clauses.append("started_at <= ?")
            params.append(iso_datetime(until))
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        params.append(max(1, min(limit, 100_000)))
        rows = self.connection.execute(
            f"SELECT * FROM scans {where} ORDER BY started_at ASC LIMIT ?", params
        ).fetchall()
        result: list[dict[str, Any]] = []
        for row in rows:
            try:
                summary = json.loads(row["summary_json"] or "{}")
            except (json.JSONDecodeError, RecursionError):
                summary = {}
            result.append(
                {
                    "id": row["id"],
                    "started_at": row["started_at"],
                    "finished_at": row["finished_at"],
                    "status": row["status"],
                    "summary": summary if isinstance(summary, dict) and _json_nesting_is_safe(summary) else {},
                }
            )
        return result

    def record_overhead_measurement(
        self,
        report: dict[str, Any],
        *,
        measured_at: datetime | None = None,
    ) -> str:
        """Persist numeric watcher overhead without storing process details."""

        fields = (
            "interval_seconds",
            "warmup_seconds",
            "sample_seconds",
            "startup_process_tree_cpu_percent",
            "process_tree_cpu_percent",
            "startup_rss_mb_peak",
            "rss_mb_mean",
            "rss_mb_peak",
            "startup_disk_read_mb",
            "startup_disk_write_mb",
            "disk_read_mb",
            "disk_write_mb",
        )
        try:
            values = [report[field] for field in fields]
        except KeyError as exc:
            raise ValueError(f"Overhead report is missing {exc.args[0]}") from exc
        measurement_id = str(uuid.uuid4())
        self.connection.execute(
            """
            INSERT INTO overhead_measurements
            (id, measured_at, interval_seconds, warmup_seconds, sample_seconds,
             startup_process_tree_cpu_percent, process_tree_cpu_percent,
             startup_rss_mb_peak, rss_mb_mean, rss_mb_peak,
             startup_disk_read_mb, startup_disk_write_mb, disk_read_mb, disk_write_mb)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                measurement_id,
                iso_datetime(measured_at or utc_now()),
                int(values[0]),
                float(values[1]),
                float(values[2]),
                float(values[3]),
                float(values[4]),
                float(values[5]),
                float(values[6]),
                float(values[7]),
                float(values[8]),
                float(values[9]),
                float(values[10]),
                float(values[11]),
            ),
        )
        self.connection.commit()
        return measurement_id

    def list_overhead_measurements(
        self,
        *,
        since: datetime | None = None,
        until: datetime | None = None,
        limit: int = 10_000,
    ) -> list[dict[str, Any]]:
        clauses: list[str] = []
        params: list[Any] = []
        if since is not None:
            clauses.append("measured_at >= ?")
            params.append(iso_datetime(since))
        if until is not None:
            clauses.append("measured_at <= ?")
            params.append(iso_datetime(until))
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        params.append(max(1, min(limit, 100_000)))
        rows = self.connection.execute(
            f"SELECT * FROM overhead_measurements {where} ORDER BY measured_at ASC LIMIT ?", params
        ).fetchall()
        return [dict(row) for row in rows]

    def prune_sensitive_symptom_details(
        self,
        *,
        retain_days: int = 30,
        as_of: datetime | None = None,
        scan_id: str | None = None,
    ) -> int:
        """Drop raw Event Log messages after the short evidence-retention window."""

        if retain_days < 1:
            raise ValueError("retain_days must be at least 1 day")
        cutoff = ensure_utc(as_of or utc_now()) - timedelta(days=retain_days)
        rows = self.connection.execute(
            "SELECT id, details_json FROM events WHERE kind = 'symptom' AND occurred_at < ?",
            (iso_datetime(cutoff),),
        ).fetchall()
        updates: list[tuple[str, str]] = []
        for row in rows:
            try:
                details = json.loads(row["details_json"] or "{}")
            except (json.JSONDecodeError, RecursionError):
                details = None
            if not isinstance(details, dict) or not _json_nesting_is_safe(details):
                # A malformed legacy detail document must not keep a raw
                # symptom message forever or make every future scan partial.
                updates.append((_canonical_json({"raw_message_retained": False}), row["id"]))
                continue
            if "message" not in details:
                continue
            details.pop("message", None)
            details["raw_message_retained"] = False
            updates.append(("{}".format(_canonical_json(details)), row["id"]))
        if updates:
            with self.connection:
                if scan_id is not None:
                    self._assert_scan_lease(scan_id)
                self.connection.executemany("UPDATE events SET details_json = ? WHERE id = ?", updates)
        return len(updates)

    def recent_incidents(self, limit: int = 10) -> list[dict[str, Any]]:
        return self.list_incidents(limit=max(1, min(limit, 100)))

    def source_status(self) -> list[dict[str, Any]]:
        sources = ("updates", "apps", "drivers", "services", "tasks", "startup", "devices")
        counts = {
            row["source"]: {"item_count": int(row["item_count"]), "last_seen_at": row["last_seen_at"]}
            for row in self.connection.execute(
                "SELECT source, COUNT(*) AS item_count, MAX(last_seen_at) AS last_seen_at FROM state_items GROUP BY source"
            ).fetchall()
        }
        labels = {
            "updates": "Windows updates",
            "apps": "Applications",
            "drivers": "Drivers",
            "services": "Services",
            "tasks": "Scheduled tasks",
            "startup": "Startup entries",
            "devices": "Devices",
        }
        result = []
        for source in sources:
            item = counts.get(source, {})
            initialized = self.get_meta(f"source:{source}:initialized") == "1"
            result.append(
                {
                    "source": source,
                    "label": labels[source],
                    "initialized": initialized,
                    "item_count": item.get("item_count", 0),
                    "last_seen_at": item.get("last_seen_at"),
                    "status": "capturing" if initialized else "waiting for baseline",
                }
            )
        return result

    def investigation_coverage(
        self,
        subsystem: str,
        *,
        since: datetime | None = None,
        until: datetime | None = None,
    ) -> dict[str, Any]:
        """Summarize collection gaps across the investigation's scan window."""

        clauses: list[str] = []
        params: list[Any] = []
        if until is not None:
            clauses.append("started_at <= ?")
            params.append(iso_datetime(until))
        if since is not None:
            clauses.append("(finished_at IS NULL OR finished_at >= ?)")
            params.append(iso_datetime(since))
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        scan_rows = self.connection.execute(
            f"SELECT status, summary_json FROM scans {where} ORDER BY started_at DESC",
            params,
        ).fetchall()
        if not scan_rows:
            return {
                "known": False,
                "limited": False,
                "reasons": [],
                "sources": [],
                "uninitialized_sources": [],
                "scan_count": 0,
                "provider_warning_count": 0,
                "scan_status_counts": {},
            }

        source_map = {
            "graphics": {"drivers", "devices", "updates"},
            "audio": {"drivers", "devices"},
            "network": {"drivers", "devices"},
            "bluetooth": {"drivers", "devices"},
            "driver": {"drivers", "devices"},
            "startup": {"services", "tasks", "startup"},
            "application": {"apps"},
            "windows-update": {"updates"},
            "device": {"devices", "drivers"},
            "general": {"updates", "apps", "drivers", "services", "tasks", "startup", "devices"},
        }
        statuses = {item["source"]: item for item in self.source_status()}
        expected = sorted(source_map.get(subsystem, source_map["general"]))
        uninitialized = [
            source for source in expected
            if not statuses.get(source, {}).get("initialized", False)
        ]
        status_counts: dict[str, int] = {}
        provider_warning_count = 0
        for row in scan_rows:
            status = str(row["status"])
            status_counts[status] = status_counts.get(status, 0) + 1
            summary = self._scan_summary(row["summary_json"])
            raw_warnings = summary.get("errors", [])
            if isinstance(raw_warnings, list):
                provider_warning_count += len(raw_warnings)
        reasons: list[str] = []
        impaired_counts = {
            status: status_counts.get(status, 0)
            for status in ("partial", "failed", "interrupted")
            if status_counts.get(status, 0)
        }
        if impaired_counts:
            descriptions = ", ".join(
                f"{count} {status}" + (" scan" if count == 1 else " scans")
                for status, count in sorted(impaired_counts.items())
            )
            reasons.append(f"The investigation window includes {descriptions}.")
        if uninitialized:
            reasons.append("Some relevant sources are still waiting for their first baseline.")
        if provider_warning_count:
            reasons.append(
                f"{provider_warning_count} provider warning"
                + (" was" if provider_warning_count == 1 else "s were")
                + " recorded in the investigation window."
            )
        return {
            "known": True,
            "limited": bool(reasons),
            "reasons": reasons,
            "sources": expected,
            "uninitialized_sources": uninitialized,
            "provider_warning_count": provider_warning_count,
            "scan_count": len(scan_rows),
            "scan_status_counts": dict(sorted(status_counts.items())),
        }

    def status(self, *, include_integrity: bool = False) -> dict[str, Any]:
        last_scan_row = self.connection.execute(
            "SELECT finished_at, status, summary_json FROM scans ORDER BY started_at DESC LIMIT 1"
        ).fetchone()
        last_scan = None
        if last_scan_row:
            summary = redact_value(self._scan_summary(last_scan_row["summary_json"]))
            last_scan = {
                "finished_at": last_scan_row["finished_at"],
                "status": last_scan_row["status"],
                "summary": summary,
            }
        journal = (
            self.journal_diagnostics()
            if include_integrity
            else self._journal_health_snapshot()
        )
        return {
            "events": self.count_events(),
            "changes": self.count_events("change"),
            "symptoms": self.count_events("symptom"),
            "incidents": len(self.recent_incidents(100)),
            "retention_days": self.retention_days(),
            "sources": self.source_status(),
            "last_scan": dict(last_scan) if last_scan else None,
            "schema": journal["schema"],
            "journal": journal,
        }
