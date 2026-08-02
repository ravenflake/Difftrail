from __future__ import annotations

import hashlib
import json
import sqlite3
import uuid
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Iterable

from .models import Event, Incident, IncidentRequest, SnapshotItem, ensure_utc, iso_datetime, parse_datetime, utc_now
from .privacy import extract_safe_application_name, redact_text, redact_value


DEFAULT_RETENTION_DAYS = 30


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


REMOVED_SUBSYSTEMS = {
    "updates": "windows-update",
    "apps": "application",
    "drivers": "driver",
    "services": "startup",
    "tasks": "startup",
    "startup": "startup",
    "devices": "device",
}


SCHEMA = """
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


def _canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)


def _hash(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


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
    return normalized


def _comparison_payload(source: str, payload: dict[str, Any]) -> dict[str, Any]:
    safe_payload = _comparison_value(source, "", redact_value(payload))
    ignored = IGNORED_SNAPSHOT_FIELDS.get(source, frozenset())
    return {key: value for key, value in safe_payload.items() if key not in ignored}


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
        self.path = Path(path) if str(path) != ":memory:" else Path(":memory:")
        database_target = ":memory:" if str(path) == ":memory:" else str(self.path)
        if database_target != ":memory:":
            self.path.parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(database_target, timeout=30, check_same_thread=False)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute("PRAGMA foreign_keys = ON")
        if database_target != ":memory:":
            self.connection.execute("PRAGMA journal_mode = WAL")
        self.connection.execute("PRAGMA synchronous = NORMAL")
        self.connection.executescript(SCHEMA)
        self.connection.commit()
        self._ensure_schema_compatibility()

    def _ensure_schema_compatibility(self) -> None:
        """Add additive columns needed by journals created by older MVP builds."""

        columns = {
            row[1]
            for row in self.connection.execute("PRAGMA table_info(incidents)").fetchall()
        }
        migrations = {
            "feedback_outcome": "TEXT",
            "feedback_event_id": "TEXT",
            "feedback_at": "TEXT",
        }
        missing = [
            (name, definition)
            for name, definition in migrations.items()
            if name not in columns
        ]
        if missing:
            with self.connection:
                for name, definition in missing:
                    self.connection.execute(f"ALTER TABLE incidents ADD COLUMN {name} {definition}")
        self._backfill_safe_application_entities()

    def _backfill_safe_application_entities(self) -> None:
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
            details = json.loads(row["details_json"] or "{}")
            application_name = details.get("application_name") or extract_safe_application_name(str(details.get("message", "")))
            if not application_name:
                continue
            details["application_name"] = application_name
            updates.append((application_name, _canonical_json(details), row["id"]))
        with self.connection:
            if updates:
                self.connection.executemany("UPDATE events SET entity = ?, details_json = ? WHERE id = ?", updates)
            self.connection.execute(
                "INSERT INTO meta(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                ("migration:safe-application-entities", "1"),
            )

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
        self.connection.execute(
            "INSERT INTO meta(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, value),
        )
        self.connection.commit()

    def record_automation_action(
        self,
        event_id: str,
        action: str,
        *,
        incident_id: str | None = None,
        created_at: datetime | None = None,
    ) -> bool:
        """Record an automation action once so retries remain idempotent."""

        before_changes = self.connection.total_changes
        self.connection.execute(
            """
            INSERT OR IGNORE INTO automation_actions
            (id, event_id, action, created_at, incident_id)
            VALUES (?, ?, ?, ?, ?)
            """,
            (str(uuid.uuid4()), event_id, action, iso_datetime(created_at or utc_now()), incident_id),
        )
        self.connection.commit()
        return self.connection.total_changes > before_changes

    def create_automation_notification(
        self,
        *,
        kind: str,
        title: str,
        body: str,
        event_id: str | None = None,
        incident_id: str | None = None,
        created_at: datetime | None = None,
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
        safe_title = redact_text(event.title)
        safe_entity = redact_text(event.entity)
        safe_details = redact_value(event.details)
        fingerprint_payload = {
            "occurred_at": iso_datetime(event.occurred_at),
            "kind": event.kind,
            "subsystem": event.subsystem,
            "action": event.action,
            "title": safe_title,
            "entity": safe_entity,
            "source": event.source,
            "details": safe_details,
        }
        fingerprint = event.fingerprint or _hash(fingerprint_payload)
        event_id = event.event_id or fingerprint
        return (
            Event(
                occurred_at=ensure_utc(event.occurred_at),
                kind=event.kind,
                subsystem=event.subsystem,
                action=event.action,
                title=safe_title,
                entity=safe_entity,
                severity=event.severity,
                source=event.source,
                details=safe_details,
                event_id=event_id,
                fingerprint=fingerprint,
            ),
            event_id,
            fingerprint,
        )

    def save_events(self, events: Iterable[Event]) -> int:
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
        if not rows:
            return 0
        before_changes = self.connection.total_changes
        with self.connection:
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

    @staticmethod
    def _row_to_event(row: sqlite3.Row) -> Event:
        details = json.loads(row["details_json"] or "{}")
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
        ascending: bool = False,
    ) -> list[Event]:
        clauses: list[str] = []
        params: list[Any] = []
        if kind and kind != "all":
            clauses.append("kind = ?")
            params.append(kind)
        if subsystem and subsystem != "all":
            clauses.append("subsystem = ?")
            params.append(subsystem)
        if search and search.strip():
            needle = f"%{search.strip()}%"
            clauses.append("(title LIKE ? OR entity LIKE ? OR details_json LIKE ?)")
            params.extend([needle, needle, needle])
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        order = "ASC" if ascending else "DESC"
        params.append(max(1, min(limit, 10_000)))
        rows = self.connection.execute(
            f"SELECT * FROM events {where} ORDER BY occurred_at {order} LIMIT ?", params
        ).fetchall()
        return [self._row_to_event(row) for row in rows]

    def count_events(self, kind: str | None = None) -> int:
        if kind and kind != "all":
            row = self.connection.execute("SELECT COUNT(*) FROM events WHERE kind = ?", (kind,)).fetchone()
        else:
            row = self.connection.execute("SELECT COUNT(*) FROM events").fetchone()
        return int(row[0])

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
        previous = {row["item_key"]: json.loads(row["payload_json"]) for row in previous_rows}
        initialized_key = f"source:{source}:initialized"
        initialized = self.get_meta(initialized_key) == "1"

        generated: list[Event] = []
        matched_previous_keys: set[str] = set()
        if not initialized and baseline_if_empty:
            self._replace_state(source, current, now)
            self.set_meta(initialized_key, "1")
            return generated

        for key, item in current.items():
            previous_key = key if key in previous else self._legacy_app_key(key, previous, matched_previous_keys, source)
            old_payload = previous.get(previous_key) if previous_key is not None else None
            safe_payload = redact_value(item.payload)
            comparison_payload = _comparison_payload(source, item.payload)
            if old_payload is None:
                action = item.action_on_add
            else:
                old_comparison_payload = _comparison_payload(source, old_payload)
                if _is_bits_trigger_oscillation(source, old_payload, safe_payload):
                    old_comparison_payload = dict(old_comparison_payload)
                    comparison_payload = dict(comparison_payload)
                    old_comparison_payload.pop("start_mode", None)
                    comparison_payload.pop("start_mode", None)
                changed = _hash(old_comparison_payload) != _hash(comparison_payload)
                if changed:
                    action = item.action_on_update
                else:
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

        self._replace_state(source, current, now)
        self.set_meta(initialized_key, "1")
        self.save_events(generated)
        return generated

    @staticmethod
    def _legacy_app_key(
        current_key: str,
        previous: dict[str, dict[str, Any]],
        matched_previous_keys: set[str],
        source: str,
    ) -> str | None:
        """Match app state written before app keys were made registry-stable."""

        if source != "apps":
            return None
        candidates = [
            key
            for key in previous
            if key not in matched_previous_keys and key.split("|", 1)[0] == current_key
        ]
        return candidates[0] if len(candidates) == 1 else None

    def _replace_state(self, source: str, current: dict[str, SnapshotItem], now: datetime) -> None:
        timestamp = iso_datetime(now)
        with self.connection:
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
        scan_id = str(uuid.uuid4())
        self.connection.execute(
            "INSERT INTO scans(id, started_at, status) VALUES (?, ?, ?)",
            (scan_id, iso_datetime(started_at), "running"),
        )
        self.connection.commit()
        return scan_id

    def finish_scan(self, scan_id: str, finished_at: datetime, status: str, summary: dict[str, Any]) -> None:
        self.connection.execute(
            "UPDATE scans SET finished_at = ?, status = ?, summary_json = ? WHERE id = ?",
            (iso_datetime(finished_at), status, _canonical_json(summary), scan_id),
        )
        self.connection.commit()

    def create_incident(
        self,
        request: IncidentRequest,
        *,
        created_at: datetime | None = None,
        status: str = "investigating",
    ) -> Incident:
        if not status.strip():
            raise ValueError("Incident status must not be empty")
        incident = Incident(id=str(uuid.uuid4()), created_at=created_at or utc_now(), request=request, status=status)
        self.connection.execute(
            """
            INSERT INTO incidents
            (id, created_at, description, subsystem, onset_start, onset_end, lookback_days, status, result_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
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
            ),
        )
        self.connection.commit()
        return incident

    def update_incident_results(self, incident_id: str, results: list[dict[str, Any]], status: str = "investigating") -> None:
        self.connection.execute(
            "UPDATE incidents SET status = ?, result_json = ? WHERE id = ?",
            (status, _canonical_json(redact_value(results)), incident_id),
        )
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

    @staticmethod
    def _incident_row(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "id": row["id"],
            "created_at": row["created_at"],
            "description": row["description"],
            "subsystem": row["subsystem"],
            "onset_start": row["onset_start"],
            "onset_end": row["onset_end"],
            "lookback_days": row["lookback_days"],
            "status": row["status"],
            "results": json.loads(row["result_json"] or "[]"),
            "feedback": {
                "outcome": row["feedback_outcome"],
                "event_id": row["feedback_event_id"],
                "recorded_at": row["feedback_at"],
            },
        }

    def get_incident(self, incident_id: str) -> dict[str, Any] | None:
        row = self.connection.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,)).fetchone()
        return self._incident_row(row) if row else None

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
            except json.JSONDecodeError:
                summary = {}
            result.append(
                {
                    "id": row["id"],
                    "started_at": row["started_at"],
                    "finished_at": row["finished_at"],
                    "status": row["status"],
                    "summary": summary if isinstance(summary, dict) else {},
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

    def prune_sensitive_symptom_details(self, *, retain_days: int = 30, as_of: datetime | None = None) -> int:
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
            details = json.loads(row["details_json"] or "{}")
            if "message" not in details:
                continue
            details.pop("message", None)
            details["raw_message_retained"] = False
            updates.append(("{}".format(_canonical_json(details)), row["id"]))
        if updates:
            with self.connection:
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

    def status(self) -> dict[str, Any]:
        last_scan_row = self.connection.execute(
            "SELECT finished_at, status, summary_json FROM scans ORDER BY started_at DESC LIMIT 1"
        ).fetchone()
        last_scan = None
        if last_scan_row:
            try:
                summary = json.loads(last_scan_row["summary_json"] or "{}")
            except json.JSONDecodeError:
                summary = {}
            last_scan = {
                "finished_at": last_scan_row["finished_at"],
                "status": last_scan_row["status"],
                "summary": summary,
            }
        return {
            "events": self.count_events(),
            "changes": self.count_events("change"),
            "symptoms": self.count_events("symptom"),
            "incidents": len(self.recent_incidents(100)),
            "retention_days": self.retention_days(),
            "sources": self.source_status(),
            "last_scan": dict(last_scan) if last_scan else None,
        }
