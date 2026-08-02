from __future__ import annotations

"""Small loopback-only JSON API for the Difftrail desktop interface.

The UI talks to this adapter instead of opening SQLite itself.  Keeping the
boundary here means redaction, deterministic ranking, and all writes remain
owned by the Python engine.  The server is intentionally dependency-free and
binds to loopback by default; it is not an internet-facing web service.
"""

import json
import sys
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

from . import __version__
from .automation import (
    automation_snapshot,
    disable_watcher,
    enable_watcher,
    mark_notifications_read,
    run_automated_scan,
    update_automation_config,
)
from .correlation import infer_subsystem, investigation_summary, rank_candidates
from .db import Database
from .models import IncidentRequest, parse_datetime, utc_now
from .host_validation import build_host_validation_report
from .overhead import measure_watcher_overhead
from .privacy import extract_safe_application_name


SOURCE_LABELS = {
    "updates": "Windows updates",
    "apps": "Applications",
    "drivers": "Drivers",
    "services": "Services",
    "tasks": "Scheduled tasks",
    "startup": "Startup entries",
    "devices": "Devices",
    "event-log": "Windows signal",
    "eventlog": "Windows signal",
    "fixture:eventlog": "Windows signal",
    "windows-reliability": "Windows signal",
}

ALLOWED_ORIGINS = frozenset({"http://tauri.localhost", "http://127.0.0.1:5173"})
MAX_REQUEST_BODY_BYTES = 64 * 1024
SAFE_CHANGE_FIELDS = frozenset({"display_name", "state", "start_mode", "start_name", "version", "driver_date", "manufacturer", "class", "status"})
SAFE_EVENT_FIELDS = frozenset({"event_id", "log_name", "provider", "record_id", "application_name"})


def _safe_detail_value(value: Any) -> str | int | float | bool | None:
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return None


def _public_detail_summary(event: dict[str, Any]) -> dict[str, Any] | None:
    """Expose parsed, non-sensitive event context without raw messages/paths."""

    details = event.get("details")
    if not isinstance(details, dict):
        return None
    summary: dict[str, Any] = {}
    before = details.get("before") if isinstance(details.get("before"), dict) else None
    after = details.get("after") if isinstance(details.get("after"), dict) else None
    if before is not None or after is not None:
        old = before or {}
        new = after or {}
        changed_fields = sorted(
            key for key in set(old) | set(new)
            if key in SAFE_CHANGE_FIELDS and old.get(key) != new.get(key)
        )
        if changed_fields:
            summary["changed_fields"] = changed_fields
        for label, values in (("before", old), ("after", new)):
            selected = {
                key: safe_value
                for key, value in values.items()
                if key in SAFE_CHANGE_FIELDS
                and (safe_value := _safe_detail_value(value)) is not None
            }
            if selected:
                summary[label] = selected
    for key in SAFE_EVENT_FIELDS:
        value = _safe_detail_value(details.get(key))
        if value is not None:
            summary[key] = value
    if "application_name" not in summary and details.get("message"):
        application_name = extract_safe_application_name(str(details["message"]))
        if application_name:
            summary["application_name"] = application_name
    if "message" in details:
        summary["raw_message_retained"] = bool(details.get("message"))
    elif details.get("raw_message_retained") is False:
        summary["raw_message_retained"] = False
    return summary or None


def _public_event(event: dict[str, Any]) -> dict[str, Any]:
    """Return UI-safe event metadata without raw detail payloads."""

    result = dict(event)
    detail_summary = _public_detail_summary(result)
    result.pop("details", None)
    if detail_summary:
        result["detail_summary"] = detail_summary
    result["source_label"] = SOURCE_LABELS.get(result.get("source", ""), result.get("source", "Unknown").replace("-", " "))
    return result


def _public_hypothesis(hypothesis: dict[str, Any]) -> dict[str, Any]:
    result = dict(hypothesis)
    if isinstance(result.get("event"), dict):
        result["event"] = _public_event(result["event"])
    result["evidence"] = [dict(item) for item in result.get("evidence", [])]
    result["counter_evidence"] = [dict(item) for item in result.get("counter_evidence", [])]
    return result


def public_incident(incident: dict[str, Any]) -> dict[str, Any]:
    result = dict(incident)
    result["results"] = [_public_hypothesis(item) for item in result.get("results", [])]
    return result


def _now_or_parse(value: str | None) -> datetime:
    return parse_datetime(value) if value else utc_now()


def build_bootstrap(database: Database, *, days: int = 7) -> dict[str, Any]:
    status = database.status()
    return {
        "version": __version__,
        "status": status,
        "events": [_public_event(event.as_dict()) for event in database.list_events(limit=120)],
        "incidents": [public_incident(item) for item in database.recent_incidents(limit=20)],
        "validation": build_host_validation_report(database, days=days),
        "automation": automation_snapshot(database),
    }


def create_investigation(database: Database, body: dict[str, Any]) -> dict[str, Any]:
    description = str(body.get("description", "")).strip()
    if not description:
        raise ValueError("Describe what went wrong before investigating")
    onset_start = _now_or_parse(body.get("onset"))
    onset_end = utc_now()
    subsystem = str(body.get("subsystem") or infer_subsystem(description))
    lookback_days = int(body.get("lookback_days", 7))
    request = IncidentRequest(description, onset_start, onset_end, subsystem, lookback_days)
    incident = database.create_incident(request)
    events = database.list_events(limit=10_000, ascending=True)
    hypotheses = rank_candidates(events, request)
    summary = investigation_summary(request, hypotheses)
    database.update_incident_results(incident.id, summary["hypotheses"])
    stored = database.get_incident(incident.id)
    if stored is None:  # pragma: no cover - the insert was just performed
        raise ValueError("The investigation could not be loaded after creation")
    summary["incident_id"] = incident.id
    summary["hypotheses"] = [_public_hypothesis(item) for item in summary["hypotheses"]]
    return {"summary": summary, "incident": public_incident(stored)}


def record_overhead(database: Database) -> dict[str, Any]:
    """Record a short local watcher-footprint sample for the health view."""

    report = measure_watcher_overhead(interval_seconds=15, warmup_seconds=2, sample_seconds=5)
    measurement_id = database.record_overhead_measurement(report)
    public_report = dict(report)
    public_report.pop("process_id", None)
    return {"measurement_id": measurement_id, "report": public_report}


class UiRequestHandler(BaseHTTPRequestHandler):
    server: "UiServer"

    def log_message(self, format: str, *args: Any) -> None:
        # The desktop shell should stay quiet.  Errors are returned as JSON.
        return

    def _send(self, status: int, payload: dict[str, Any] | list[Any]) -> None:
        encoded = json.dumps(payload, ensure_ascii=False, default=str).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.send_header("Cache-Control", "no-store")
        origin = self.headers.get("Origin")
        if origin in ALLOWED_ORIGINS:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Access-Control-Allow-Headers", "Content-Type")
            self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
            self.send_header("Vary", "Origin")
        self.end_headers()
        self.wfile.write(encoded)

    def _error(self, status: int, message: str) -> None:
        self._send(status, {"error": message})

    def _body(self) -> dict[str, Any]:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except (TypeError, ValueError) as exc:
            raise ValueError("Content-Length must be an integer") from exc
        if length < 0:
            raise ValueError("Content-Length must not be negative")
        if length > MAX_REQUEST_BODY_BYTES:
            raise ValueError(f"Request body is too large (maximum {MAX_REQUEST_BODY_BYTES} bytes)")
        try:
            payload = json.loads(self.rfile.read(length) or b"{}")
        except json.JSONDecodeError as exc:
            raise ValueError("Request body must be valid JSON") from exc
        if not isinstance(payload, dict):
            raise ValueError("Request body must be a JSON object")
        return payload

    def _query(self) -> dict[str, str]:
        values = parse_qs(urlparse(self.path).query)
        return {key: items[-1] for key, items in values.items() if items}

    def _with_database(self, callback):
        with Database(self.server.database_path) as database:
            return callback(database)

    def do_OPTIONS(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        if self.headers.get("Origin") not in ALLOWED_ORIGINS:
            self._error(403, "Origin is not allowed")
            return
        self._send(204, {})

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"
        query = self._query()
        try:
            if path == "/api/bootstrap":
                days = max(1, min(int(query.get("days", "7")), 3650))
                payload = self._with_database(lambda db: build_bootstrap(db, days=days))
            elif path == "/api/automation":
                payload = self._with_database(automation_snapshot)
            elif path == "/api/timeline":
                limit = max(1, min(int(query.get("limit", "120")), 500))
                events = self._with_database(
                    lambda db: db.list_events(
                        limit=limit,
                        kind=query.get("kind", "all"),
                        subsystem=query.get("subsystem", "all"),
                        search=query.get("search"),
                    )
                )
                payload = [_public_event(event.as_dict()) for event in events]
            elif path == "/api/incidents":
                incidents = self._with_database(lambda db: db.recent_incidents(limit=100))
                payload = [public_incident(item) for item in incidents]
            elif path.startswith("/api/incidents/"):
                incident_id = path.rsplit("/", 1)[-1]
                incident = self._with_database(lambda db: db.get_incident(incident_id))
                if incident is None:
                    self._error(404, "Investigation not found")
                    return
                payload = public_incident(incident)
            elif path == "/api/health":
                days = max(1, min(int(query.get("days", "7")), 3650))
                payload = self._with_database(
                    lambda db: {
                        "api_port": self.server.server_address[1],
                        "status": db.status(),
                        "validation": build_host_validation_report(db, days=days),
                    }
                )
            else:
                self._error(404, "Difftrail UI endpoint not found")
                return
            self._send(200, payload)
        except (ValueError, OSError) as exc:
            self._error(400, str(exc))

    def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"
        try:
            body = self._body()
            if path == "/api/scan":
                result = self._with_database(run_automated_scan)
                payload = {"scan": result.as_dict()}
            elif path == "/api/automation/config":
                def update_config(database: Database) -> dict[str, Any]:
                    update_automation_config(database, body)
                    return {"automation": automation_snapshot(database)}

                payload = self._with_database(update_config)
            elif path == "/api/automation/watcher":
                action = str(body.get("action", "")).strip().casefold()

                def update_watcher(database: Database) -> dict[str, Any]:
                    scan = None
                    if action == "enable":
                        enable_watcher(database, body.get("interval_seconds"))
                    elif action == "disable":
                        disable_watcher(database)
                    elif action == "run":
                        scan = run_automated_scan(database)
                    else:
                        raise ValueError("Watcher action must be enable, disable, or run")
                    result: dict[str, Any] = {"automation": automation_snapshot(database)}
                    if scan is not None:
                        result["scan"] = scan.as_dict()
                    return result

                payload = self._with_database(update_watcher)
            elif path == "/api/automation/notifications/read":
                ids = body.get("ids")
                if ids is not None and not isinstance(ids, list):
                    raise ValueError("Notification ids must be an array")
                payload = self._with_database(lambda db: {"automation": mark_notifications_read(db, ids)})
            elif path == "/api/overhead":
                payload = self._with_database(record_overhead)
            elif path == "/api/investigations":
                payload = self._with_database(lambda db: create_investigation(db, body))
            elif path.startswith("/api/incidents/") and path.endswith("/feedback"):
                incident_id = path.split("/")[-2]

                def record(database: Database) -> dict[str, Any]:
                    return database.record_incident_feedback(
                        incident_id,
                        str(body.get("outcome", "unknown")),
                        event_id=body.get("event_id"),
                    )

                payload = {"incident": public_incident(self._with_database(record))}
            else:
                self._error(404, "Difftrail UI endpoint not found")
                return
            self._send(200, payload)
        except (RuntimeError, ValueError, OSError) as exc:
            self._error(400, str(exc))


class UiServer(ThreadingHTTPServer):
    allow_reuse_address = True

    def __init__(self, address: tuple[str, int], database_path: Path):
        self.database_path = database_path
        super().__init__(address, UiRequestHandler)


def serve(database_path: Path, *, host: str = "127.0.0.1", port: int = 45917) -> None:
    if host not in {"127.0.0.1", "localhost", "::1"}:
        raise ValueError("The Difftrail UI server only supports loopback hosts")
    server = UiServer((host, port), database_path)
    actual_port = server.server_address[1]
    print(f"Difftrail UI API ready on http://{host}:{actual_port}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nDifftrail UI API stopped.", file=sys.stderr)
    finally:
        server.server_close()
