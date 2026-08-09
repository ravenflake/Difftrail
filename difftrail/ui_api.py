from __future__ import annotations

"""Small loopback-only JSON API for the Difftrail desktop interface.

The UI talks to this adapter instead of opening SQLite itself.  Keeping the
boundary here means redaction, deterministic ranking, and all writes remain
owned by the Python engine.  The server is intentionally dependency-free and
binds to loopback by default; it is not an internet-facing web service.
"""

import hmac
import json
import os
import sys
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse, urlsplit

from . import __version__
from .automation import (
    automation_snapshot,
    disable_watcher,
    enable_watcher,
    mark_notifications_read,
    run_automated_scan,
    update_automation_config,
)
from .bundles import bundle_filename, export_bundle, validate_bundle
from .correlation import infer_subsystem
from .db import Database
from .investigation import run_investigation
from .models import IncidentRequest, parse_datetime, utc_now
from .host_validation import build_host_validation_report
from .overhead import measure_watcher_overhead
from .assessment import NEUTRAL_ASSESSMENT
from .privacy import error_bucket, redact_text
from .public_data import public_detail_summary


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

ALLOWED_ORIGINS = frozenset(
    {"http://tauri.localhost", "http://127.0.0.1:5173", "http://localhost:5173"}
)
MAX_REQUEST_BODY_BYTES = 64 * 1024
MAX_BUNDLE_REQUEST_BODY_BYTES = 32 * 1024 * 1024
VALID_EVENT_KINDS = frozenset({"all", "change", "symptom"})
API_TOKEN_ENV = "DIFFTRAIL_API_TOKEN"


def _public_event(event: dict[str, Any]) -> dict[str, Any]:
    """Return UI-safe event metadata without raw detail payloads."""

    result = dict(event)
    detail_summary = public_detail_summary(result)
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
    result["description"] = redact_text(str(result.get("description", "")))
    raw_results = result.get("results", [])
    if not isinstance(raw_results, list):
        raw_results = []
    result["results"] = [_public_hypothesis(item) for item in raw_results if isinstance(item, dict)]
    result["assessment"] = str(result.get("assessment", NEUTRAL_ASSESSMENT))
    raw_reasons = result.get("assessment_reasons", [])
    if not isinstance(raw_reasons, list):
        raw_reasons = []
    result["assessment_reasons"] = [
        redact_text(str(reason)) for reason in raw_reasons
    ]
    result["coverage"] = result.get("coverage") if isinstance(result.get("coverage"), dict) else {}
    return result


def public_status(status: dict[str, Any]) -> dict[str, Any]:
    """Expose aggregate status without provider exception text."""

    result = dict(status)
    last_scan = status.get("last_scan")
    if isinstance(last_scan, dict):
        safe_last_scan = dict(last_scan)
        raw_summary = last_scan.get("summary")
        summary = raw_summary if isinstance(raw_summary, dict) else {}
        errors = summary.get("errors", [])
        if not isinstance(errors, list):
            errors = []
        safe_last_scan["summary"] = {
            key: summary.get(key)
            for key in ("scan_id", "status", "sources", "state_events", "symptom_events")
            if key in summary
        }
        safe_last_scan["summary"]["errors"] = []
        safe_last_scan["summary"]["error_count"] = len(errors)
        safe_last_scan["summary"]["error_buckets"] = sorted({error_bucket(error) for error in errors})
        result["last_scan"] = safe_last_scan
    return result


def _now_or_parse(value: str | None) -> datetime:
    return parse_datetime(value) if value else utc_now()


def build_bootstrap(database: Database, *, days: int = 7) -> dict[str, Any]:
    status = database.status()
    return {
        "version": __version__,
        "status": public_status(status),
        "events": [_public_event(event.as_dict()) for event in database.list_events(limit=120)],
        "incidents": [public_incident(item) for item in database.recent_incidents(limit=20)],
        "validation": build_host_validation_report(database, days=days),
        "automation": automation_snapshot(database),
    }


def create_investigation(database: Database, body: dict[str, Any]) -> dict[str, Any]:
    description = str(body.get("description", "")).strip()
    if not description:
        raise ValueError("Describe what went wrong before investigating")
    onset_value = body.get("onset")
    if onset_value is not None and not isinstance(onset_value, str):
        raise ValueError("onset must be an ISO timestamp string")
    onset_start = _now_or_parse(onset_value)
    onset_end = utc_now()
    raw_subsystem = body.get("subsystem")
    if raw_subsystem is not None and not isinstance(raw_subsystem, str):
        raise ValueError("subsystem must be a string")
    subsystem = str(raw_subsystem or infer_subsystem(description))
    raw_lookback = body.get("lookback_days", 7)
    if isinstance(raw_lookback, bool) or (
        isinstance(raw_lookback, float) and not raw_lookback.is_integer()
    ):
        raise ValueError("lookback_days must be an integer")
    try:
        lookback_days = int(raw_lookback)
    except (TypeError, ValueError) as exc:
        raise ValueError("lookback_days must be an integer") from exc
    request = IncidentRequest(description, onset_start, onset_end, subsystem, lookback_days)
    run = run_investigation(database, request)
    incident = run.incident
    summary = run.summary
    stored = database.get_incident(incident.id)
    if stored is None:  # pragma: no cover - the insert was just performed
        raise ValueError("The investigation could not be loaded after creation")
    summary["incident_id"] = incident.id
    summary["hypotheses"] = [_public_hypothesis(item) for item in summary["hypotheses"]]
    return {"summary": summary, "incident": public_incident(stored)}


def create_bundle(database: Database, body: dict[str, Any]) -> dict[str, Any]:
    raw_days = body.get("days", 30)
    if isinstance(raw_days, bool) or (isinstance(raw_days, float) and not raw_days.is_integer()):
        raise ValueError("days must be an integer")
    try:
        days = int(raw_days)
    except (TypeError, ValueError) as exc:
        raise ValueError("days must be an integer") from exc
    if days < 1 or days > 3650:
        raise ValueError("days must be between 1 and 3650")
    incident_id = body.get("incident_id")
    if incident_id is not None and not isinstance(incident_id, str):
        raise ValueError("incident_id must be a string")
    if incident_id is not None and not incident_id.strip():
        raise ValueError("incident_id must not be empty")
    bundle = export_bundle(database, days=days, incident_id=incident_id)
    return {"filename": bundle_filename(incident_id), "bundle": bundle}


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
        self.send_header("X-Content-Type-Options", "nosniff")
        origin = self.headers.get("Origin")
        if origin in ALLOWED_ORIGINS:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Access-Control-Allow-Headers", "Content-Type, X-Difftrail-Token")
            self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
            self.send_header("Vary", "Origin")
        self.end_headers()
        self.wfile.write(encoded)

    def _error(self, status: int, message: str) -> None:
        self._send(status, {"error": message})

    def _body(self, *, maximum_bytes: int = MAX_REQUEST_BODY_BYTES) -> dict[str, Any]:
        content_type = self.headers.get("Content-Type", "")
        if content_type and content_type.casefold().split(";", 1)[0].strip() != "application/json":
            raise ValueError("POST requests must use application/json")
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except (TypeError, ValueError) as exc:
            raise ValueError("Content-Length must be an integer") from exc
        if length < 0:
            raise ValueError("Content-Length must not be negative")
        if length > maximum_bytes:
            raise ValueError(f"Request body is too large (maximum {maximum_bytes} bytes)")
        try:
            payload = json.loads(self.rfile.read(length) or b"{}")
        except json.JSONDecodeError as exc:
            raise ValueError("Request body must be valid JSON") from exc
        if not isinstance(payload, dict):
            raise ValueError("Request body must be a JSON object")
        return payload

    def _query(self, allowed: set[str] | None = None) -> dict[str, str]:
        values = parse_qs(urlparse(self.path).query, keep_blank_values=True)
        if allowed is not None:
            unknown = sorted(set(values) - allowed)
            if unknown:
                raise ValueError(f"Unsupported query parameter: {unknown[0]}")
        result: dict[str, str] = {}
        for key, items in values.items():
            if len(items) != 1:
                raise ValueError(f"Query parameter must have exactly one non-empty value: {key}")
            if not items[0].strip():
                if key == "search":
                    continue
                raise ValueError(f"Query parameter must have exactly one non-empty value: {key}")
            result[key] = items[0]
        return result

    def _request_allowed(self, *, require_token: bool = True) -> bool:
        origin = self.headers.get("Origin")
        if origin and origin not in ALLOWED_ORIGINS:
            self._error(403, "Origin is not allowed")
            return False
        host = self.headers.get("Host")
        if not host:
            self._error(400, "Host header is required")
            return False
        try:
            parsed = urlsplit(f"//{host}")
            hostname = (parsed.hostname or "").casefold()
            port = parsed.port
        except ValueError:
            self._error(400, "Host header is invalid")
            return False
        if hostname not in {"127.0.0.1", "localhost", "::1"}:
            self._error(403, "The Difftrail API only accepts loopback hosts")
            return False
        if port is not None and port != self.server.server_address[1]:
            self._error(403, "Host port does not match the local API")
            return False
        if require_token and self.server.api_token:
            supplied_token = self.headers.get("X-Difftrail-Token", "")
            if not hmac.compare_digest(supplied_token, self.server.api_token):
                self._error(401, "A valid Difftrail API token is required")
                return False
        return True

    @staticmethod
    def _bounded_int(query: dict[str, str], name: str, default: int, minimum: int, maximum: int) -> int:
        raw = query.get(name, str(default))
        try:
            value = int(raw)
        except ValueError as exc:
            raise ValueError(f"Query parameter {name} must be an integer") from exc
        if value < minimum or value > maximum:
            raise ValueError(f"Query parameter {name} must be between {minimum} and {maximum}")
        return value

    def _with_database(self, callback):
        with Database(self.server.database_path) as database:
            return callback(database)

    def do_OPTIONS(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        # CORS preflight requests declare the custom token header but do not
        # carry its value. The subsequent request is still authenticated.
        if not self._request_allowed(require_token=False):
            return
        if self.headers.get("Origin") not in ALLOWED_ORIGINS:
            self._error(403, "Origin is not allowed")
            return
        self.send_response(204)
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        origin = self.headers.get("Origin")
        if origin in ALLOWED_ORIGINS:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Access-Control-Allow-Headers", "Content-Type, X-Difftrail-Token")
            self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
            self.send_header("Vary", "Origin")
        self.end_headers()

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        if not self._request_allowed():
            return
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"
        try:
            allowed_query = {
                "/api/bootstrap": {"days"},
                "/api/timeline": {"limit", "kind", "subsystem", "search"},
                "/api/health": {"days"},
            }.get(path, set())
            query = self._query(allowed_query)
            if path == "/api/bootstrap":
                days = self._bounded_int(query, "days", 7, 1, 3650)
                payload = self._with_database(lambda db: build_bootstrap(db, days=days))
            elif path == "/api/automation":
                payload = self._with_database(automation_snapshot)
            elif path == "/api/timeline":
                limit = self._bounded_int(query, "limit", 120, 1, 500)
                kind = query.get("kind", "all")
                if kind not in VALID_EVENT_KINDS:
                    raise ValueError("Query parameter kind must be all, change, or symptom")
                subsystem = query.get("subsystem", "all")
                if len(subsystem) > 64:
                    raise ValueError("Query parameter subsystem is too long")
                events = self._with_database(
                    lambda db: db.list_events(
                        limit=limit,
                        kind=kind,
                        subsystem=subsystem,
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
                days = self._bounded_int(query, "days", 7, 1, 3650)
                payload = self._with_database(
                    lambda db: {
                        "api_port": self.server.server_address[1],
                        "status": public_status(db.status()),
                        "validation": build_host_validation_report(db, days=days),
                    }
                )
            elif path == "/api/doctor":
                payload = self._with_database(lambda db: db.journal_diagnostics())
            else:
                self._error(404, "Difftrail UI endpoint not found")
                return
            self._send(200, payload)
        except (ValueError, OSError) as exc:
            self._error(400, str(exc))

    def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        if not self._request_allowed():
            return
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"
        try:
            body = self._body(
                maximum_bytes=(
                    MAX_BUNDLE_REQUEST_BODY_BYTES
                    if path == "/api/validate-bundle"
                    else MAX_REQUEST_BODY_BYTES
                )
            )
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
            elif path == "/api/export-bundle":
                payload = self._with_database(lambda db: create_bundle(db, body))
            elif path == "/api/validate-bundle":
                if "bundle" not in body:
                    raise ValueError("bundle is required")
                payload = validate_bundle(body["bundle"])
            elif path.startswith("/api/incidents/") and path.endswith("/feedback"):
                incident_id = path.split("/")[-2]
                event_id = body.get("event_id")
                if event_id is not None and not isinstance(event_id, str):
                    raise ValueError("event_id must be a string")

                def record(database: Database) -> dict[str, Any]:
                    return database.record_incident_feedback(
                        incident_id,
                        str(body.get("outcome", "unknown")),
                        event_id=event_id,
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

    def __init__(
        self,
        address: tuple[str, int],
        database_path: Path,
        *,
        api_token: str | None = None,
    ):
        if api_token is not None and len(api_token) < 32:
            raise ValueError("The Difftrail API token must contain at least 32 characters")
        self.database_path = database_path
        self.api_token = api_token
        super().__init__(address, UiRequestHandler)


def serve(
    database_path: Path,
    *,
    host: str = "127.0.0.1",
    port: int = 45917,
    api_token: str | None = None,
) -> None:
    if host not in {"127.0.0.1", "localhost", "::1"}:
        raise ValueError("The Difftrail UI server only supports loopback hosts")
    token = api_token if api_token is not None else os.environ.get(API_TOKEN_ENV)
    server = UiServer((host, port), database_path, api_token=token)
    actual_port = server.server_address[1]
    print(f"Difftrail UI API ready on http://{host}:{actual_port}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nDifftrail UI API stopped.", file=sys.stderr)
    finally:
        server.server_close()
