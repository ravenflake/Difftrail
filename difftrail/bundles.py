from __future__ import annotations

"""Portable, redacted diagnostic bundles.

Bundles are deliberately a one-way export format. They contain enough
normalized context for a human or support workflow to understand a local
incident, but never contain the SQLite file or raw collector payloads.
"""

import hashlib
import json
import math
import os
import re
import tempfile
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from . import __version__
from .assessment import NEUTRAL_ASSESSMENT
from .db import Database
from .models import ensure_utc, iso_datetime, parse_datetime, utc_now
from .privacy import error_bucket, redact_public_text
from .public_data import SAFE_CHANGE_FIELDS, public_detail_summary


BUNDLE_FORMAT = "difftrail-diagnostic-bundle"
BUNDLE_VERSION = 1
MAX_BUNDLE_ROWS = 100_000
MAX_BUNDLE_NESTING = 64
FORBIDDEN_KEYS = frozenset(
    {
        "message",
        "rawmessage",
        "raw_message",
        "process_id",
        "processid",
        "pid",
        "username",
        "user_name",
        "sqlite",
        "database_path",
        "connection_string",
        "command",
        "path",
        "start_name",
    }
)
_ABSOLUTE_WINDOWS_PATH = re.compile(r"(?i)(?:(?<![A-Za-z0-9])[a-z]:[\\/]|\\\\[^\\\s]+\\|(?<!:)//[^/\s]+/)")
_PROFILE_PATH = re.compile(r"(?i)(?:(?<![A-Za-z0-9])[a-z]:[\\/](?:Users|Documents and Settings)[\\/]|(?<!:)//[^/\s]+/Users/)")


def _safe_text(value: Any) -> str:
    """Redact profile data and remove remaining absolute Windows paths."""

    return redact_public_text(str(value))


def _safe_summary_value(value: Any) -> Any:
    if isinstance(value, str):
        return _safe_text(value)
    if isinstance(value, dict):
        return {str(key): _safe_summary_value(child) for key, child in value.items()}
    if isinstance(value, list):
        return [_safe_summary_value(child) for child in value]
    return value


def _safe_detail_summary(event: dict[str, Any]) -> dict[str, Any] | None:
    summary = public_detail_summary(event)
    if not summary:
        return None
    safe: dict[str, Any] = {
        key: _safe_summary_value(value)
        for key, value in summary.items()
        if key in {"application_name", "event_id", "log_name", "provider", "record_id", "changed_fields", "raw_message_retained"}
    }
    for section in ("before", "after"):
        values = summary.get(section)
        if isinstance(values, dict):
            selected = {
                key: _safe_summary_value(value)
                for key, value in values.items()
                if key in SAFE_CHANGE_FIELDS
            }
            if selected:
                safe[section] = selected
    return safe or None


def _canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)


def _safe_event(event: Any) -> dict[str, Any]:
    """Serialize an Event without trusting its stored details payload."""

    raw = event.as_dict() if hasattr(event, "as_dict") else dict(event)
    safe = {
        "id": _safe_text(raw.get("id", "")) if raw.get("id") is not None else None,
        "occurred_at": raw.get("occurred_at"),
        "kind": raw.get("kind"),
        "subsystem": _safe_text(raw.get("subsystem", "")),
        "action": _safe_text(raw.get("action", "")),
        "title": _safe_text(raw.get("title", "")),
        "entity": _safe_text(raw.get("entity", "")),
        "severity": _safe_text(raw.get("severity", "")),
        "source": _safe_text(raw.get("source", "")),
    }
    detail_summary = _safe_detail_summary(raw)
    if detail_summary:
        safe["detail_summary"] = detail_summary
    return safe


def _safe_hypothesis(hypothesis: Any) -> dict[str, Any]:
    if not isinstance(hypothesis, dict):
        return {}
    diagnostic = hypothesis.get("safe_diagnostic")
    if not isinstance(diagnostic, dict):
        diagnostic = {}
    result = {
        "score": hypothesis.get("score"),
        "confidence": hypothesis.get("confidence"),
        "next_action": _safe_text(hypothesis.get("next_action", "")),
        "safe_diagnostic": {
            "label": _safe_text(diagnostic.get("label", "")),
            "target": _safe_text(diagnostic.get("target", "")),
            "note": _safe_text(diagnostic.get("note", "")),
        },
        "evidence": [],
        "counter_evidence": [],
    }
    event = hypothesis.get("event")
    if isinstance(event, dict):
        result["event"] = _safe_event(event)
    for key in ("evidence", "counter_evidence"):
        evidence_items = hypothesis.get(key, [])
        if not isinstance(evidence_items, list):
            evidence_items = []
        result[key] = [
            {
                "signal": _safe_text(item.get("signal", "")),
                "strength": _safe_text(item.get("strength", "")),
                "explanation": _safe_text(item.get("explanation", "")),
                "event_id": item.get("event_id"),
            }
            for item in evidence_items
            if isinstance(item, dict)
        ]
    return result


def _safe_incident(incident: dict[str, Any]) -> dict[str, Any]:
    raw_reasons = incident.get("assessment_reasons", [])
    if not isinstance(raw_reasons, list):
        raw_reasons = []
    raw_coverage = incident.get("coverage")
    coverage = raw_coverage if isinstance(raw_coverage, dict) else {}
    coverage_reasons = coverage.get("reasons", [])
    if not isinstance(coverage_reasons, list):
        coverage_reasons = []
    uninitialized_sources = coverage.get("uninitialized_sources", [])
    if not isinstance(uninitialized_sources, list):
        uninitialized_sources = []
    raw_results = incident.get("results", [])
    if not isinstance(raw_results, list):
        raw_results = []
    feedback = incident.get("feedback")
    if not isinstance(feedback, dict):
        feedback = {}
    return {
        "id": incident.get("id"),
        "created_at": incident.get("created_at"),
        "description": _safe_text(incident.get("description", "")),
        "subsystem": _safe_text(incident.get("subsystem", "")),
        "onset_start": incident.get("onset_start"),
        "onset_end": incident.get("onset_end"),
        "lookback_days": incident.get("lookback_days"),
        "status": _safe_text(incident.get("status", "")),
        "assessment": _safe_text(incident.get("assessment", NEUTRAL_ASSESSMENT)),
        "assessment_reasons": [_safe_text(reason) for reason in raw_reasons],
        "coverage": {
            "known": bool(coverage.get("known", False)),
            "limited": bool(coverage.get("limited", False)),
            "reasons": [
                _safe_text(reason)
                for reason in coverage_reasons
            ],
            "uninitialized_sources": [
                _safe_text(source)
                for source in uninitialized_sources
            ],
            "provider_warning_count": max(0, int(coverage.get("provider_warning_count", 0) or 0)),
            "scan_count": max(0, int(coverage.get("scan_count", 0) or 0)),
        },
        "results": [_safe_hypothesis(item) for item in raw_results],
        "feedback": {
            "outcome": feedback.get("outcome"),
            "event_id": feedback.get("event_id"),
            "recorded_at": feedback.get("recorded_at"),
        },
    }


def _safe_scan(scan: dict[str, Any]) -> dict[str, Any]:
    summary = scan.get("summary") if isinstance(scan.get("summary"), dict) else {}
    errors = summary.get("errors", []) if isinstance(summary.get("errors", []), list) else []
    return {
        "id": scan.get("id"),
        "started_at": scan.get("started_at"),
        "finished_at": scan.get("finished_at"),
        "status": scan.get("status"),
        "summary": {
            "sources": summary.get("sources", 0),
            "state_events": summary.get("state_events", 0),
            "symptom_events": summary.get("symptom_events", 0),
            "error_count": len(errors),
            "error_buckets": sorted({error_bucket(error) for error in errors}),
        },
    }


def _safe_source(source: dict[str, Any]) -> dict[str, Any]:
    return {
        "source": _safe_text(source.get("source", "")),
        "label": _safe_text(source.get("label", "")),
        "initialized": bool(source.get("initialized", False)),
        "item_count": int(source.get("item_count", 0) or 0),
        "last_seen_at": source.get("last_seen_at"),
        "status": _safe_text(source.get("status", "")),
    }


def _safe_event_summary(summary: dict[str, Any]) -> dict[str, Any]:
    """Redact aggregate labels as well as the event values they summarize."""

    try:
        changes = max(0, int(summary.get("changes", 0) or 0))
    except (TypeError, ValueError, OverflowError):
        changes = 0
    try:
        symptoms = max(0, int(summary.get("symptoms", 0) or 0))
    except (TypeError, ValueError, OverflowError):
        symptoms = 0
    result: dict[str, Any] = {
        "changes": changes,
        "symptoms": symptoms,
    }
    for name in ("changes_by_source", "changes_by_subsystem", "symptoms_by_subsystem"):
        counts = summary.get(name)
        safe_counts: dict[str, int] = {}
        if isinstance(counts, dict):
            for key, value in counts.items():
                try:
                    count = max(0, int(value))
                except (TypeError, ValueError, OverflowError):
                    continue
                safe_key = _safe_text(key)
                safe_counts[safe_key] = safe_counts.get(safe_key, 0) + count
        result[name] = dict(sorted(safe_counts.items()))
    return result


def _period_for_export(
    database: Database,
    *,
    days: int,
    incident_id: str | None,
    as_of: datetime,
) -> tuple[datetime, datetime, dict[str, Any], list[dict[str, Any]]]:
    if days < 1 or days > 3650:
        raise ValueError("days must be between 1 and 3650")
    end = ensure_utc(as_of)
    if incident_id:
        incident = database.get_incident(incident_id)
        if incident is None:
            raise ValueError(f"Unknown incident: {incident_id}")
        start = parse_datetime(incident["onset_start"]) - timedelta(days=int(incident["lookback_days"]))
        end = parse_datetime(incident["onset_end"])
        return start, end, {"kind": "incident", "incident_id": incident_id}, [incident]
    start = end - timedelta(days=days)
    return start, end, {"kind": "journal"}, database.list_incidents(since=start, until=end, limit=MAX_BUNDLE_ROWS)


def export_bundle(
    database: Database,
    *,
    days: int = 30,
    incident_id: str | None = None,
    as_of: datetime | None = None,
) -> dict[str, Any]:
    """Build a portable redacted bundle without reading SQLite outside Database."""

    exported_at = ensure_utc(as_of or utc_now())
    start, end, scope, incidents = _period_for_export(
        database, days=days, incident_id=incident_id, as_of=exported_at
    )
    duration_days = max(1, math.ceil((end - start).total_seconds() / 86_400))
    event_summary = _safe_event_summary(database.event_summary(since=start, until=end))
    events = database.list_events(
        limit=MAX_BUNDLE_ROWS,
        ascending=True,
        since=start,
        until=end,
        maximum_limit=MAX_BUNDLE_ROWS,
    )
    scans = database.list_scans(since=start, until=end, limit=MAX_BUNDLE_ROWS)
    payload: dict[str, Any] = {
        "format": BUNDLE_FORMAT,
        "format_version": BUNDLE_VERSION,
        "application": {"name": "Difftrail", "version": __version__},
        "exported_at": iso_datetime(exported_at),
        "period": {"start": iso_datetime(start), "end": iso_datetime(end), "days": duration_days},
        "scope": scope,
        "journal": {
            "event_summary": event_summary,
            "events_truncated": len(events) < event_summary["changes"] + event_summary["symptoms"],
            "sources": [_safe_source(item) for item in database.source_status()],
            "scans": [_safe_scan(item) for item in scans],
            "events": [_safe_event(event) for event in events],
        },
        "investigations": [_safe_incident(incident) for incident in incidents],
        "health": {
            "validation": database.status()["journal"],
            "scan_statuses": sorted({str(scan.get("status", "")) for scan in scans}),
        },
        "privacy": {
            "mode": "redacted-export",
            "raw_messages": "excluded",
            "absolute_paths": "excluded",
            "usernames": "excluded",
            "process_ids": "excluded",
            "sqlite_database": "excluded",
            "note": "Only normalized event metadata, aggregate health, and safe detail summaries are included.",
        },
    }
    payload["integrity"] = {"sha256": _payload_digest(payload)}
    report = validate_bundle(payload)
    if not report["valid"]:
        raise ValueError("Generated bundle failed its privacy validation: " + "; ".join(report["errors"]))
    return payload


def _payload_digest(payload: dict[str, Any]) -> str:
    without_integrity = dict(payload)
    without_integrity.pop("integrity", None)
    return hashlib.sha256(_canonical_json(without_integrity).encode("utf-8")).hexdigest()


def validate_bundle(bundle: Any) -> dict[str, Any]:
    errors: list[str] = []
    if not isinstance(bundle, dict):
        return {"valid": False, "errors": ["Bundle root must be a JSON object"], "warnings": []}
    if bundle.get("format") != BUNDLE_FORMAT:
        errors.append("Unsupported bundle format")
    if bundle.get("format_version") != BUNDLE_VERSION:
        errors.append("Unsupported bundle version")
    for key in ("application", "exported_at", "period", "scope", "journal", "investigations", "privacy", "integrity"):
        if key not in bundle:
            errors.append(f"Missing required field: {key}")
    if not isinstance(bundle.get("application"), dict):
        errors.append("Application metadata must be an object")
    if not isinstance(bundle.get("period"), dict):
        errors.append("Period metadata must be an object")
    if not isinstance(bundle.get("scope"), dict):
        errors.append("Scope metadata must be an object")
    journal = bundle.get("journal")
    if not isinstance(journal, dict):
        errors.append("Journal must be an object")
    else:
        if not isinstance(journal.get("events"), list):
            errors.append("Journal events must be an array")
        if not isinstance(journal.get("scans"), list):
            errors.append("Journal scans must be an array")
        if not isinstance(journal.get("sources"), list):
            errors.append("Journal sources must be an array")
    if not isinstance(bundle.get("investigations"), list):
        errors.append("Investigations must be an array")
    if not isinstance(bundle.get("privacy"), dict):
        errors.append("Privacy metadata must be an object")
    if isinstance(bundle.get("integrity"), dict):
        expected = bundle["integrity"].get("sha256")
        try:
            actual = _payload_digest(bundle)
        except (RecursionError, TypeError, ValueError):
            errors.append("Bundle structure is too deeply nested or malformed")
        else:
            if expected != actual:
                errors.append("Bundle integrity digest does not match its contents")
    else:
        errors.append("Integrity metadata must be an object")

    def walk(value: Any, path: str = "$") -> None:
        too_deep = False
        stack: list[tuple[Any, str, int]] = [(value, path, 0)]
        while stack:
            current, current_path, depth = stack.pop()
            if depth > MAX_BUNDLE_NESTING:
                if not too_deep:
                    errors.append(f"Bundle nesting exceeds {MAX_BUNDLE_NESTING} levels")
                    too_deep = True
                continue
            if isinstance(current, dict):
                for key, child in current.items():
                    key_text = str(key)
                    normalized_key = str(key).casefold()
                    child_path = f"{current_path}.{_safe_text(key_text)}"
                    if normalized_key in FORBIDDEN_KEYS:
                        errors.append(f"Forbidden sensitive field at {child_path}")
                    if _PROFILE_PATH.search(key_text):
                        errors.append(f"User profile path detected in field name at {current_path}")
                    elif _ABSOLUTE_WINDOWS_PATH.search(key_text):
                        errors.append(f"Absolute Windows path detected in field name at {current_path}")
                    stack.append((child, child_path, depth + 1))
            elif isinstance(current, list):
                for index, child in enumerate(current):
                    stack.append((child, f"{current_path}[{index}]", depth + 1))
            elif isinstance(current, str):
                if _PROFILE_PATH.search(current):
                    errors.append(f"User profile path detected at {current_path}")
                elif _ABSOLUTE_WINDOWS_PATH.search(current):
                    errors.append(f"Absolute Windows path detected at {current_path}")

    walk(bundle)
    return {
        "valid": not errors,
        "errors": sorted(set(errors)),
        "warnings": [],
        "format": bundle.get("format"),
        "format_version": bundle.get("format_version"),
        "event_count": len((bundle.get("journal") or {}).get("events", [])) if isinstance(bundle.get("journal"), dict) else 0,
        "investigation_count": len(bundle.get("investigations", [])) if isinstance(bundle.get("investigations"), list) else 0,
    }


def read_bundle(path: str | Path) -> tuple[Any | None, dict[str, Any]]:
    """Read and validate a bundle without raising for user-facing errors."""

    bundle_path = Path(path)
    try:
        with bundle_path.open("r", encoding="utf-8") as handle:
            bundle = json.load(handle)
    except FileNotFoundError as exc:
        return None, {"valid": False, "errors": [f"Bundle file was not found: {bundle_path}"], "warnings": []}
    except (OSError, UnicodeDecodeError) as exc:
        return None, {"valid": False, "errors": [f"Bundle could not be read: {exc}"], "warnings": []}
    except (json.JSONDecodeError, RecursionError) as exc:
        return None, {"valid": False, "errors": [f"Bundle is not valid JSON: {exc}"], "warnings": []}
    return bundle, validate_bundle(bundle)


def load_bundle(path: str | Path) -> tuple[dict[str, Any], dict[str, Any]]:
    bundle, report = read_bundle(path)
    if bundle is None:
        raise ValueError(report["errors"][0])
    if not report["valid"]:
        raise ValueError("Bundle validation failed: " + "; ".join(report["errors"]))
    return bundle, report


def write_bundle(bundle: dict[str, Any], output: str | Path, *, database_path: Path | None = None) -> Path:
    output_path = Path(output)
    if output_path.name in {"", ".", ".."}:
        raise ValueError("Bundle output must be a file path")
    if database_path is not None:
        resolved_output = output_path.resolve()
        protected_paths = {
            database_path.resolve(),
            Path(f"{database_path}-wal").resolve(),
            Path(f"{database_path}-shm").resolve(),
        }
        if resolved_output in protected_paths:
            raise ValueError("Bundle output must not overwrite the live SQLite journal or its SQLite sidecars")
    report = validate_bundle(bundle)
    if not report["valid"]:
        raise ValueError("Bundle validation failed: " + "; ".join(report["errors"]))
    output_path.parent.mkdir(parents=True, exist_ok=True)
    encoded = json.dumps(bundle, ensure_ascii=False, indent=2) + "\n"
    temporary_name: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", dir=output_path.parent, prefix=f".{output_path.name}.", suffix=".tmp", delete=False
        ) as handle:
            temporary_name = handle.name
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_name, output_path)
    finally:
        if temporary_name:
            try:
                Path(temporary_name).unlink()
            except FileNotFoundError:
                pass
    return output_path


def bundle_filename(incident_id: str | None = None) -> str:
    if incident_id:
        safe_id = re.sub(r"[^A-Za-z0-9._-]+", "-", str(incident_id)).strip(".-")[:80]
        return f"difftrail-investigation-{safe_id or 'report'}-bundle.json"
    return "difftrail-diagnostic-bundle.json"
