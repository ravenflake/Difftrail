from __future__ import annotations

from collections import Counter
from datetime import datetime, timedelta
from typing import Any

from .assessment import NEUTRAL_ASSESSMENT
from .db import Database
from .models import ensure_utc, iso_datetime, utc_now
from .privacy import error_bucket, redact_public_text


MAX_VALIDATION_DAYS = 3650
def _rate(numerator: int, denominator: int) -> float | None:
    if denominator == 0:
        return None
    return round(numerator / denominator, 3)


def _error_bucket(error: object) -> str:
    return error_bucket(error)


def _safe_count(value: object) -> int:
    try:
        return max(0, int(value or 0))
    except (TypeError, ValueError):
        return 0


def _safe_label_counts(values: object) -> dict[str, int]:
    """Keep aggregate metric labels within the report's no-path contract."""

    result: dict[str, int] = {}
    if not isinstance(values, dict):
        return result
    for key, value in values.items():
        label = redact_public_text(str(key))
        result[label] = result.get(label, 0) + _safe_count(value)
    return dict(sorted(result.items()))


def _aggregate_overhead(rows: list[dict[str, Any]]) -> dict[str, Any]:
    if not rows:
        return {
            "status": "not recorded",
            "measurements": 0,
        }

    def mean(field: str) -> float:
        return round(sum(float(row[field]) for row in rows) / len(rows), 3)

    def maximum(field: str) -> float:
        return round(max(float(row[field]) for row in rows), 3)

    return {
        "status": "recorded",
        "measurements": len(rows),
        "first_measured_at": rows[0]["measured_at"],
        "last_measured_at": rows[-1]["measured_at"],
        "cpu_percent_mean": mean("process_tree_cpu_percent"),
        "cpu_percent_peak": maximum("process_tree_cpu_percent"),
        "rss_mb_mean": mean("rss_mb_mean"),
        "rss_mb_peak": maximum("rss_mb_peak"),
        "disk_read_mb_total": round(sum(float(row["disk_read_mb"]) for row in rows), 3),
        "disk_write_mb_total": round(sum(float(row["disk_write_mb"]) for row in rows), 3),
        "startup_cpu_percent_peak": maximum("startup_process_tree_cpu_percent"),
        "startup_rss_mb_peak": maximum("startup_rss_mb_peak"),
    }


def _investigation_metrics(incidents: list[dict[str, Any]]) -> dict[str, Any]:
    assessment_distribution = Counter(
        str(incident.get("assessment", NEUTRAL_ASSESSMENT)) for incident in incidents
    )
    outcomes = Counter(
        incident["feedback"]["outcome"]
        for incident in incidents
        if incident["feedback"]["outcome"] in {"correct", "incorrect", "unknown"}
    )
    correct_total = outcomes["correct"]
    top3_hits = 0
    rank_counts: Counter[str] = Counter()
    for incident in incidents:
        feedback = incident["feedback"]
        if feedback["outcome"] != "correct":
            continue
        selected_event_id = feedback["event_id"]
        rank: int | None = None
        for index, hypothesis in enumerate(incident["results"], start=1):
            event = hypothesis.get("event", {}) if isinstance(hypothesis, dict) else {}
            if event.get("id") == selected_event_id:
                rank = index
                break
        if rank is not None and rank <= 3:
            top3_hits += 1
            rank_counts[f"rank_{rank}"] += 1
        else:
            rank_counts["outside_top3"] += 1

    return {
        "total": len(incidents),
        "with_feedback": sum(outcomes.values()),
        "outcomes": {
            "correct": outcomes["correct"],
            "incorrect": outcomes["incorrect"],
            "unknown": outcomes["unknown"],
        },
        "correct_cause_top3_hits": top3_hits,
        "correct_cause_top3_rate": _rate(top3_hits, correct_total),
        "correct_cause_rank_distribution": {
            "rank_1": rank_counts["rank_1"],
            "rank_2": rank_counts["rank_2"],
            "rank_3": rank_counts["rank_3"],
            "outside_top3": rank_counts["outside_top3"],
        },
        "assessment_distribution": dict(sorted(assessment_distribution.items())),
    }


def build_host_validation_report(
    database: Database,
    *,
    days: int = 7,
    as_of: datetime | None = None,
) -> dict[str, Any]:
    """Build an aggregate, local-only report for real host validation.

    The report intentionally excludes event titles, descriptions, evidence,
    paths, raw messages, and process IDs. It measures collection health and
    user-labeled investigation outcomes without exporting machine history.
    """

    if days < 1 or days > MAX_VALIDATION_DAYS:
        raise ValueError(f"days must be between 1 and {MAX_VALIDATION_DAYS}")
    end = ensure_utc(as_of or utc_now())
    start = end - timedelta(days=days)
    scans = database.list_scans(since=start, until=end)
    journal = database.event_summary(since=start, until=end)
    status_counts = Counter(str(scan["status"]) for scan in scans)
    error_buckets: Counter[str] = Counter()
    reported_changes = 0
    reported_symptoms = 0
    sources_seen: list[int] = []
    quiet_scans = 0
    change_bearing_scans = 0
    symptom_bearing_scans = 0
    for scan in scans:
        summary = scan["summary"]
        reported_changes += _safe_count(summary.get("state_events"))
        reported_symptoms += _safe_count(summary.get("symptom_events"))
        sources_seen.append(_safe_count(summary.get("sources")))
        if _safe_count(summary.get("state_events")) == 0 and _safe_count(summary.get("symptom_events")) == 0:
            quiet_scans += 1
        if _safe_count(summary.get("state_events")) > 0:
            change_bearing_scans += 1
        if _safe_count(summary.get("symptom_events")) > 0:
            symptom_bearing_scans += 1
        for error in summary.get("errors", []) if isinstance(summary.get("errors", []), list) else []:
            error_buckets[_error_bucket(error)] += 1

    incidents = database.list_incidents(since=start, until=end)
    overhead = database.list_overhead_measurements(since=start, until=end)
    scan_count = len(scans)
    report = {
        "period": {
            "start": iso_datetime(start),
            "end": iso_datetime(end),
            "days": days,
        },
        "privacy": "aggregate local report; no event details, paths, descriptions, raw messages, or process IDs",
        "scans": {
            "total": scan_count,
            "by_status": dict(sorted(status_counts.items())),
            "quiet": quiet_scans,
            "quiet_rate": _rate(quiet_scans, scan_count),
            "with_changes": change_bearing_scans,
            "with_symptoms": symptom_bearing_scans,
            "reported_changes": reported_changes,
            "reported_symptoms": reported_symptoms,
            "provider_error_count": sum(error_buckets.values()),
            "error_buckets": dict(sorted(error_buckets.items())),
            "sources_per_scan_mean": round(sum(sources_seen) / len(sources_seen), 2) if sources_seen else None,
            "change_bearing_scan_rate": _rate(change_bearing_scans, scan_count),
        },
        "journal": {
            "changes": journal["changes"],
            "symptoms": journal["symptoms"],
            "changes_per_scan": round(journal["changes"] / scan_count, 2) if scan_count else None,
            "changes_per_day": round(journal["changes"] / days, 2),
            "changes_by_source": _safe_label_counts(journal["changes_by_source"]),
            "changes_by_subsystem": _safe_label_counts(journal["changes_by_subsystem"]),
            "symptoms_by_subsystem": _safe_label_counts(journal["symptoms_by_subsystem"]),
        },
        "overhead": _aggregate_overhead(overhead),
        "investigations": _investigation_metrics(incidents),
        "limits": [
            "This report measures collection behavior and user-labeled outcomes; it does not establish causality by itself.",
            "Top-three accuracy is calculated only for investigations explicitly labeled correct with an event ID.",
            "A longer window and multiple hosts are needed before treating overhead or ranking results as general guarantees.",
        ],
    }
    return report
