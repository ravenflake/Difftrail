from __future__ import annotations

from collections import Counter
from datetime import datetime, timedelta
from typing import Any

from .assessment import NEUTRAL_ASSESSMENT
from .db import Database
from .runtime_health import runtime_health
from .models import ensure_utc, iso_datetime, utc_now
from .privacy import error_bucket, redact_public_text
from .public_data import FEEDBACK_REASONS_BY_OUTCOME, LEGACY_FEEDBACK_REASON, public_feedback_outcome


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
    except (TypeError, ValueError, OverflowError):
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
        public_feedback_outcome(incident["feedback"]["outcome"])
        for incident in incidents
        if public_feedback_outcome(incident["feedback"]["outcome"]) is not None
    )
    rank_counts: dict[str, Counter[str]] = {
        outcome: Counter() for outcome in sorted(outcomes)
    }
    reason_counts: Counter[str] = Counter()

    def rank_bucket(rank: int | None) -> str:
        if rank is None or rank < 1:
            return "not_ranked"
        if rank <= 3:
            return f"rank_{rank}"
        return "rank_4_plus"

    for incident in incidents:
        feedback = incident["feedback"]
        outcome = public_feedback_outcome(feedback["outcome"])
        if outcome is None:
            continue
        reason = feedback.get("reason")
        if isinstance(reason, str) and reason:
            safe_reasons = FEEDBACK_REASONS_BY_OUTCOME.get(outcome, frozenset()) | {
                LEGACY_FEEDBACK_REASON
            }
            reason_counts[reason if reason in safe_reasons else "invalid"] += 1
        rank = feedback.get("rank")
        if not isinstance(rank, int) or isinstance(rank, bool) or rank < 1:
            rank = None
            selected_event_id = feedback.get("event_id")
            for index, hypothesis in enumerate(incident["results"], start=1):
                event = hypothesis.get("event", {}) if isinstance(hypothesis, dict) else {}
                if event.get("id") == selected_event_id:
                    rank = index
                    break
        rank_counts.setdefault(outcome, Counter())[rank_bucket(rank)] += 1

    confirmed_total = outcomes["confirmed_cause"]
    useful_total = outcomes["useful_lead"]
    confirmed_top1 = rank_counts.get("confirmed_cause", Counter())["rank_1"]
    confirmed_top3 = sum(
        rank_counts.get("confirmed_cause", Counter())[f"rank_{rank}"] for rank in range(1, 4)
    )
    useful_top3 = sum(
        rank_counts.get("useful_lead", Counter())[f"rank_{rank}"] for rank in range(1, 4)
    )
    cause_outcomes = confirmed_total + outcomes["uncaptured_cause"]

    def public_rank_distribution(outcome: str) -> dict[str, int]:
        counts = rank_counts.get(outcome, Counter())
        return {
            "rank_1": counts["rank_1"],
            "rank_2": counts["rank_2"],
            "rank_3": counts["rank_3"],
            "rank_4_plus": counts["rank_4_plus"],
            "not_ranked": counts["not_ranked"],
        }

    return {
        "total": len(incidents),
        "with_feedback": sum(outcomes.values()),
        "outcomes": {
            outcome: outcomes[outcome]
            for outcome in (
                "confirmed_cause",
                "useful_lead",
                "irrelevant_lead",
                "uncaptured_cause",
                "unknown",
            )
        },
        "known_cause_capture_rate": _rate(confirmed_total, cause_outcomes),
        "confirmed_cause_top1_hits": confirmed_top1,
        "confirmed_cause_top1_rate": _rate(confirmed_top1, confirmed_total),
        "confirmed_cause_top3_hits": confirmed_top3,
        "confirmed_cause_top3_rate": _rate(confirmed_top3, confirmed_total),
        "useful_lead_top3_hits": useful_top3,
        "useful_lead_top3_rate": _rate(useful_top3, useful_total),
        "rank_distribution_by_outcome": {
            outcome: public_rank_distribution(outcome)
            for outcome in ("confirmed_cause", "useful_lead", "irrelevant_lead")
        },
        "reason_distribution": dict(sorted(reason_counts.items())),
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
        "runtime": runtime_health(database.path, start=start, end=end),
        "investigations": _investigation_metrics(incidents),
        "limits": [
            "This report measures collection behavior and user-labeled outcomes; it does not establish causality by itself.",
            "Confirmed-cause metrics include only outcomes explicitly verified by a user; Difftrail never infers confirmation from rank or timing.",
            "Useful and irrelevant leads measure investigation value separately from confirmed-cause rank.",
            "A longer window and multiple hosts are needed before treating overhead or ranking results as general guarantees.",
        ],
    }
    return report
