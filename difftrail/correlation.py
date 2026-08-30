from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass, replace
from datetime import timedelta
from typing import Any, Iterable

from .assessment import ASSESSMENT_STATES, NEUTRAL_ASSESSMENT
from .models import Event, IncidentRequest, ensure_utc, iso_datetime
from .service_identity import is_per_user_service_payload


SUBSYSTEM_KEYWORDS: dict[str, tuple[str, ...]] = {
    "graphics": ("gpu", "graphics", "display", "screen", "monitor", "nvidia", "amd", "game", "dxgi"),
    "audio": ("audio", "sound", "speaker", "microphone", "headset", "bluetooth audio"),
    "network": ("network", "internet", "wifi", "wi-fi", "ethernet", "dns", "proxy", "connection"),
    "bluetooth": ("bluetooth",),
    "driver": ("driver", "drivers"),
    "startup": ("startup", "service", "services", "scheduled task", "background"),
    "windows-update": ("windows update", "hotfix", "patch", "update"),
    "application": ("app", "application", "program", "software", "launch", "crash"),
    "device": ("device", "usb", "peripheral", "keyboard", "mouse", "printer"),
}


COMPATIBLE_SUBSYSTEMS: dict[str, set[str]] = {
    "graphics": {"graphics", "driver", "device"},
    "audio": {"audio", "driver", "device"},
    "network": {"network", "driver", "device"},
    "bluetooth": {"bluetooth", "network", "driver", "device"},
    "driver": {"driver", "graphics", "audio", "network", "bluetooth", "device"},
    "startup": {"startup", "application", "driver", "windows-update"},
    "windows-update": {"windows-update", "driver", "application", "startup"},
    "application": {"application", "driver", "startup", "windows-update"},
    "device": {"device", "driver", "audio", "network", "bluetooth", "graphics"},
    "general": {"general", "application", "driver", "startup", "windows-update", "device", "graphics", "audio", "network", "bluetooth"},
}


SOURCE_PRIORITY: dict[str, int] = {
    "updates": 5,
    "drivers": 5,
    "devices": 4,
    "services": 3,
    "tasks": 3,
    "startup": 3,
    "apps": 1,
}

# Explicit context is a bounded bonus on top of the established evidence
# model. It is deliberately smaller than any two of temporal proximity,
# subsystem relevance, and baseline evidence, so a name match cannot become
# a strongly supported lead by itself.
ENTITY_RELEVANCE_BOOST = 0.12
SUSPECTED_CHANGE_BOOST = 0.06
ENTITY_SCOPED_MISMATCH_PENALTY = 0.12
AMBIGUITY_SCORE_MARGIN = 0.025
ONSET_SYMPTOM_TOLERANCE = timedelta(hours=6)
_ENTITY_SCOPED_CHANGE_SOURCES = frozenset({"apps", "services", "startup", "tasks"})
_NON_SPECIFIC_SYMPTOM_ACTIONS = frozenset(
    {"failure", "reliability_event", "unexpected_restart", "unexpected_shutdown"}
)
_ENTITY_SPECIFIC_SYMPTOM_ACTIONS = frozenset({"crash", "hang"})
_GENERIC_IDENTITY_WORDS = frozenset(
    {
        "app",
        "application",
        "changed",
        "change",
        "crash",
        "crashed",
        "detected",
        "executable",
        "hang",
        "helper",
        "install",
        "installed",
        "installer",
        "process",
        "removed",
        "service",
        "setup",
        "stopped",
        "update",
        "updated",
        "updater",
    }
)
_IDENTITY_DETAIL_FIELDS = frozenset(
    {
        "application_name",
        "device_name",
        "display_name",
        "executable",
        "key",
        "name",
        "package_id",
        "process_name",
        "service_name",
    }
)

@dataclass(frozen=True)
class Evidence:
    signal: str
    strength: str
    explanation: str
    event_id: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "signal": self.signal,
            "strength": self.strength,
            "explanation": self.explanation,
            "event_id": self.event_id,
        }


@dataclass(frozen=True)
class Hypothesis:
    event: Event
    score: float
    confidence: str
    evidence: tuple[Evidence, ...]
    counter_evidence: tuple[Evidence, ...]
    next_action: str
    safe_diagnostic: dict[str, str]
    tie_count: int = 1

    def as_dict(self) -> dict[str, Any]:
        return {
            "event": self.event.as_dict(),
            "score": round(self.score, 3),
            "confidence": self.confidence,
            "evidence": [item.as_dict() for item in self.evidence],
            "counter_evidence": [item.as_dict() for item in self.counter_evidence],
            "next_action": self.next_action,
            "safe_diagnostic": self.safe_diagnostic,
            "tie_count": self.tie_count,
        }

    def public_dict(self) -> dict[str, Any]:
        """Serialize a lead without exposing internal ordering weights."""

        result = self.as_dict()
        result.pop("score", None)
        result.pop("confidence", None)
        result["support_level"] = {
            "High": "strong",
            "Medium": "moderate",
            "Low": "weak",
        }.get(self.confidence, "weak")
        return result


@dataclass(frozen=True)
class InvestigationAssessment:
    state: str
    reasons: tuple[str, ...] = ()
    coverage: dict[str, Any] | None = None

    def __post_init__(self) -> None:
        if self.state not in ASSESSMENT_STATES:
            raise ValueError(f"Unsupported investigation assessment: {self.state}")

    def as_dict(self) -> dict[str, Any]:
        return {
            "state": self.state,
            "reasons": list(self.reasons),
            "coverage": self.coverage or {},
        }


def infer_subsystem(description: str) -> str:
    text = description.casefold()
    scores = {
        subsystem: sum(1 for keyword in keywords if re.search(rf"\b{re.escape(keyword)}\b", text))
        for subsystem, keywords in SUBSYSTEM_KEYWORDS.items()
    }
    best = max(scores, key=scores.get)
    return best if scores[best] else "general"


def _relevance(incident_subsystem: str, event_subsystem: str) -> tuple[float, str]:
    if incident_subsystem == "general":
        return 0.45, "The incident area is broad, so subsystem relevance is limited."
    if event_subsystem == incident_subsystem:
        return 1.0, f"The change and problem are both in the {incident_subsystem} area."
    if event_subsystem in COMPATIBLE_SUBSYSTEMS.get(incident_subsystem, set()):
        return 0.72, f"A {event_subsystem} change can affect the {incident_subsystem} area."
    return 0.12, f"The change is in {event_subsystem}, which is not a close match for {incident_subsystem}."


def _subsystem_matches(incident_subsystem: str, symptom_subsystem: str) -> bool:
    """Keep symptom support inside the user's selected problem area."""

    return (
        incident_subsystem == "general"
        or symptom_subsystem == incident_subsystem
        or symptom_subsystem in COMPATIBLE_SUBSYSTEMS.get(incident_subsystem, set())
    )


def _temporal_score(gap_hours: float) -> float:
    if gap_hours < 0:
        return 0.0
    return math.exp(-gap_hours / 72.0)


def _identity_key(value: object) -> str | None:
    """Return a conservative identity key; never use broad fuzzy matching."""

    text = str(value or "").strip().strip("\"'")
    if not text:
        return None
    # Paths are identities only through their basename. Splitting camel case
    # lets DiffTrailUpdater.exe normalize like "Difftrail update service".
    text = re.split(r"[\\/]", text)[-1]
    text = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", " ", text)
    text = re.sub(r"\.(?:exe|com|bat|cmd|msi)$", "", text, flags=re.IGNORECASE)
    tokens = [
        token
        for token in re.findall(r"[a-z0-9]+", text.casefold())
        if token not in _GENERIC_IDENTITY_WORDS
    ]
    return "".join(tokens) or None


def _event_identity_keys(event: Event) -> set[str]:
    values: list[object] = [event.entity, event.title]
    for key, value in event.details.items():
        if key in _IDENTITY_DETAIL_FIELDS:
            values.append(value)
        elif key in {"before", "after"} and isinstance(value, dict):
            values.extend(
                nested_value
                for nested_key, nested_value in value.items()
                if nested_key in _IDENTITY_DETAIL_FIELDS
            )
    return {key for value in values if (key := _identity_key(value))}


def _context_matches_event(value: str | None, event: Event) -> bool:
    key = _identity_key(value)
    return bool(key and key in _event_identity_keys(event))


def _context_identity_relation(value: str | None, event: Event) -> str:
    """Classify explicit identity evidence without treating missing data as a mismatch."""

    context_key = _identity_key(value)
    event_keys = _event_identity_keys(event)
    if not context_key or not event_keys:
        return "unknown"
    return "match" if context_key in event_keys else "mismatch"


def _is_direct_application_change(event: Event) -> bool:
    """Return whether an event represents an installed-application change."""

    return event.source == "apps"


def _is_entity_scoped_change(event: Event) -> bool:
    """Return whether a change belongs to an identifiable app or persistence entry."""

    return event.source in _ENTITY_SCOPED_CHANGE_SOURCES


def _entity_scoped_change_label(event: Event) -> str:
    return {
        "apps": "installed-application",
        "services": "service",
        "startup": "startup-entry",
        "tasks": "scheduled-task",
    }.get(event.source, "entity-scoped")


def _event_symptom_identity_relation(event: Event, symptom: Event) -> str:
    """Compare known identities without interpreting missing identity as a mismatch."""

    event_keys = _event_identity_keys(event)
    symptom_keys = _event_identity_keys(symptom)
    if not event_keys or not symptom_keys:
        return "unknown"
    return "match" if event_keys.intersection(symptom_keys) else "mismatch"


def _symptom_link_quality(
    request: IncidentRequest,
    event: Event,
    symptom: Event,
) -> str | None:
    """Return ``strong`` or ``possible`` for a compatible symptom record.

    This is intentionally conservative. A generic restart or anonymous failure
    can provide timeline context, but it cannot strongly corroborate every
    nearby change. Known identity mismatches exclude entity-scoped changes so
    one application's crash is not shared across unrelated app/service leads.
    """

    if not _subsystem_matches(request.subsystem, event.subsystem):
        return None
    if not _subsystem_matches(request.subsystem, symptom.subsystem):
        return None

    generic_symptom = symptom.action in _NON_SPECIFIC_SYMPTOM_ACTIONS
    entity_relation = _context_identity_relation(request.affected_entity, event)
    symptom_context_relation = _context_identity_relation(request.affected_entity, symptom)
    event_symptom_relation = _event_symptom_identity_relation(event, symptom)

    if request.affected_entity:
        if symptom_context_relation == "mismatch":
            return None
        if _is_entity_scoped_change(event) and entity_relation == "mismatch":
            return None
    elif (
        _is_entity_scoped_change(event)
        and symptom.action in _ENTITY_SPECIFIC_SYMPTOM_ACTIONS
        and event_symptom_relation == "mismatch"
    ):
        return None

    # General reliability records describe a machine-level outcome, not the
    # component that produced it. They remain useful timeline context only.
    if request.subsystem == "general" or generic_symptom:
        return "possible"

    exact_area = event.subsystem == symptom.subsystem
    if _is_entity_scoped_change(event):
        if request.affected_entity:
            exact_identity = (
                entity_relation == "match" and symptom_context_relation == "match"
            )
        else:
            exact_identity = event_symptom_relation == "match"
        return "strong" if exact_area and exact_identity else "possible"

    # Drivers, devices, and updates are system-scoped. Exact area plus a
    # specific symptom is meaningful corroboration without pretending that an
    # application identity should match a driver or update identity.
    return "strong" if exact_area else "possible"


def _strength(value: float) -> str:
    if value >= 0.78:
        return "strong"
    if value >= 0.5:
        return "moderate"
    return "weak"


def _next_action(event: Event) -> str:
    if event.subsystem in {"graphics", "audio", "network", "bluetooth", "driver"} or event.source == "drivers":
        return "In Device Manager, compare the current device status, driver provider, version, and date with this journaled change. Do not roll back a driver based on rank alone."
    if event.subsystem == "windows-update" or event.source == "updates":
        return "In Windows Update history, confirm the install time and update identifier, then compare them with the problem onset. Do not uninstall an update based on timing alone."
    if event.source == "services":
        if _is_per_user_service_event(event):
            return "In Services, compare the per-user service's base name, status, and executable path. A changed session suffix alone is not evidence of a new installation."
        return "In Services, compare the service status, startup type, and executable path with the journaled before/after values. Do not change it based on rank alone."
    if event.source == "tasks":
        return "In Task Scheduler, inspect the task's author, trigger, action, and last-run result, then compare them with the journaled change."
    if event.source == "startup" or event.subsystem == "startup":
        return "In Startup apps, inspect the entry's publisher and current state, then compare them with the journaled change."
    if event.subsystem == "application" or event.source == "apps":
        return "Confirm the application's current version and update time, then reproduce the problem once while noting whether the same symptom returns."
    if event.subsystem == "device":
        return "In Device Manager, compare the device status and associated driver with the journaled change before taking action."
    return "Open the relevant Windows management surface and compare its current state with this journaled change before taking action."


def _safe_diagnostic(event: Event) -> dict[str, str]:
    """Return a read-only Windows surface the user may open manually."""

    if event.subsystem in {"graphics", "audio", "network", "bluetooth", "device", "driver"} or event.source == "drivers":
        return {"label": "Device Manager", "target": "devmgmt.msc", "note": "Opening this surface does not change system state."}
    if event.subsystem == "windows-update" or event.source == "updates":
        return {"label": "Windows Update history", "target": "ms-settings:windowsupdate-history", "note": "Opening this surface does not change system state."}
    if event.source == "tasks":
        return {"label": "Task Scheduler", "target": "taskschd.msc", "note": "Opening this surface does not change system state."}
    if event.source == "services":
        return {
            "label": "Services",
            "target": "services.msc",
            "note": "Review configuration only; do not change a service based on timing alone.",
        }
    if event.source == "startup" or event.subsystem == "startup":
        return {
            "label": "Startup apps",
            "target": "ms-settings:startupapps",
            "note": "Opening this surface does not change system state.",
        }
    if event.subsystem == "application" or event.source == "apps":
        return {"label": "Installed apps", "target": "ms-settings:appsfeatures", "note": "Opening this surface does not change system state."}
    return {"label": "Event Viewer", "target": "eventvwr.msc", "note": "Opening this surface does not change system state."}


def _is_per_user_service_event(event: Event) -> bool:
    if event.source != "services" or not isinstance(event.details, dict):
        return False
    return any(
        is_per_user_service_payload(event.details.get(label))
        for label in ("before", "after")
    )


def rank_candidates(
    events: Iterable[Event],
    request: IncidentRequest,
    *,
    limit: int = 8,
) -> list[Hypothesis]:
    """Rank changes with deterministic, inspectable evidence signals.

    Scores are only ordering weights, not probabilities. ``confidence``
    describes the specificity of the recorded support for reviewing a lead;
    it never describes confidence that the change caused the problem.
    """

    onset_start = ensure_utc(request.onset_start)
    onset_end = ensure_utc(request.onset_end)
    lookback_start = onset_start - timedelta(days=request.lookback_days)
    symptom_window_start = max(lookback_start, onset_start - ONSET_SYMPTOM_TOLERANCE)
    symptom_window_end = min(onset_end, onset_start + ONSET_SYMPTOM_TOLERANCE)
    all_events = sorted(events, key=lambda item: ensure_utc(item.occurred_at))
    changes = [
        event
        for event in all_events
        if event.kind == "change"
        and lookback_start <= ensure_utc(event.occurred_at) <= onset_start
        and event.details.get("refresh_kind") != "per_user_service_instances"
    ]
    symptoms = [event for event in all_events if event.kind == "symptom"]
    source_counts = Counter(event.source for event in changes)
    results: list[Hypothesis] = []

    for event in changes:
        event_time = ensure_utc(event.occurred_at)
        gap_hours = max(0.0, (onset_start - event_time).total_seconds() / 3600)
        temporal = _temporal_score(gap_hours)
        relevance, relevance_text = _relevance(request.subsystem, event.subsystem)
        entity_relation = _context_identity_relation(request.affected_entity, event)
        entity_match = entity_relation == "match"
        entity_scoped_mismatch = (
            _is_entity_scoped_change(event) and entity_relation == "mismatch"
        )
        suspected_change_match = _context_matches_event(request.suspected_change, event)
        supporting_links = [
            (symptom, quality)
            for symptom in symptoms
            if event_time <= ensure_utc(symptom.occurred_at) <= symptom_window_end
            and symptom_window_start <= ensure_utc(symptom.occurred_at)
            if (quality := _symptom_link_quality(request, event, symptom)) is not None
        ]
        supporting = [symptom for symptom, _quality in supporting_links]
        strong_support = [
            symptom for symptom, quality in supporting_links if quality == "strong"
        ]
        prior_symptoms = [
            symptom
            for symptom in symptoms
            if lookback_start <= ensure_utc(symptom.occurred_at) < event_time
            and _symptom_link_quality(request, event, symptom) is not None
        ]
        earlier_onset_symptoms = [
            symptom
            for symptom in symptoms
            if event_time <= ensure_utc(symptom.occurred_at) < symptom_window_start
            and _symptom_link_quality(request, event, symptom) is not None
        ]
        identity_mismatched_symptoms = [
            symptom
            for symptom in symptoms
            if event_time <= ensure_utc(symptom.occurred_at) <= symptom_window_end
            and symptom_window_start <= ensure_utc(symptom.occurred_at)
            and _is_entity_scoped_change(event)
            and symptom.action in _ENTITY_SPECIFIC_SYMPTOM_ACTIONS
            and _event_symptom_identity_relation(event, symptom) == "mismatch"
            and _subsystem_matches(request.subsystem, symptom.subsystem)
        ]
        if strong_support and not prior_symptoms and not earlier_onset_symptoms:
            baseline = 0.9
        elif supporting and not prior_symptoms and not earlier_onset_symptoms:
            baseline = 0.65
        elif supporting:
            baseline = 0.5
        else:
            baseline = 0.15
        rarity = 1.0 if source_counts[event.source] == 1 else max(0.35, 1.0 / source_counts[event.source])
        score = 0.35 * temporal + 0.35 * relevance + 0.2 * baseline + 0.1 * rarity
        if entity_match:
            score += ENTITY_RELEVANCE_BOOST
        if suspected_change_match:
            score += SUSPECTED_CHANGE_BOOST

        evidence: list[Evidence] = [
            Evidence(
                "temporal proximity",
                _strength(temporal),
                f"This change was recorded {gap_hours:.1f} hours before the selected onset. Timing determines rank but does not establish a connection.",
                event.event_id,
            ),
            Evidence("subsystem relevance", _strength(relevance), relevance_text, event.event_id),
        ]
        if request.affected_entity and entity_match:
            evidence.append(
                Evidence(
                    "entity relevance",
                    "strong",
                    "This change matches the affected entity supplied for the evidence review.",
                    event.event_id,
                )
            )
        if request.suspected_change and suspected_change_match:
            evidence.append(
                Evidence(
                    "suspected change",
                    "moderate",
                    "This event matches the optional recent change supplied by the user. User suspicion affects ordering only.",
                    event.event_id,
                )
            )
        if supporting:
            first_symptom = strong_support[0] if strong_support else supporting[0]
            symptom_gap_hours = max(
                0.0,
                (ensure_utc(first_symptom.occurred_at) - event_time).total_seconds() / 3600,
            )
            support_kind = "specific" if strong_support else "broad or unidentified"
            evidence.append(
                Evidence(
                    "symptom timing",
                    "strong" if strong_support and not prior_symptoms and not earlier_onset_symptoms else "moderate",
                    f"{len(supporting)} compatible symptom record{'' if len(supporting) == 1 else 's'} appeared near the reported onset; the first was {symptom_gap_hours:.1f} hours after this change was recorded. The match is {support_kind} and does not prove causality.",
                    first_symptom.event_id,
                )
            )
        if source_counts[event.source] == 1:
            evidence.append(
                Evidence(
                    "source frequency",
                    "moderate",
                    "This is the only change from its source in the selected lookback window. That helps separate it from bulk churn but does not connect it to the problem.",
                    event.event_id,
                )
            )

        counter: list[Evidence] = []
        if not supporting:
            counter.append(
                Evidence(
                    "no symptom corroboration",
                    "strong",
                    "No compatible symptom record was captured near the reported onset. This lead is ranked from change timing and category only.",
                    event.event_id,
                )
            )
        elif not strong_support:
            counter.append(
                Evidence(
                    "limited symptom specificity",
                    "moderate",
                    "The symptom record is broad, anonymous, or only indirectly related to this change, so it cannot strongly corroborate the lead.",
                    supporting[0].event_id,
                )
            )
        if entity_scoped_mismatch:
            change_label = _entity_scoped_change_label(event)
            counter.append(
                Evidence(
                    "entity mismatch",
                    "strong",
                    f"This {change_label} change belongs to a different known entity than the affected entity, so the symptom record does not corroborate it.",
                    event.event_id,
                )
            )
            score -= ENTITY_SCOPED_MISMATCH_PENALTY
        elif identity_mismatched_symptoms:
            counter.append(
                Evidence(
                    "symptom identity mismatch",
                    "strong",
                    "A nearby crash or hang names a different known entity, so that symptom was not used to corroborate this lead.",
                    identity_mismatched_symptoms[0].event_id,
                )
            )
        if _is_per_user_service_event(event):
            counter.append(
                Evidence(
                    "per-user service identity",
                    "moderate",
                    "The suffixed service name identifies a Windows per-user instance; its session identity can change without a new persistence installation.",
                    event.event_id,
                )
            )
            score -= 0.2
        if prior_symptoms:
            counter.append(
                Evidence(
                    "symptom predates change",
                    "moderate",
                    f"{len(prior_symptoms)} compatible symptom record{'' if len(prior_symptoms) == 1 else 's'} existed before this change. That weakens the timing-based link.",
                    prior_symptoms[0].event_id,
                )
            )
            score -= 0.12
        if earlier_onset_symptoms:
            counter.append(
                Evidence(
                    "symptom predates reported onset",
                    "moderate",
                    f"{len(earlier_onset_symptoms)} compatible symptom record{'' if len(earlier_onset_symptoms) == 1 else 's'} appeared well before the selected onset. Recheck the onset time before relying on this sequence.",
                    earlier_onset_symptoms[0].event_id,
                )
            )
            score -= 0.08
        if request.subsystem == "general":
            counter.append(
                Evidence(
                    "broad problem area",
                    "moderate",
                    "The problem area is General, so subsystem matching cannot distinguish this lead from many unrelated kinds of change.",
                    event.event_id,
                )
            )
        score = max(0.0, min(1.0, score))
        if not supporting:
            confidence = "Low"
        elif score >= 0.67 and strong_support and not counter:
            confidence = "High"
        elif score >= 0.43:
            confidence = "Medium"
        else:
            confidence = "Low"
        results.append(
            Hypothesis(
                event,
                score,
                confidence,
                tuple(evidence),
                tuple(counter),
                _next_action(event),
                _safe_diagnostic(event),
            )
        )

    results.sort(
        key=lambda item: (
            any(
                evidence.signal in {"entity mismatch", "symptom identity mismatch"}
                for evidence in item.counter_evidence
            ),
            -item.score,
            -SOURCE_PRIORITY.get(item.event.source, 0),
            ensure_utc(item.event.occurred_at),
            item.event.event_id or "",
        ),
        reverse=False,
    )
    normalized: list[Hypothesis] = []
    for item in results:
        tie_count = sum(
            abs(other.score - item.score) <= AMBIGUITY_SCORE_MARGIN
            for other in results
        )
        confidence = "Medium" if tie_count >= 2 and item.confidence == "High" else item.confidence
        normalized.append(replace(item, confidence=confidence, tie_count=tie_count))
    return normalized[: max(1, min(limit, 50))]


def assess_investigation(
    request: IncidentRequest,
    hypotheses: Iterable[Hypothesis],
    events: Iterable[Event],
    *,
    coverage: dict[str, Any] | None = None,
) -> InvestigationAssessment:
    """Give the investigation an honest conclusion state.

    A ranked change is only a review lead. Only a uniquely ranked lead with
    specific symptom support receives ``candidate_found``; broad matching,
    counter-evidence, ambiguity, and incomplete collection remain inconclusive.
    """

    onset_start = ensure_utc(request.onset_start)
    lookback_start = onset_start - timedelta(days=request.lookback_days)
    changes = [
        event
        for event in events
        if event.kind == "change"
        and lookback_start <= ensure_utc(event.occurred_at) <= onset_start
    ]
    ranked = list(hypotheses)
    normalized_coverage = coverage if isinstance(coverage, dict) else {}
    coverage_unknown = bool(
        isinstance(coverage, dict)
        and (
            normalized_coverage.get("known") is False
            or (
                "scan_count" in normalized_coverage
                and int(normalized_coverage.get("scan_count", 0) or 0) == 0
            )
        )
    )
    coverage_limited = bool(normalized_coverage.get("limited")) or coverage_unknown
    coverage_reasons = normalized_coverage.get("reasons", [])
    if not isinstance(coverage_reasons, list):
        coverage_reasons = []
    reasons: list[str] = [
        str(reason)
        for reason in coverage_reasons
        if str(reason).strip()
    ]
    if coverage_unknown:
        reasons.append(
            "No completed scan covers this evidence window, so absence of recorded changes or symptoms is not meaningful."
        )
    bulk_refreshes = [
        event for event in changes
        if event.details.get("refresh_kind") == "per_user_service_instances"
    ]
    if bulk_refreshes:
        reasons.append(
            "A bulk Windows per-user service refresh was excluded from ranked leads because its suffixed instances changed together."
        )

    if not changes:
        reasons.append("No journaled changes were recorded during the selected lookback window before onset.")
        state = "limited_coverage" if coverage_limited else "no_recent_changes"
    elif not ranked:
        if not bulk_refreshes:
            reasons.append("Changes were recorded, but none matched the reported subsystem closely enough to rank.")
        state = "limited_coverage" if coverage_limited else "insufficient_evidence"
    else:
        lead = ranked[0]
        application_changes = [event for event in changes if _is_direct_application_change(event)]
        if (
            request.affected_entity
            and application_changes
            and not any(
                _context_identity_relation(request.affected_entity, event) == "match"
                for event in application_changes
            )
            and any(
                _context_identity_relation(request.affected_entity, event) == "mismatch"
                for event in application_changes
            )
        ):
            reasons.append(
                f"No recent installed-application change matching {request.affected_entity} was recorded."
            )
        if lead.confidence == "Low":
            reasons.append(
                "The top-ranked change has only weak or non-specific support; review it as timeline context, not an answer."
            )
        elif lead.confidence == "Medium":
            reasons.append(
                "The top-ranked change has some compatible evidence, but not enough specific support for a strong lead."
            )
        if lead.counter_evidence:
            reasons.append(
                "The top-ranked change also has limitations that weaken the apparent link."
            )
        if lead.tie_count >= 2:
            reasons.append(
                f"{lead.tie_count} changes are tied by the fixed ranking rules, so no single lead is uniquely supported."
            )
        if request.subsystem == "general":
            reasons.append(
                "The reported problem area is broad; choose a more specific area when possible to reduce unrelated leads."
            )
        conclusive_lead = lead.confidence == "High" and lead.tie_count == 1
        state = (
            "limited_coverage"
            if coverage_limited
            else "candidate_found"
            if conclusive_lead
            else "insufficient_evidence"
        )

    # Preserve deterministic order while avoiding duplicate explanations.
    unique_reasons = tuple(dict.fromkeys(reason.strip() for reason in reasons if reason.strip()))
    return InvestigationAssessment(state, unique_reasons, normalized_coverage)


def investigation_summary(
    request: IncidentRequest,
    hypotheses: Iterable[Hypothesis],
    *,
    assessment: InvestigationAssessment | None = None,
) -> dict[str, Any]:
    ranked = list(hypotheses)
    return {
        "description": request.description,
        "subsystem": request.subsystem,
        "onset_start": iso_datetime(request.onset_start),
        "onset_end": iso_datetime(request.onset_end),
        "lookback_days": request.lookback_days,
        "affected_entity": request.affected_entity,
        "suspected_change": request.suspected_change,
        "method": "Fixed rules order recorded changes by timing, problem-area relevance, symptom specificity, and counter-evidence. The order is not a probability or proof of cause.",
        "assessment": (
            assessment.as_dict()
            if assessment
            else InvestigationAssessment(
                NEUTRAL_ASSESSMENT,
                ("No assessment was supplied for this investigation.",),
            ).as_dict()
        ),
        "hypotheses": [item.as_dict() for item in ranked],
    }
