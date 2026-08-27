from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass
from datetime import timedelta
from typing import Any, Iterable

from .assessment import ASSESSMENT_STATES, NEUTRAL_ASSESSMENT
from .models import Event, IncidentRequest, ensure_utc, iso_datetime


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
# a causal conclusion by itself.
ENTITY_RELEVANCE_BOOST = 0.12
SUSPECTED_CHANGE_BOOST = 0.06
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

    def as_dict(self) -> dict[str, Any]:
        return {
            "event": self.event.as_dict(),
            "score": round(self.score, 3),
            "confidence": self.confidence,
            "evidence": [item.as_dict() for item in self.evidence],
            "counter_evidence": [item.as_dict() for item in self.counter_evidence],
            "next_action": self.next_action,
            "safe_diagnostic": self.safe_diagnostic,
        }


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


def _symptom_matches_context(value: str | None, symptom: Event) -> bool:
    """Exclude a known different entity, while retaining unidentified evidence."""

    context_key = _identity_key(value)
    if not context_key:
        return True
    symptom_keys = _event_identity_keys(symptom)
    return not symptom_keys or context_key in symptom_keys


def _strength(value: float) -> str:
    if value >= 0.78:
        return "strong"
    if value >= 0.5:
        return "moderate"
    return "weak"


def _next_action(event: Event) -> str:
    if event.subsystem in {"graphics", "audio", "network", "bluetooth", "driver"} or event.source == "drivers":
        return "Review the device in Device Manager; use Windows' built-in rollback option only after checking the evidence."
    if event.subsystem == "windows-update" or event.source == "updates":
        return "Review Windows Update history and use its standard uninstall or recovery option only if appropriate."
    if event.source in {"services", "tasks", "startup"} or event.subsystem == "startup":
        return "Review the new persistence entry; disable it only if you recognize it and can restore it."
    if event.subsystem == "application" or event.source == "apps":
        return "Open the application's normal update or repair flow; Difftrail will not remove software automatically."
    if event.subsystem == "device":
        return "Reconnect the device and review its driver association in Windows settings."
    return "Open the originating Windows evidence and inspect this change before acting."


def _safe_diagnostic(event: Event) -> dict[str, str]:
    """Return a read-only Windows surface the user may open manually."""

    if event.subsystem in {"graphics", "audio", "network", "bluetooth", "device", "driver"} or event.source == "drivers":
        return {"label": "Device Manager", "target": "devmgmt.msc", "note": "Opening this surface does not change system state."}
    if event.subsystem == "windows-update" or event.source == "updates":
        return {"label": "Windows Update history", "target": "ms-settings:windowsupdate-history", "note": "Opening this surface does not change system state."}
    if event.source == "tasks":
        return {"label": "Task Scheduler", "target": "taskschd.msc", "note": "Opening this surface does not change system state."}
    if event.source in {"services", "startup"} or event.subsystem == "startup":
        return {"label": "Services", "target": "services.msc", "note": "Opening this surface does not change system state."}
    if event.subsystem == "application" or event.source == "apps":
        return {"label": "Installed apps", "target": "ms-settings:appsfeatures", "note": "Opening this surface does not change system state."}
    return {"label": "Event Viewer", "target": "eventvwr.msc", "note": "Opening this surface does not change system state."}


def rank_candidates(
    events: Iterable[Event],
    request: IncidentRequest,
    *,
    limit: int = 8,
) -> list[Hypothesis]:
    """Rank changes with deterministic, inspectable evidence signals.

    The result intentionally avoids percentages. Scores are only an internal
    ordering mechanism; the UI exposes High/Medium/Low plus the signals that
    produced the ordering.
    """

    onset_start = ensure_utc(request.onset_start)
    onset_end = ensure_utc(request.onset_end)
    lookback_start = onset_start - timedelta(days=request.lookback_days)
    all_events = sorted(events, key=lambda item: ensure_utc(item.occurred_at))
    changes = [
        event
        for event in all_events
        if event.kind == "change"
        and lookback_start <= ensure_utc(event.occurred_at) <= onset_start
    ]
    symptoms = [event for event in all_events if event.kind == "symptom"]
    source_counts = Counter(event.source for event in changes)
    results: list[Hypothesis] = []

    for event in changes:
        event_time = ensure_utc(event.occurred_at)
        gap_hours = max(0.0, (onset_start - event_time).total_seconds() / 3600)
        temporal = _temporal_score(gap_hours)
        relevance, relevance_text = _relevance(request.subsystem, event.subsystem)
        entity_match = _context_matches_event(request.affected_entity, event)
        suspected_change_match = _context_matches_event(request.suspected_change, event)
        supporting = [
            symptom
            for symptom in symptoms
            if event_time <= ensure_utc(symptom.occurred_at) <= onset_end
            and _subsystem_matches(request.subsystem, symptom.subsystem)
            and _symptom_matches_context(request.affected_entity, symptom)
            and (
                symptom.subsystem == event.subsystem
                or symptom.subsystem in COMPATIBLE_SUBSYSTEMS.get(event.subsystem, set())
            )
        ]
        prior_symptoms = [
            symptom
            for symptom in symptoms
            if lookback_start <= ensure_utc(symptom.occurred_at) < event_time
            and _symptom_matches_context(request.affected_entity, symptom)
            and (
                symptom.subsystem == request.subsystem
                or request.subsystem == "general"
                or symptom.subsystem in COMPATIBLE_SUBSYSTEMS.get(request.subsystem, set())
            )
        ]
        baseline = 0.9 if supporting and not prior_symptoms else 0.65 if supporting else 0.25
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
                f"This change occurred {gap_hours:.1f} hours before the selected onset.",
                event.event_id,
            ),
            Evidence("subsystem relevance", _strength(relevance), relevance_text, event.event_id),
        ]
        if request.affected_entity:
            evidence.append(
                Evidence(
                    "entity relevance",
                    "strong" if entity_match else "weak",
                    (
                        "This change directly matches the affected entity supplied for the investigation."
                        if entity_match
                        else "This change does not directly match the affected entity supplied for the investigation."
                    ),
                    event.event_id,
                )
            )
        if request.suspected_change:
            evidence.append(
                Evidence(
                    "suspected change",
                    "moderate" if suspected_change_match else "weak",
                    (
                        "This event matches the optional recent change suspected by the user."
                        if suspected_change_match
                        else "This event does not directly match the optional recent change suspected by the user."
                    ),
                    event.event_id,
                )
            )
        if supporting:
            evidence.append(
                Evidence(
                    "baseline break",
                    _strength(baseline),
                    f"{len(supporting)} related symptom event{'' if len(supporting) == 1 else 's'} appeared after this change and before the investigation window ended.",
                    supporting[0].event_id,
                )
            )
        else:
            evidence.append(
                Evidence(
                    "baseline break",
                    "weak",
                    "No related symptom event was recorded after this change in the selected window.",
                    event.event_id,
                )
            )
        if source_counts[event.source] == 1:
            evidence.append(
                Evidence("rarity", "strong", "This is the only change from its source in the selected lookback window.", event.event_id)
            )

        counter: list[Evidence] = []
        if prior_symptoms:
            counter.append(
                Evidence(
                    "counter-evidence",
                    "moderate",
                    f"{len(prior_symptoms)} related symptom event{'' if len(prior_symptoms) == 1 else 's'} existed before this change, so it may not be the original cause.",
                    prior_symptoms[0].event_id,
                )
            )
            score -= 0.12
        score = max(0.0, min(1.0, score))
        if not supporting:
            confidence = "Low"
        elif score >= 0.67 and len(evidence) >= 3 and not counter:
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
            -item.score,
            -SOURCE_PRIORITY.get(item.event.source, 0),
            ensure_utc(item.event.occurred_at),
            item.event.event_id or "",
        ),
        reverse=False,
    )
    return results[: max(1, min(limit, 50))]


def assess_investigation(
    request: IncidentRequest,
    hypotheses: Iterable[Hypothesis],
    events: Iterable[Event],
    *,
    coverage: dict[str, Any] | None = None,
) -> InvestigationAssessment:
    """Give the investigation an honest conclusion state.

    A ranked change is not automatically a cause. Low-confidence candidates,
    counter-evidence, and incomplete collection are surfaced as limitations so
    callers do not present a weak guess as an answer.
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
    coverage_limited = bool(normalized_coverage.get("limited"))
    coverage_reasons = normalized_coverage.get("reasons", [])
    if not isinstance(coverage_reasons, list):
        coverage_reasons = []
    reasons: list[str] = [
        str(reason)
        for reason in coverage_reasons
        if str(reason).strip()
    ]

    if not changes:
        reasons.append("No journaled changes occurred during the selected lookback window before onset.")
        state = "limited_coverage" if coverage_limited else "no_recent_changes"
    elif not ranked:
        reasons.append("Changes were recorded, but none matched the reported subsystem closely enough to rank.")
        state = "limited_coverage" if coverage_limited else "insufficient_evidence"
    else:
        lead = ranked[0]
        if lead.confidence == "Low":
            reasons.append("The strongest candidate has only weak supporting evidence.")
        if lead.counter_evidence:
            reasons.append("Related symptoms or signals existed before the strongest candidate change.")
        weak = lead.confidence == "Low" or bool(lead.counter_evidence)
        state = "limited_coverage" if coverage_limited else "insufficient_evidence" if weak else "candidate_found"

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
        "method": "deterministic evidence signals; no AI causal inference",
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
