from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass
from datetime import timedelta
from typing import Any, Iterable

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
        supporting = [
            symptom
            for symptom in symptoms
            if event_time <= ensure_utc(symptom.occurred_at) <= onset_end
            and _subsystem_matches(request.subsystem, symptom.subsystem)
            and (
                symptom.subsystem == event.subsystem
                or symptom.subsystem in COMPATIBLE_SUBSYSTEMS.get(event.subsystem, set())
            )
        ]
        prior_symptoms = [
            symptom
            for symptom in symptoms
            if lookback_start <= ensure_utc(symptom.occurred_at) < event_time
            and (
                symptom.subsystem == request.subsystem
                or request.subsystem == "general"
                or symptom.subsystem in COMPATIBLE_SUBSYSTEMS.get(request.subsystem, set())
            )
        ]
        baseline = 0.9 if supporting and not prior_symptoms else 0.65 if supporting else 0.25
        rarity = 1.0 if source_counts[event.source] == 1 else max(0.35, 1.0 / source_counts[event.source])
        score = 0.35 * temporal + 0.35 * relevance + 0.2 * baseline + 0.1 * rarity

        evidence: list[Evidence] = [
            Evidence(
                "temporal proximity",
                _strength(temporal),
                f"This change occurred {gap_hours:.1f} hours before the selected onset.",
                event.event_id,
            ),
            Evidence("subsystem relevance", _strength(relevance), relevance_text, event.event_id),
        ]
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

    results.sort(key=lambda item: (-item.score, ensure_utc(item.event.occurred_at)), reverse=False)
    return results[: max(1, min(limit, 50))]


def investigation_summary(request: IncidentRequest, hypotheses: Iterable[Hypothesis]) -> dict[str, Any]:
    ranked = list(hypotheses)
    return {
        "description": request.description,
        "subsystem": request.subsystem,
        "onset_start": iso_datetime(request.onset_start),
        "onset_end": iso_datetime(request.onset_end),
        "lookback_days": request.lookback_days,
        "method": "deterministic evidence signals; no AI causal inference",
        "hypotheses": [item.as_dict() for item in ranked],
    }
