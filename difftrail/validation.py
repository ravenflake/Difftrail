from __future__ import annotations

import random
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Iterable

from .correlation import Hypothesis, assess_investigation, rank_candidates
from .models import Event, IncidentRequest, utc_now


@dataclass(frozen=True)
class GroundTruthScenario:
    name: str
    description: str
    request: IncidentRequest
    events: tuple[Event, ...]
    expected_event_id: str | None
    expected_max_rank: int = 1
    expected_confidence: str | None = None
    expected_assessment: str | None = None
    coverage: dict[str, Any] | None = None


def _change(
    base: datetime,
    event_id: str,
    hours_before: float,
    subsystem: str,
    title: str,
    source: str,
    action: str = "updated",
) -> Event:
    return Event(
        base - timedelta(hours=hours_before),
        "change",
        subsystem,
        action,
        title,
        entity=title,
        source=source,
        severity="high" if subsystem in {"graphics", "audio", "network", "driver"} else "medium",
        event_id=event_id,
    )


def _symptom(base: datetime, event_id: str, hours_before: float, subsystem: str, title: str, action: str = "failure") -> Event:
    return Event(
        base - timedelta(hours=hours_before),
        "symptom",
        subsystem,
        action,
        title,
        entity=title,
        source="ground-truth",
        severity="high",
        event_id=event_id,
    )


def build_ground_truth_scenarios(base: datetime | None = None) -> tuple[GroundTruthScenario, ...]:
    now = base or utc_now()
    scenarios: list[GroundTruthScenario] = []

    scenarios.append(
        GroundTruthScenario(
            "graphics-driver-with-distractors",
            "Graphics crashes started after a driver update, with a nearby app update and service addition.",
            IncidentRequest("the graphics started crashing", now - timedelta(hours=2), now, "graphics", 7),
            (
                _change(now, "gt-graphics-driver", 20, "graphics", "Display driver updated", "drivers"),
                _change(now, "gt-graphics-app", 18, "application", "Chat app updated", "apps"),
                _change(now, "gt-graphics-service", 12, "startup", "Overlay service added", "services", "added"),
                _symptom(now, "gt-graphics-reset", 1, "graphics", "Display driver reset", "driver_reset"),
                _symptom(now, "gt-graphics-crash", 0.5, "graphics", "Game crash", "crash"),
            ),
            "gt-graphics-driver",
            expected_assessment="candidate_found",
        )
    )
    scenarios.append(
        GroundTruthScenario(
            "audio-device-with-distractors",
            "Audio stopped after the default device changed; an unrelated app update is more recent.",
            IncidentRequest("the audio stopped working", now - timedelta(hours=3), now, "audio", 7),
            (
                _change(now, "gt-audio-device", 16, "audio", "Default audio device changed", "devices", "changed"),
                _change(now, "gt-audio-app", 10, "application", "Media app updated", "apps"),
                _symptom(now, "gt-audio-failure", 2, "audio", "Audio failure", "device_failure"),
            ),
            "gt-audio-device",
            expected_assessment="candidate_found",
        )
    )
    scenarios.append(
        GroundTruthScenario(
            "network-driver-relevance",
            "Connectivity failed after a network driver change and a close-in-time unrelated app update.",
            IncidentRequest("Wi-Fi became unstable", now - timedelta(hours=1), now, "network", 7),
            (
                _change(now, "gt-network-driver", 30, "network", "Wi-Fi driver updated", "drivers"),
                _change(now, "gt-network-app", 2, "application", "Browser updated", "apps"),
                _symptom(now, "gt-network-failure", 0.5, "network", "Connectivity failure", "connectivity_failure"),
            ),
            "gt-network-driver",
            expected_assessment="candidate_found",
        )
    )
    scenarios.append(
        GroundTruthScenario(
            "older-relevant-change-beats-recent-distractor",
            "A relevant graphics driver change is older than a recent unrelated app update.",
            IncidentRequest("games are crashing", now - timedelta(hours=0.5), now, "graphics", 7),
            (
                _change(now, "gt-older-driver", 48, "graphics", "Graphics driver updated", "drivers"),
                _change(now, "gt-recent-app", 2, "application", "Chat app updated", "apps"),
                _symptom(now, "gt-older-crash", 0.25, "graphics", "Game crash", "crash"),
            ),
            "gt-older-driver",
            expected_assessment="candidate_found",
        )
    )
    scenarios.append(
        GroundTruthScenario(
            "counter-evidence-reduces-support",
            "Audio fails after a driver change, but the same symptom was already present before it.",
            IncidentRequest("audio is unreliable", now - timedelta(hours=1), now, "audio", 7),
            (
                _symptom(now, "gt-audio-old-failure", 16, "audio", "Audio failure", "device_failure"),
                _change(now, "gt-audio-driver-counter", 12, "audio", "Audio driver updated", "drivers"),
                _symptom(now, "gt-audio-new-failure", 0.5, "audio", "Audio failure", "device_failure"),
                _change(now, "gt-audio-counter-app", 5, "application", "Chat app updated", "apps"),
            ),
            "gt-audio-driver-counter",
            expected_confidence="Medium",
            expected_assessment="insufficient_evidence",
        )
    )
    scenarios.append(
        GroundTruthScenario(
            "missing-symptom-evidence",
            "A relevant driver changed, but no symptom event was recorded.",
            IncidentRequest("the display feels wrong", now - timedelta(hours=1), now, "graphics", 7),
            (
                _change(now, "gt-missing-driver", 6, "graphics", "Graphics driver updated", "drivers"),
                _change(now, "gt-missing-app", 2, "application", "Chat app updated", "apps"),
            ),
            "gt-missing-driver",
            expected_confidence="Low",
            expected_assessment="insufficient_evidence",
        )
    )
    scenarios.append(
        GroundTruthScenario(
            "no-supported-change-recorded",
            "A network symptom occurs, but only unrelated changes are in the journal.",
            IncidentRequest("the internet stopped working", now - timedelta(hours=1), now, "network", 7),
            (
                _change(now, "gt-no-cause-app", 2, "application", "Chat app updated", "apps"),
                _change(now, "gt-no-cause-service", 4, "startup", "Helper service added", "services", "added"),
                _symptom(now, "gt-no-cause-symptom", 0.5, "network", "Connectivity failure", "connectivity_failure"),
            ),
            None,
            expected_assessment="insufficient_evidence",
        )
    )
    scenarios.append(
        GroundTruthScenario(
            "post-onset-change-is-not-ranked",
            "A graphics driver changes after the selected onset and must not be ranked for the earlier problem window.",
            IncidentRequest("the display failed", now - timedelta(hours=2), now, "graphics", 7),
            (
                _change(now, "gt-post-onset-driver", 1, "graphics", "Graphics driver updated", "drivers"),
                _change(now, "gt-post-onset-app", 1, "application", "Chat app updated", "apps"),
                _symptom(now, "gt-post-onset-symptom", 1.5, "graphics", "Display failure", "device_failure"),
            ),
            None,
            expected_assessment="no_recent_changes",
        )
    )
    scenarios.append(
        GroundTruthScenario(
            "unrelated-symptoms-only",
            "Only an unrelated application symptom exists for a graphics report.",
            IncidentRequest("the graphics failed", now - timedelta(hours=1), now, "graphics", 7),
            (_symptom(now, "gt-unrelated-symptom", 0.5, "application", "Application crash", "crash"),),
            None,
            expected_assessment="no_recent_changes",
        )
    )
    scenarios.append(
        GroundTruthScenario(
            "simultaneous-changes-have-stable-tie-break",
            "Two same-source changes happen together; the stable event ID tie-break must repeat.",
            IncidentRequest("games are crashing", now - timedelta(hours=1), now, "graphics", 7),
            (
                _change(now, "gt-simultaneous-a", 8, "graphics", "Graphics setting A changed", "drivers"),
                _change(now, "gt-simultaneous-b", 8, "graphics", "Graphics setting B changed", "drivers"),
                _symptom(now, "gt-simultaneous-symptom", 0.25, "graphics", "Game crash", "crash"),
            ),
            "gt-simultaneous-a",
            expected_assessment="insufficient_evidence",
        )
    )
    scenarios.append(
        GroundTruthScenario(
            "partial-provider-coverage",
            "A plausible change exists but the latest scan had provider warnings and no symptom evidence.",
            IncidentRequest("the display feels wrong", now - timedelta(hours=1), now, "graphics", 7),
            (_change(now, "gt-partial-driver", 6, "graphics", "Graphics driver updated", "drivers"),),
            "gt-partial-driver",
            expected_confidence="Low",
            expected_assessment="limited_coverage",
            coverage={"known": True, "limited": True, "reasons": ["The latest scan reported provider warnings."]},
        )
    )
    return tuple(scenarios)


def _rank_of(hypotheses: Iterable[Hypothesis], event_id: str | None) -> int | None:
    if event_id is None:
        return None
    for index, hypothesis in enumerate(hypotheses, start=1):
        if hypothesis.event.event_id == event_id:
            return index
    return None


def run_ground_truth_suite(base: datetime | None = None) -> dict[str, Any]:
    scenarios = build_ground_truth_scenarios(base)
    reports: list[dict[str, Any]] = []
    expected_leads = 0
    top1 = 0
    top3 = 0
    no_false_high = 0
    expected_confidence_passes = 0
    assessment_passes = 0
    determinism_failures: list[str] = []
    for scenario in scenarios:
        hypotheses = rank_candidates(scenario.events, scenario.request)
        assessment = assess_investigation(
            scenario.request,
            hypotheses,
            scenario.events,
            coverage=scenario.coverage,
        )
        baseline_order = [item.event.event_id for item in hypotheses]
        for _ in range(3):
            repeated_order = [
                item.event.event_id
                for item in rank_candidates(scenario.events, scenario.request)
            ]
            if repeated_order != baseline_order:
                determinism_failures.append(scenario.name)
                break
        rank = _rank_of(hypotheses, scenario.expected_event_id)
        assessment_pass = scenario.expected_assessment is None or assessment.state == scenario.expected_assessment
        assessment_passes += int(assessment_pass)
        if scenario.expected_event_id is None:
            passed = not any(item.confidence == "High" for item in hypotheses)
            no_false_high += int(passed)
            passed = passed and assessment_pass
        else:
            expected_leads += 1
            top1 += int(rank == 1)
            top3 += int(rank is not None and rank <= 3)
            confidence_pass = scenario.expected_confidence is None or (
                bool(hypotheses) and hypotheses[0].event.event_id == scenario.expected_event_id and hypotheses[0].confidence == scenario.expected_confidence
            )
            expected_confidence_passes += int(confidence_pass)
            passed = rank is not None and rank <= scenario.expected_max_rank and confidence_pass and assessment_pass
        if scenario.name in determinism_failures:
            passed = False
        reports.append(
            {
                "name": scenario.name,
                "description": scenario.description,
                "expected_event_id": scenario.expected_event_id,
                "rank": rank,
                "top": hypotheses[0].public_dict() if hypotheses else None,
                "assessment": assessment.as_dict(),
                "passed": passed,
                "ranked_lead_count": len(hypotheses),
            }
        )
    stress = run_perturbation_suite(base)
    return {
        "scenario_count": len(scenarios),
        "expected_lead_count": expected_leads,
        "expected_lead_top1_rate": round(top1 / expected_leads, 3) if expected_leads else 0.0,
        "expected_lead_top3_rate": round(top3 / expected_leads, 3) if expected_leads else 0.0,
        "no_false_strong_support_rate": round(no_false_high / (len(scenarios) - expected_leads), 3) if len(scenarios) != expected_leads else 1.0,
        "expected_support_pass_rate": round(expected_confidence_passes / expected_leads, 3) if expected_leads else 0.0,
        "assessment_pass_rate": round(assessment_passes / len(scenarios), 3) if scenarios else 0.0,
        "determinism": {"passed": not determinism_failures, "failures": determinism_failures},
        "passed": all(report["passed"] for report in reports) and stress["passed"] and not determinism_failures,
        "perturbation": stress,
        "scenarios": reports,
    }


def run_perturbation_suite(base: datetime | None = None, *, iterations: int = 100, seed: int = 20260802) -> dict[str, Any]:
    """Stress the relevance signal with deterministic nearby distractors."""

    rng = random.Random(seed)
    now = base or utc_now()
    areas = ("graphics", "audio", "network")
    successes = 0
    failures: list[dict[str, Any]] = []
    for index in range(iterations):
        area = areas[index % len(areas)]
        true_hours = rng.uniform(4.0, 72.0)
        onset = now - timedelta(hours=1)
        true_source = "devices" if area == "audio" else "drivers"
        true_event = _change(now, f"stress-true-{index}", true_hours, area, f"Expected {area} change", true_source)
        distractors = [
            _change(now, f"stress-app-{index}", rng.uniform(1.5, max(2.0, true_hours - 0.5)), "application", "Nearby app update", "apps"),
            _change(now, f"stress-startup-{index}", rng.uniform(1.5, max(2.0, true_hours - 0.5)), "startup", "Nearby startup change", "services", "added"),
        ]
        symptoms = (_symptom(now, f"stress-symptom-{index}", 0.25, area, f"{area} failure"),)
        request = IncidentRequest(f"{area} stopped working", onset, now, area, 7)
        hypotheses = rank_candidates((true_event, *distractors, *symptoms), request)
        rank = _rank_of(hypotheses, true_event.event_id)
        if rank == 1:
            successes += 1
        elif len(failures) < 10:
            failures.append({"iteration": index, "area": area, "rank": rank, "top": hypotheses[0].public_dict() if hypotheses else None})
    top1_rate = successes / iterations if iterations else 0.0
    return {"iterations": iterations, "seed": seed, "expected_lead_top1_rate": round(top1_rate, 3), "passed": top1_rate >= 0.95, "failures": failures}
