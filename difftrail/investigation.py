from __future__ import annotations

"""Shared deterministic investigation orchestration."""

from dataclasses import dataclass
from datetime import timedelta
from typing import Any

from .correlation import (
    Hypothesis,
    InvestigationAssessment,
    assess_investigation,
    investigation_summary,
    rank_candidates,
)
from .db import Database
from .models import Event, Incident, IncidentRequest


@dataclass(frozen=True)
class InvestigationRun:
    incident: Incident
    events: tuple[Event, ...]
    hypotheses: tuple[Hypothesis, ...]
    assessment: InvestigationAssessment
    summary: dict[str, Any]


def run_investigation(
    database: Database,
    request: IncidentRequest,
    *,
    status: str = "investigating",
    commit: bool = True,
) -> InvestigationRun:
    """Create, assess, and persist one deterministic investigation."""

    incident = database.create_incident(request, status=status, commit=commit)
    window_start = request.onset_start - timedelta(days=request.lookback_days)
    events = database.list_events(
        limit=10_000,
        ascending=True,
        since=window_start,
        until=request.onset_end,
    )
    hypotheses = tuple(rank_candidates(events, request))
    coverage = database.investigation_coverage(
        request.subsystem,
        since=window_start,
        until=request.onset_end,
    )
    assessment = assess_investigation(request, hypotheses, events, coverage=coverage)
    summary = investigation_summary(request, hypotheses, assessment=assessment)
    database.update_incident_results(
        incident.id,
        summary["hypotheses"],
        status=status,
        assessment=assessment.state,
        assessment_reasons=assessment.reasons,
        coverage=coverage,
        commit=commit,
    )
    return InvestigationRun(incident, tuple(events), hypotheses, assessment, summary)
