from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


UTC = timezone.utc
KNOWN_SUBSYSTEMS = frozenset(
    {
        "general",
        "graphics",
        "audio",
        "network",
        "bluetooth",
        "driver",
        "startup",
        "windows-update",
        "application",
        "device",
    }
)


def utc_now() -> datetime:
    return datetime.now(UTC)


def ensure_utc(value: datetime) -> datetime:
    """Return an aware UTC datetime, treating naive values as UTC."""

    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def parse_datetime(value: str | datetime) -> datetime:
    if isinstance(value, datetime):
        return ensure_utc(value)
    normalized = value.strip().replace("Z", "+00:00")
    return ensure_utc(datetime.fromisoformat(normalized))


def iso_datetime(value: datetime) -> str:
    return ensure_utc(value).isoformat(timespec="seconds").replace("+00:00", "Z")


@dataclass(frozen=True)
class Event:
    occurred_at: datetime
    kind: str
    subsystem: str
    action: str
    title: str
    entity: str = ""
    severity: str = "medium"
    source: str = "unknown"
    details: dict[str, Any] = field(default_factory=dict)
    event_id: str | None = None
    fingerprint: str | None = None

    def __post_init__(self) -> None:
        if self.kind not in {"change", "symptom"}:
            raise ValueError(f"Unsupported event kind: {self.kind}")
        if self.severity not in {"info", "low", "medium", "high", "critical"}:
            raise ValueError(f"Unsupported event severity: {self.severity}")

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.event_id,
            "occurred_at": iso_datetime(self.occurred_at),
            "kind": self.kind,
            "subsystem": self.subsystem,
            "action": self.action,
            "title": self.title,
            "entity": self.entity,
            "severity": self.severity,
            "source": self.source,
            "details": self.details,
        }


@dataclass(frozen=True)
class SnapshotItem:
    """Current state for one item in a collector's snapshot."""

    source: str
    key: str
    subsystem: str
    display_name: str
    payload: dict[str, Any]
    severity: str = "medium"
    entity: str = ""
    action_on_add: str = "added"
    action_on_update: str = "updated"


@dataclass(frozen=True)
class IncidentRequest:
    description: str
    onset_start: datetime
    onset_end: datetime
    subsystem: str = "general"
    lookback_days: int = 7

    def __post_init__(self) -> None:
        if not self.description.strip():
            raise ValueError("Incident description must not be empty")
        if self.onset_end < self.onset_start:
            raise ValueError("Incident end must be after incident start")
        if self.lookback_days < 1 or self.lookback_days > 365:
            raise ValueError("lookback_days must be between 1 and 365")
        if self.subsystem not in KNOWN_SUBSYSTEMS:
            raise ValueError(f"Unsupported incident subsystem: {self.subsystem}")


@dataclass(frozen=True)
class Incident:
    id: str
    created_at: datetime
    request: IncidentRequest
    status: str = "investigating"
    results: list[dict[str, Any]] = field(default_factory=list)
