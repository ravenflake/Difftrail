from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import re
from typing import Any

from .privacy import redact_public_text


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
    affected_entity: str | None = None
    suspected_change: str | None = None

    def __post_init__(self) -> None:
        if not self.description.strip():
            raise ValueError("Incident description must not be empty")
        if self.onset_end < self.onset_start:
            raise ValueError("Incident end must be after incident start")
        if self.lookback_days < 1 or self.lookback_days > 365:
            raise ValueError("lookback_days must be between 1 and 365")
        if self.subsystem not in KNOWN_SUBSYSTEMS:
            raise ValueError(f"Unsupported incident subsystem: {self.subsystem}")
        for name, value in (
            ("affected_entity", self.affected_entity),
            ("suspected_change", self.suspected_change),
        ):
            if value is not None and not isinstance(value, str):
                raise ValueError(f"{name} must be a string or None")
            if value is not None and len(value.strip()) > 200:
                raise ValueError(f"{name} must be 200 characters or fewer")


def automatic_draft_request(
    *,
    title: str,
    entity: str,
    occurred_at: datetime,
    subsystem: str,
    action: str = "",
) -> IncidentRequest:
    """Build the canonical request used for an automatic investigation draft."""

    identity = _safe_draft_identity(entity)
    if action == "crash":
        description = f"{identity} crashed" if identity else "Application crashed"
    elif action == "hang":
        description = f"{identity} stopped responding" if identity else "Application stopped responding"
    else:
        fallbacks = {
            "driver_reset": "Display driver reset detected",
            "unexpected_restart": "Unexpected restart detected",
            "unexpected_shutdown": "Unexpected shutdown detected",
            "failure": "Application failure detected" if subsystem == "application" else "System failure detected",
        }
        description = fallbacks.get(action, "System symptom detected")
    normalized_subsystem = subsystem if subsystem in KNOWN_SUBSYSTEMS else "general"
    return IncidentRequest(
        description=description,
        onset_start=occurred_at,
        onset_end=occurred_at,
        subsystem=normalized_subsystem,
        lookback_days=7,
        affected_entity=identity,
    )


def legacy_automatic_draft_request(
    *,
    title: str,
    entity: str,
    occurred_at: datetime,
    subsystem: str,
) -> IncidentRequest:
    """Reconstruct a pre-v7 request when repairing older unlinked drafts."""

    safe_title = redact_public_text(title).strip()
    identity = redact_public_text(entity).strip()
    description = f"Automatic draft: {safe_title}" + (
        f" · {identity}" if identity and identity not in safe_title else ""
    )
    normalized_subsystem = subsystem if subsystem in KNOWN_SUBSYSTEMS else "general"
    return IncidentRequest(
        description=description,
        onset_start=occurred_at,
        onset_end=occurred_at,
        subsystem=normalized_subsystem,
        lookback_days=7,
    )


def _safe_draft_identity(raw: str) -> str | None:
    value = str(raw or "").strip().strip("\"'")
    generic = {"", "application error", "application hang", "unknown", "unknown app"}
    if not value or value.casefold() in generic:
        return None
    contained_path = "\\" in value or "/" in value
    value = re.split(r"[\\/]", value)[-1]
    executable = re.match(
        r'^"?(.+?\.(?:exe|com|bat|cmd|msi|msix|appx))(?=["\s]|$)',
        value,
        flags=re.IGNORECASE,
    )
    if executable:
        value = executable.group(1)
    elif contained_path:
        return None
    value = redact_public_text(value)
    value = re.sub(r"[^A-Za-z0-9._() +\-]", "", value)[:80].strip()
    return value if value and value.casefold() not in generic and "<path>" not in value.casefold() else None


@dataclass(frozen=True)
class Incident:
    id: str
    created_at: datetime
    request: IncidentRequest
    status: str = "investigating"
    results: list[dict[str, Any]] = field(default_factory=list)
