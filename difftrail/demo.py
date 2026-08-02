from __future__ import annotations

from datetime import timedelta

from .db import Database
from .models import Event, utc_now


def seed_demo(database: Database) -> int:
    """Seed a small, deterministic-looking incident for first-run exploration."""

    if database.count_events() > 0:
        return 0
    now = utc_now()
    events = [
        Event(
            occurred_at=now - timedelta(hours=36),
            kind="change",
            subsystem="graphics",
            action="updated",
            title="NVIDIA display driver updated",
            entity="NVIDIA display adapter",
            severity="high",
            source="demo",
            details={"from_version": "551.23", "to_version": "552.12", "source": "Windows Update"},
            event_id="demo:graphics-driver-update",
        ),
        Event(
            occurred_at=now - timedelta(hours=35, minutes=45),
            kind="change",
            subsystem="application",
            action="updated",
            title="Discord updated",
            entity="Discord",
            severity="low",
            source="demo",
            details={"from_version": "1.0", "to_version": "1.1"},
            event_id="demo:discord-update",
        ),
        Event(
            occurred_at=now - timedelta(hours=28),
            kind="change",
            subsystem="startup",
            action="added",
            title="Service GameOverlay Helper added",
            entity="GameOverlay Helper",
            severity="medium",
            source="demo",
            details={"start_mode": "Automatic", "state": "Running"},
            event_id="demo:service-added",
        ),
        Event(
            occurred_at=now - timedelta(hours=1),
            kind="symptom",
            subsystem="graphics",
            action="driver_reset",
            title="Display driver reset detected",
            entity="Display",
            severity="high",
            source="demo",
            details={"message": "The display driver stopped responding and recovered."},
            event_id="demo:driver-reset",
        ),
        Event(
            occurred_at=now - timedelta(minutes=45),
            kind="symptom",
            subsystem="graphics",
            action="crash",
            title="Application crash detected",
            entity="Example game",
            severity="high",
            source="demo",
            details={"message": "The example game crashed after launch."},
            event_id="demo:game-crash",
        ),
    ]
    return database.save_events(events)
