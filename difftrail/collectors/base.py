from __future__ import annotations

from datetime import datetime
from typing import Protocol

from ..models import Event, SnapshotItem


class Collector(Protocol):
    def collect_snapshots(self) -> dict[str, list[SnapshotItem]]: ...

    def collect_symptoms(self, since: datetime) -> list[Event]: ...
