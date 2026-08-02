"""Read-only system data collectors."""

from .base import Collector
from .windows import WindowsCollector

__all__ = ["Collector", "WindowsCollector"]
