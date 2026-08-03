from __future__ import annotations

"""Headless one-shot worker used by the Windows background task."""

import argparse
import logging
import logging.handlers
import os
from pathlib import Path

from .automation import run_automated_scan
from .db import Database


LOGGER = logging.getLogger("difftrail.watcher")


def _log_path(database_path: Path) -> Path:
    if os.name == "nt":
        local_app_data = os.environ.get("LOCALAPPDATA")
        if local_app_data:
            return Path(local_app_data) / "Difftrail" / "watcher.log"
    return database_path.with_name("watcher.log")


def _configure_logging(database_path: Path) -> None:
    log_path = _log_path(database_path)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    handler = logging.handlers.RotatingFileHandler(
        log_path,
        maxBytes=1_048_576,
        backupCount=1,
        encoding="utf-8",
    )
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    LOGGER.setLevel(logging.INFO)
    LOGGER.addHandler(handler)


def run_once(database_path: Path) -> int:
    _configure_logging(database_path)
    try:
        with Database(database_path) as database:
            result = run_automated_scan(database)
        if result.errors:
            LOGGER.warning(
                "Background scan completed with warnings: %s",
                " | ".join(result.errors),
            )
        else:
            LOGGER.info(
                "Background scan completed: status=%s changes=%s symptoms=%s sources=%s",
                result.status,
                result.state_events,
                result.symptom_events,
                result.sources,
            )
        return 0
    except Exception:
        LOGGER.exception("Background scan failed")
        return 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="difftrail-watcher")
    parser.add_argument("--db", required=True, help="SQLite path for the local journal")
    args = parser.parse_args(argv)
    return run_once(Path(args.db))


if __name__ == "__main__":
    raise SystemExit(main())
