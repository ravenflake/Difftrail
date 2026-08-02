import argparse
import contextlib
import io
import json
import tempfile
import unittest
from datetime import timedelta
from pathlib import Path
from unittest.mock import patch

from difftrail.cli import command_investigate
from difftrail.db import Database
from difftrail.models import Event, utc_now


class CliTests(unittest.TestCase):
    def test_investigation_without_onset_includes_recent_changes(self) -> None:
        now = utc_now()
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "journal.db"
            with Database(path) as database:
                database.save_events(
                    [
                        Event(
                            now - timedelta(minutes=5),
                            "change",
                            "graphics",
                            "updated",
                            "Display driver updated",
                            source="drivers",
                            severity="high",
                            event_id="recent-driver",
                        )
                    ]
                )

            args = argparse.Namespace(
                db=str(path),
                description="graphics started failing",
                onset=None,
                subsystem="graphics",
                lookback_days=7,
                json=True,
            )
            output = io.StringIO()
            with patch("difftrail.cli.utc_now", return_value=now), contextlib.redirect_stdout(output):
                self.assertEqual(command_investigate(args), 0)

            result = json.loads(output.getvalue())
            self.assertEqual(result["onset_start"], result["onset_end"])
            self.assertEqual(result["hypotheses"][0]["event"]["id"], "recent-driver")
