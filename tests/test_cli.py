import argparse
import contextlib
import io
import json
import tempfile
import unittest
from datetime import timedelta
from pathlib import Path
from unittest.mock import patch

from difftrail.cli import build_parser, command_feedback, command_investigate, command_timeline
from difftrail.db import Database
from difftrail.models import Event, IncidentRequest, utc_now


class CliTests(unittest.TestCase):
    def test_timeline_json_uses_the_reduced_public_event_contract(self) -> None:
        now = utc_now()
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "journal.db"
            with Database(path) as database:
                database.save_events(
                    [
                        Event(
                            now,
                            "change",
                            "application",
                            "updated",
                            "Application updated",
                            source="apps",
                            details={"message": "raw provider text"},
                        )
                    ]
                )

            args = argparse.Namespace(
                db=str(path),
                limit=100,
                kind=None,
                subsystem=None,
                json=True,
            )
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                self.assertEqual(command_timeline(args), 0)

        event = json.loads(output.getvalue())[0]
        self.assertEqual(event["time_basis"], "scan_observation")
        self.assertNotIn("details", event)
        self.assertNotIn("raw provider text", json.dumps(event))

    def test_feedback_uses_helpfulness_terms_while_preserving_stored_schema(self) -> None:
        now = utc_now()
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "journal.db"
            with Database(path) as database:
                event = Event(
                    now - timedelta(hours=1),
                    "change",
                    "application",
                    "updated",
                    "Application updated",
                    source="apps",
                    event_id="app-update",
                )
                database.save_events([event])
                incident = database.create_incident(
                    IncidentRequest("Application started crashing", now, now, "application", 7)
                )
                database.update_incident_results(
                    incident.id,
                    [{"event": event.as_dict(), "confidence": "Low"}],
                )

            args = argparse.Namespace(
                db=str(path),
                incident_id=incident.id,
                outcome="helpful",
                event_id=event.event_id,
                json=True,
            )
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                self.assertEqual(command_feedback(args), 0)

            self.assertEqual(json.loads(output.getvalue())["outcome"], "helpful")
            with Database(path) as database:
                self.assertEqual(database.get_incident(incident.id)["feedback"]["outcome"], "correct")

    def test_feedback_parser_accepts_hyphenated_public_term(self) -> None:
        args = build_parser().parse_args(
            ["feedback", "incident-id", "--outcome", "not-helpful"]
        )
        self.assertEqual(args.outcome, "not_helpful")

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
            lead = result["hypotheses"][0]
            self.assertEqual(lead["event"]["id"], "recent-driver")
            self.assertEqual(lead["support_level"], "weak")
            self.assertNotIn("score", lead)
            self.assertNotIn("confidence", lead)
