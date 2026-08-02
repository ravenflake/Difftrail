import json
import unittest

from difftrail.db import Database
from difftrail.simulation import simulate_nvidia_driver_switch
from difftrail.ui_api import build_bootstrap, create_investigation


class UiApiTests(unittest.TestCase):
    def test_bootstrap_exposes_real_journal_without_raw_event_details(self) -> None:
        with Database(":memory:") as database:
            simulate_nvidia_driver_switch(database)
            payload = build_bootstrap(database)

        self.assertEqual(payload["status"]["changes"], 2)
        self.assertEqual(len(payload["events"]), 3)
        self.assertTrue(all("details" not in event for event in payload["events"]))
        self.assertNotIn('"details":', json.dumps(payload))

    def test_investigation_response_is_ui_safe_and_persists_incident(self) -> None:
        with Database(":memory:") as database:
            simulate_nvidia_driver_switch(database)
            result = create_investigation(
                database,
                {"description": "graphics started failing", "subsystem": "graphics", "lookback_days": 7},
            )

            self.assertTrue(result["incident"]["id"])
            self.assertEqual(result["summary"]["incident_id"], result["incident"]["id"])
            self.assertTrue(result["summary"]["hypotheses"])
            self.assertTrue(all("details" not in hypothesis["event"] for hypothesis in result["summary"]["hypotheses"]))
