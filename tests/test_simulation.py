import unittest

from difftrail.db import Database
from difftrail.models import IncidentRequest, utc_now
from difftrail.simulation import run_controlled_fixture_suite, simulate_nvidia_driver_switch
from difftrail.correlation import rank_candidates


class SimulationTests(unittest.TestCase):
    def test_controlled_fixture_suite_replays_real_scanner_path(self) -> None:
        report = run_controlled_fixture_suite()

        self.assertTrue(report["passed"])
        self.assertEqual(report["scenario_count"], 5)
        self.assertEqual(report["checks"], {
            "capture": True,
            "ranking": True,
            "no_false_high": True,
            "evidence": True,
        })
        for scenario in report["scenarios"]:
            self.assertEqual(scenario["baseline"]["state_events"], 0)
            self.assertEqual(scenario["baseline"]["symptom_events"], 0)
            self.assertTrue(scenario["passed"])
            self.assertTrue(all(item["passed"] for item in scenario["expectations"]))

    def test_controlled_fixture_mixes_unrelated_sources_without_false_high(self) -> None:
        report = run_controlled_fixture_suite()
        scenario = next(item for item in report["scenarios"] if item["name"] == "mixed-unrelated-changes")

        self.assertEqual(scenario["replay"]["state_events"], 5)
        self.assertEqual(
            scenario["captured_change_sources"],
            ["apps", "drivers", "services", "startup", "tasks"],
        )
        self.assertEqual(scenario["top"]["event"]["source"], "drivers")
        self.assertEqual(scenario["checks"]["no_false_high"], True)

    def test_nvidia_driver_switch_replay_uses_snapshot_diff_and_ranks_driver(self) -> None:
        with Database(":memory:") as database:
            result = simulate_nvidia_driver_switch(database)
            self.assertEqual(result["baseline"]["state_events"], 0)
            self.assertEqual(result["change_scan"]["state_events"], 2)
            self.assertEqual(result["change_scan"]["symptom_events"], 1)
            self.assertIn("--db", result["next_command"])

            events = database.list_events(limit=20, ascending=True)
            changes = [event for event in events if event.kind == "change"]
            driver_change = next(event for event in changes if event.source == "drivers")
            self.assertEqual(driver_change.subsystem, "graphics")
            self.assertEqual(driver_change.details["before"]["version"], "31.0.15.5222")
            self.assertEqual(driver_change.details["after"]["version"], "32.0.16.1088")

            now = utc_now()
            hypotheses = rank_candidates(
                events,
                IncidentRequest("graphics started failing", now, now, "graphics", 7),
            )
            self.assertEqual(hypotheses[0].event.source, "drivers")
            self.assertEqual(hypotheses[0].confidence, "High")

    def test_simulation_refuses_a_non_empty_database(self) -> None:
        with Database(":memory:") as database:
            simulate_nvidia_driver_switch(database)
            with self.assertRaises(ValueError):
                simulate_nvidia_driver_switch(database)
