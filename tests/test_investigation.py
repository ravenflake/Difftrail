import unittest
from datetime import timedelta

from difftrail.db import Database
from difftrail.investigation import run_investigation
from difftrail.models import Event, IncidentRequest, utc_now


class InvestigationTests(unittest.TestCase):
    def test_filters_events_to_window_before_applying_limit(self) -> None:
        now = utc_now()
        old_events = [
            Event(
                now - timedelta(days=2) + timedelta(seconds=index),
                "change",
                "graphics",
                "updated",
                f"Old event {index}",
                source="drivers",
                event_id=f"old-{index}",
            )
            for index in range(10_001)
        ]
        recent_change = Event(
            now - timedelta(hours=2),
            "change",
            "graphics",
            "updated",
            "Display driver updated",
            source="drivers",
            severity="high",
            event_id="recent-change",
        )
        recent_symptom = Event(
            now - timedelta(minutes=30),
            "symptom",
            "graphics",
            "failure",
            "Display failure",
            source="eventlog",
            event_id="recent-symptom",
        )

        with Database(":memory:") as database:
            database.save_events([*old_events, recent_change, recent_symptom])
            request = IncidentRequest(
                "graphics started failing",
                now - timedelta(hours=1),
                now,
                "graphics",
                1,
            )

            run = run_investigation(database, request)

        self.assertEqual(
            [event.event_id for event in run.events],
            ["recent-change", "recent-symptom"],
        )
        self.assertEqual(run.hypotheses[0].event.event_id, "recent-change")
        self.assertFalse(run.assessment.coverage["known"])
        self.assertEqual(run.hypotheses[0].confidence, "Low")
        self.assertEqual(run.assessment.state, "insufficient_evidence")


if __name__ == "__main__":
    unittest.main()
