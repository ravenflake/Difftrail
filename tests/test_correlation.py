import unittest
from datetime import timedelta

from difftrail.correlation import infer_subsystem, rank_candidates
from difftrail.models import Event, IncidentRequest, utc_now


class CorrelationTests(unittest.TestCase):
    def test_infers_area_from_plain_language(self) -> None:
        self.assertEqual(infer_subsystem("Bluetooth headphones stopped working"), "bluetooth")
        self.assertEqual(infer_subsystem("my game crashes after launch"), "graphics")
        self.assertEqual(infer_subsystem("the driver stopped working"), "driver")
        self.assertEqual(infer_subsystem("a new background service appeared"), "startup")

    def test_investigation_requires_a_description(self) -> None:
        now = utc_now()
        with self.assertRaises(ValueError):
            IncidentRequest("  ", now - timedelta(hours=1), now, "general", 7)

    def test_related_change_ranks_above_recent_unrelated_change(self) -> None:
        now = utc_now()
        events = [
            Event(now - timedelta(hours=8), "change", "graphics", "updated", "Display driver updated", source="drivers", severity="high", event_id="driver"),
            Event(now - timedelta(hours=7), "change", "application", "updated", "Chat app updated", source="apps", event_id="app"),
            Event(now - timedelta(hours=1), "symptom", "graphics", "driver_reset", "Display driver reset", source="eventlog", event_id="reset"),
            Event(now - timedelta(minutes=40), "symptom", "graphics", "crash", "Game crash", source="eventlog", event_id="crash"),
        ]
        request = IncidentRequest("my graphics started crashing", now - timedelta(hours=2), now, "graphics", 7)
        hypotheses = rank_candidates(events, request)
        self.assertGreaterEqual(len(hypotheses), 2)
        self.assertEqual(hypotheses[0].event.event_id, "driver")
        self.assertIn(hypotheses[0].confidence, {"High", "Medium"})
        signals = {item.signal for item in hypotheses[0].evidence}
        self.assertTrue({"temporal proximity", "subsystem relevance", "baseline break"}.issubset(signals))
        self.assertEqual(hypotheses[0].safe_diagnostic["target"], "devmgmt.msc")

    def test_prior_symptoms_are_visible_as_counter_evidence(self) -> None:
        now = utc_now()
        events = [
            Event(now - timedelta(hours=10), "symptom", "audio", "failure", "Audio failure", source="eventlog", event_id="old"),
            Event(now - timedelta(hours=4), "change", "audio", "updated", "Audio driver updated", source="drivers", event_id="driver"),
            Event(now - timedelta(minutes=30), "symptom", "audio", "failure", "Audio failure", source="eventlog", event_id="new"),
        ]
        request = IncidentRequest("audio stopped working", now - timedelta(hours=1), now, "audio", 7)
        hypotheses = rank_candidates(events, request)
        self.assertTrue(hypotheses[0].counter_evidence)

    def test_unrelated_application_symptoms_do_not_support_graphics_changes(self) -> None:
        now = utc_now()
        events = [
            Event(now - timedelta(hours=6), "change", "startup", "added", "Background service added", source="services", event_id="service"),
            Event(now - timedelta(hours=5), "change", "application", "updated", "Chat app updated", source="apps", event_id="app"),
            Event(now - timedelta(minutes=30), "symptom", "application", "crash", "Application crash detected", source="eventlog", event_id="app-crash"),
        ]
        request = IncidentRequest("graphics started failing", now - timedelta(hours=1), now, "graphics", 7)
        hypotheses = rank_candidates(events, request)
        by_id = {hypothesis.event.event_id: hypothesis for hypothesis in hypotheses}
        self.assertEqual(by_id["service"].confidence, "Low")
        self.assertEqual(by_id["app"].confidence, "Low")
        self.assertIn("No related symptom event", by_id["service"].evidence[2].explanation)
