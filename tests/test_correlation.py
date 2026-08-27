import unittest
from datetime import timedelta

from difftrail.correlation import assess_investigation, infer_subsystem, investigation_summary, rank_candidates
from difftrail.models import Event, IncidentRequest, utc_now


class CorrelationTests(unittest.TestCase):
    def test_investigation_summary_defaults_to_neutral_assessment(self) -> None:
        now = utc_now()
        request = IncidentRequest("graphics are broken", now, now, "graphics", 7)
        summary = investigation_summary(request, [])
        self.assertEqual(summary["assessment"]["state"], "insufficient_evidence")
        self.assertTrue(summary["assessment"]["reasons"])

    def test_assessment_distinguishes_no_recent_changes(self) -> None:
        now = utc_now()
        request = IncidentRequest("graphics are broken", now, now, "graphics", 7)
        assessment = assess_investigation(request, [], [Event(now, "symptom", "graphics", "failure", "Display failure")])
        self.assertEqual(assessment.state, "no_recent_changes")

    def test_assessment_does_not_present_a_low_confidence_candidate_as_answer(self) -> None:
        now = utc_now()
        request = IncidentRequest("graphics are broken", now, now, "graphics", 7)
        event = Event(now - timedelta(hours=2), "change", "graphics", "updated", "Graphics driver updated", source="drivers")
        hypothesis = rank_candidates([event], request)
        assessment = assess_investigation(request, hypothesis, [event])
        self.assertEqual(assessment.state, "insufficient_evidence")

    def test_assessment_surfaces_limited_coverage(self) -> None:
        now = utc_now()
        request = IncidentRequest("graphics are broken", now, now, "graphics", 7)
        coverage = {"known": True, "limited": True, "reasons": ["The latest scan reported provider warnings."]}
        assessment = assess_investigation(request, [], [], coverage=coverage)
        self.assertEqual(assessment.state, "limited_coverage")
        self.assertIn("The latest scan reported provider warnings.", assessment.reasons)
        self.assertEqual(assessment.coverage, coverage)

    def test_limited_coverage_is_visible_even_with_a_strong_candidate(self) -> None:
        now = utc_now()
        request = IncidentRequest("graphics are broken", now, now, "graphics", 7)
        event = Event(now - timedelta(hours=2), "change", "graphics", "updated", "Graphics driver updated", source="drivers")
        symptom = Event(now - timedelta(minutes=30), "symptom", "graphics", "failure", "Display failure")
        hypotheses = rank_candidates([event, symptom], request)
        assessment = assess_investigation(
            request,
            hypotheses,
            [event, symptom],
            coverage={"known": True, "limited": True, "reasons": ["Provider warning"]},
        )
        self.assertEqual(assessment.state, "limited_coverage")
        self.assertIn("Provider warning", assessment.reasons)
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

    def test_explicit_difftrail_entity_outranks_newer_discord_update(self) -> None:
        now = utc_now()
        onset = now - timedelta(minutes=30)
        events = [
            Event(onset - timedelta(hours=12), "change", "application", "updated", "Application Difftrail updated", entity="Difftrail", source="apps", event_id="difftrail-update"),
            Event(onset - timedelta(hours=1), "change", "application", "updated", "Application Discord updated", entity="Discord", source="apps", event_id="discord-update"),
        ]
        request = IncidentRequest(
            "DiffTrail started having issues",
            onset,
            now,
            "application",
            7,
            affected_entity="DiffTrail.exe",
        )

        hypotheses = rank_candidates(events, request)

        self.assertEqual(hypotheses[0].event.event_id, "difftrail-update")
        entity_signal = next(item for item in hypotheses[0].evidence if item.signal == "entity relevance")
        self.assertEqual(entity_signal.strength, "strong")

    def test_timing_still_orders_two_matching_entity_changes(self) -> None:
        now = utc_now()
        events = [
            Event(now - timedelta(hours=30), "change", "application", "updated", "Application Difftrail updated", entity="Difftrail", source="apps", event_id="older"),
            Event(now - timedelta(hours=2), "change", "application", "updated", "DiffTrail updater changed", entity="DiffTrailUpdater.exe", source="services", event_id="newer"),
        ]
        request = IncidentRequest("Difftrail fails", now, now, "application", 7, affected_entity="difftrail.exe")

        hypotheses = rank_candidates(events, request)

        self.assertEqual(hypotheses[0].event.event_id, "newer")

    def test_entity_match_does_not_defeat_substantially_stronger_counter_evidence(self) -> None:
        now = utc_now()
        onset = now - timedelta(minutes=30)
        matched = Event(onset - timedelta(hours=72), "change", "application", "updated", "Application Difftrail updated", entity="Difftrail", source="apps", event_id="matched-old")
        unrelated = Event(onset - timedelta(hours=1), "change", "application", "updated", "Application Discord updated", entity="Discord", source="apps", event_id="unrelated-recent")
        prior = Event(onset - timedelta(hours=80), "symptom", "application", "crash", "Application crash detected", entity="Difftrail.exe", source="eventlog", event_id="prior")
        unidentified_support = Event(onset, "symptom", "application", "crash", "Application crash detected", source="eventlog", event_id="support")
        request = IncidentRequest("Difftrail fails", onset, now, "application", 7, affected_entity="DiffTrail")

        hypotheses = rank_candidates([prior, matched, unrelated, unidentified_support], request)

        self.assertEqual(hypotheses[0].event.event_id, "unrelated-recent")
        matched_hypothesis = next(item for item in hypotheses if item.event.event_id == "matched-old")
        self.assertTrue(matched_hypothesis.counter_evidence)

    def test_entity_normalization_handles_case_executable_and_associated_service_names(self) -> None:
        now = utc_now()
        event = Event(now - timedelta(hours=1), "change", "startup", "changed", "Service DiffTrail Update Service changed", entity="DiffTrailUpdater.exe", source="services", event_id="service")
        request = IncidentRequest("app hangs", now, now, "application", 7, affected_entity="difftrail.exe")

        hypothesis = rank_candidates([event], request)[0]

        signal = next(item for item in hypothesis.evidence if item.signal == "entity relevance")
        self.assertEqual(signal.strength, "strong")

    def test_partial_name_collision_does_not_receive_entity_boost(self) -> None:
        now = utc_now()
        event = Event(now - timedelta(hours=1), "change", "application", "updated", "Application Difftrailer updated", entity="Difftrailer.exe", source="apps", event_id="collision")
        request = IncidentRequest("Difftrail fails", now, now, "application", 7, affected_entity="DiffTrail")

        hypothesis = rank_candidates([event], request)[0]

        signal = next(item for item in hypothesis.evidence if item.signal == "entity relevance")
        self.assertEqual(signal.strength, "weak")

    def test_suspected_change_is_a_separate_bounded_ranking_signal(self) -> None:
        now = utc_now()
        events = [
            Event(now - timedelta(hours=5), "change", "driver", "updated", "Display driver updated", entity="Display driver", source="drivers", event_id="display-driver"),
            Event(now - timedelta(hours=1), "change", "driver", "updated", "Audio driver updated", entity="Audio driver", source="drivers", event_id="audio-driver"),
        ]
        request = IncidentRequest(
            "the device stopped working",
            now,
            now,
            "driver",
            7,
            suspected_change="display driver update",
        )

        hypotheses = rank_candidates(events, request)

        self.assertEqual(hypotheses[0].event.event_id, "display-driver")
        signal = next(item for item in hypotheses[0].evidence if item.signal == "suspected change")
        self.assertEqual(signal.strength, "moderate")

    def test_no_structured_context_preserves_existing_temporal_order(self) -> None:
        now = utc_now()
        events = [
            Event(now - timedelta(hours=12), "change", "application", "updated", "Application Difftrail updated", entity="Difftrail", source="apps", event_id="difftrail-update"),
            Event(now - timedelta(hours=1), "change", "application", "updated", "Application Discord updated", entity="Discord", source="apps", event_id="discord-update"),
        ]
        request = IncidentRequest("DiffTrail started having issues", now, now, "application", 7)

        hypotheses = rank_candidates(events, request)

        self.assertEqual(hypotheses[0].event.event_id, "discord-update")
        self.assertFalse(any(item.signal == "entity relevance" for item in hypotheses[0].evidence))
