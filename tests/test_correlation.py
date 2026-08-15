import unittest
from datetime import timedelta

from difftrail.correlation import assess_investigation, infer_subsystem, investigation_summary, rank_candidates
from difftrail.models import Event, IncidentRequest, utc_now


class CorrelationTests(unittest.TestCase):
    def test_bulk_per_user_service_refresh_is_excluded_with_an_honest_reason(self) -> None:
        now = utc_now()
        refresh = Event(
            now - timedelta(hours=1), "change", "startup", "refreshed",
            "Windows per-user services refreshed (12 instances)", source="services",
            details={"refresh_kind": "per_user_service_instances", "instance_count": 12},
        )
        request = IncidentRequest("Startup problem", now, now, "startup", 1)

        hypotheses = rank_candidates([refresh], request)
        assessment = assess_investigation(request, hypotheses, [refresh])

        self.assertEqual(hypotheses, [])
        self.assertEqual(assessment.state, "insufficient_evidence")
        self.assertTrue(any("per-user service refresh" in reason for reason in assessment.reasons))

    def test_broad_equal_score_tie_is_counted_and_downgrades_high_confidence(self) -> None:
        now = utc_now()
        changes = [
            Event(now - timedelta(hours=1), "change", "graphics", "updated", f"Display driver {index}", source="drivers", event_id=f"tie-{index}")
            for index in range(3)
        ]
        symptom = Event(now, "symptom", "graphics", "failure", "Display failure", source="eventlog")
        request = IncidentRequest("Display failure", now, now, "graphics", 1)

        hypotheses = rank_candidates([*changes, symptom], request)

        self.assertEqual({item.tie_count for item in hypotheses}, {3})
        self.assertEqual({item.confidence for item in hypotheses}, {"Medium"})

    def test_service_diagnostic_does_not_suggest_configuration_changes(self) -> None:
        now = utc_now()
        service = Event(now - timedelta(hours=1), "change", "startup", "added", "Service added", source="services")
        request = IncidentRequest("Startup problem", now, now, "startup", 1)
        hypothesis = rank_candidates([service], request)[0]
        self.assertNotIn("disable", hypothesis.safe_diagnostic["note"].casefold())
        self.assertIn("do not change", hypothesis.safe_diagnostic["note"].casefold())
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

    def test_equal_top_scores_are_marked_ambiguous_and_not_a_conclusion(self) -> None:
        now = utc_now()
        changes = [
            Event(
                now - timedelta(hours=2),
                "change",
                "graphics",
                "updated",
                f"Display driver {label} updated",
                source="drivers",
                event_id=label,
            )
            for label in ("a", "b", "c")
        ]
        symptom = Event(now - timedelta(minutes=30), "symptom", "graphics", "crash", "Game crash", source="eventlog")
        request = IncidentRequest("the graphics started crashing", now - timedelta(hours=1), now, "graphics", 7)

        hypotheses = rank_candidates([*changes, symptom], request)
        self.assertEqual(hypotheses[0].tie_count, 3)
        self.assertEqual(hypotheses[0].confidence, "Medium")
        assessment = assess_investigation(request, hypotheses, [*changes, symptom])
        self.assertEqual(assessment.state, "insufficient_evidence")
        self.assertIn("tied at the same score", " ".join(assessment.reasons))

    def test_individual_service_events_are_not_suppressed_only_by_timestamp(self) -> None:
        now = utc_now()
        service_events = [
            Event(
                now - timedelta(minutes=2),
                "change",
                "startup",
                "added",
                f"Service {name}_c837b added",
                entity=f"{name}_c837b",
                source="services",
                event_id=name,
                details={
                    "key": f"{name}_c837b",
                    "before": None,
                    "after": {
                        "name": f"{name}_c837b",
                        "display_name": f"{name}_c837b",
                        "path": r"C:\Windows\System32\svchost.exe -k UnistackSvcGroup",
                    },
                },
            )
            for name in ("OneSyncSvc", "MessagingService", "UserDataSvc")
        ]
        symptom = Event(now - timedelta(minutes=1), "symptom", "application", "crash", "Application crash", source="eventlog")
        request = IncidentRequest("the application crashed", now, now, "application", 7)

        hypotheses = rank_candidates([*service_events, symptom], request)
        self.assertEqual(len(hypotheses), 3)
        self.assertEqual({item.tie_count for item in hypotheses}, {3})
        assessment = assess_investigation(request, hypotheses, [*service_events, symptom])
        self.assertEqual(assessment.state, "insufficient_evidence")
        self.assertNotIn("bulk Windows per-user service refresh", " ".join(assessment.reasons))
        self.assertIn("tied at the same score", " ".join(assessment.reasons))

    def test_per_user_service_candidate_uses_safe_review_language(self) -> None:
        now = utc_now()
        service = Event(
            now - timedelta(hours=1),
            "change",
            "startup",
            "added",
            "Service OneSyncSvc_c837b added",
            entity="OneSyncSvc_c837b",
            source="services",
            event_id="per-user-service",
            details={
                "after": {
                    "name": "OneSyncSvc_c837b",
                    "path": r"C:\Windows\System32\svchost.exe -k UnistackSvcGroup",
                }
            },
        )
        symptom = Event(now - timedelta(minutes=30), "symptom", "application", "crash", "Application crash", source="eventlog")
        request = IncidentRequest("the application crashed", now, now, "application", 7)

        hypothesis = rank_candidates([service, symptom], request)[0]
        self.assertIn("per-user service", hypothesis.next_action)
        self.assertNotIn("persistence entry", hypothesis.next_action)
        self.assertEqual(hypothesis.confidence, "Medium")

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
