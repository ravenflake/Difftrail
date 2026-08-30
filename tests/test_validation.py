import unittest

from difftrail.validation import run_ground_truth_suite


class GroundTruthValidationTests(unittest.TestCase):
    def test_expected_lead_suite_reports_ranking_and_false_support_metrics(self) -> None:
        report = run_ground_truth_suite()
        self.assertTrue(report["passed"])
        self.assertEqual(report["expected_lead_top1_rate"], 1.0)
        self.assertEqual(report["expected_lead_top3_rate"], 1.0)
        self.assertEqual(report["no_false_strong_support_rate"], 1.0)
        self.assertGreaterEqual(report["perturbation"]["expected_lead_top1_rate"], 0.95)

    def test_suite_contains_counter_and_missing_evidence_cases(self) -> None:
        report = run_ground_truth_suite()
        names = {scenario["name"] for scenario in report["scenarios"]}
        self.assertIn("counter-evidence-reduces-support", names)
        self.assertIn("missing-symptom-evidence", names)
