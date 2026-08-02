import unittest

from difftrail.validation import run_ground_truth_suite


class GroundTruthValidationTests(unittest.TestCase):
    def test_known_cause_suite_reports_top_one_and_false_positive_metrics(self) -> None:
        report = run_ground_truth_suite()
        self.assertTrue(report["passed"])
        self.assertEqual(report["top1_accuracy"], 1.0)
        self.assertEqual(report["top3_accuracy"], 1.0)
        self.assertEqual(report["no_false_high_rate"], 1.0)
        self.assertGreaterEqual(report["perturbation"]["top1_accuracy"], 0.95)

    def test_suite_contains_counter_and_missing_evidence_cases(self) -> None:
        report = run_ground_truth_suite()
        names = {scenario["name"] for scenario in report["scenarios"]}
        self.assertIn("counter-evidence-downgrades-confidence", names)
        self.assertIn("missing-symptom-evidence", names)
