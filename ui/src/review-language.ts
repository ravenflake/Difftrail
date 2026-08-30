import type { AssessmentState, Incident, SupportLevel } from "./types";

export function supportLabel(level: SupportLevel | undefined): string {
  if (level === "strong") return "Strong support";
  if (level === "moderate") return "Moderate support";
  if (level === "weak") return "Weak support";
  return "No ranked lead";
}

export function assessmentLabel(incident: Incident): string {
  const labels: Record<AssessmentState, string> = {
    candidate_found: "Lead to review",
    insufficient_evidence: "Weak evidence",
    no_recent_changes: "No recorded changes",
    limited_coverage: "Limited coverage",
  };
  return labels[incident.assessment || "insufficient_evidence"];
}

export function feedbackLabel(outcome: Incident["feedback"]["outcome"]): string {
  if (outcome === "helpful") return "Useful lead";
  if (outcome === "not_helpful") return "Not helpful";
  if (outcome === "unsure") return "Still checking";
  return "Not reviewed";
}
