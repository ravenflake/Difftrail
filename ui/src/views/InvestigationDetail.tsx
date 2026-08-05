import { useState } from "react";
import type { AssessmentState, Incident, Hypothesis } from "../types";
import { formatDateTime, relativeTime, subsystemLabel } from "../format";
import { Icon } from "../components/Icon";
import { EvidenceList } from "../components/EvidenceList";

interface Props {
  incident: Incident;
  onFeedback: (incidentId: string, outcome: "correct" | "incorrect" | "unknown", eventId?: string) => Promise<void>;
  onExport: (incidentId: string) => Promise<void>;
  exportBusy: boolean;
  exportError: string | null;
}

export function InvestigationDetail({ incident, onFeedback, onExport, exportBusy, exportError }: Props) {
  const [feedbackBusy, setFeedbackBusy] = useState(false);
  const [feedbackError, setFeedbackError] = useState<string | null>(null);
  const lead = incident.results[0];
  const assessment = incident.assessment || "candidate_found";

  async function giveFeedback(outcome: "correct" | "incorrect" | "unknown", eventId?: string) {
    setFeedbackBusy(true); setFeedbackError(null);
    try { await onFeedback(incident.id, outcome, eventId); } catch (reason) { setFeedbackError(reason instanceof Error ? reason.message : "Feedback could not be saved."); } finally { setFeedbackBusy(false); }
  }

  return (
    <div className="incident-detail-page">
      <section className="incident-heading">
        <div><span className="eyebrow">Investigation</span><h2>{incident.description}</h2><div className="heading-meta"><span>{subsystemLabel(incident.subsystem)}</span><span>·</span><span>Started {formatDateTime(incident.onset_start)}</span><span>·</span><span>{incident.lookback_days}-day lookback</span></div></div>
        <button type="button" className="button button-secondary button-small" onClick={() => void onExport(incident.id)} disabled={exportBusy}>{exportBusy ? "Preparing…" : "Export investigation"}</button>
      </section>
      <AssessmentBanner state={assessment} reasons={incident.assessment_reasons || []} />
      {exportError && <div className="form-error" role="alert"><Icon name="alert" size={14} /> {exportError}</div>}

      {!lead ? <div className="large-empty"><h3>{emptyTitle(assessment)}</h3><p>{emptyBody(assessment)}</p></div> : <>
        <section className={`lead-card confidence-border-${lead.confidence.toLowerCase()}`}>
          <div className="lead-card-top"><span className={`confidence-badge confidence-${lead.confidence.toLowerCase()}`}><span className="confidence-dot" />{lead.confidence} confidence</span><span className="rank-label">Top candidate</span></div>
          <div className="lead-card-body"><div className="lead-icon"><Icon name="spark" size={24} /></div><div><span className="eyebrow">{leadLabel(assessment)}</span><h3>{lead.event.title}</h3><p className="lead-subtitle">{lead.event.entity || subsystemLabel(lead.event.subsystem)} · {formatDateTime(lead.event.occurred_at)}</p></div></div>
          <div className="lead-divider" />
          <div className="why-grid"><div><span className="eyebrow">Why it is here</span><EvidenceList items={lead.evidence} /></div><div className="next-step"><span className="eyebrow">Next step</span><p>{lead.next_action}</p><button type="button" className="button button-tertiary button-small" onClick={() => copyText(lead.safe_diagnostic.target)}><Icon name="copy" size={14} /> Copy {lead.safe_diagnostic.label} target</button><small>{lead.safe_diagnostic.note}</small></div></div>
          {lead.counter_evidence.length > 0 && <div className="counter-block"><span className="eyebrow">Counter-evidence</span><EvidenceList items={lead.counter_evidence} counter /></div>}
        </section>

        <section className="feedback-panel panel"><h3>Was this useful?</h3><div className="feedback-actions">{incident.feedback.outcome ? <div className="feedback-recorded"><Icon name="check" size={15} /> Marked {incident.feedback.outcome}</div> : <><button type="button" className="button button-secondary" disabled={feedbackBusy} onClick={() => giveFeedback("incorrect")}><Icon name="close" size={15} /> Not this</button><button type="button" className="button button-secondary" disabled={feedbackBusy} onClick={() => giveFeedback("unknown")}><Icon name="clock" size={15} /> Not sure</button><button type="button" className="button button-primary" disabled={feedbackBusy} onClick={() => giveFeedback("correct", lead.event.id || undefined)}><Icon name="check" size={15} /> This helped</button></>}</div>{feedbackError && <div className="form-error" role="alert"><Icon name="alert" size={14} /> {feedbackError}</div>}</section>

        {incident.results.length > 1 && <section className="panel candidates-panel"><div className="section-heading"><div><h3>Other candidate changes</h3></div><span className="muted-count">{incident.results.length - 1} more</span></div><div className="candidate-list">{incident.results.slice(1).map((hypothesis, index) => <Candidate key={`${hypothesis.event.id}-${index}`} hypothesis={hypothesis} onFeedback={onFeedback} incidentId={incident.id} />)}</div></section>}
      </>}
    </div>
  );
}

function AssessmentBanner({ state, reasons }: { state: AssessmentState; reasons: string[] }) {
  const labels: Record<AssessmentState, { title: string; body: string }> = {
    candidate_found: { title: "A plausible candidate was found", body: "The evidence supports reviewing this change first, but it is not proof of causality." },
    insufficient_evidence: { title: "There is not enough evidence for a conclusion", body: "Difftrail found nearby changes, but the supporting signals are too weak or conflicted to call one the cause." },
    no_recent_changes: { title: "No recent changes were recorded", body: "The selected window contains no journaled change before the reported onset." },
    limited_coverage: { title: "The conclusion is limited by coverage", body: "Provider warnings or missing baselines mean the journal may not contain the relevant evidence." },
  };
  const copy = labels[state];
  return <section className={`assessment-banner assessment-${state}`} role="status"><div className="assessment-icon"><Icon name={state === "candidate_found" ? "spark" : "alert"} size={17} /></div><div><strong>{copy.title}</strong><p>{copy.body}</p>{reasons.length > 0 && <ul>{reasons.map((reason, index) => <li key={`${reason}-${index}`}>{reason}</li>)}</ul>}</div></section>;
}

function leadLabel(state: AssessmentState): string {
  if (state === "candidate_found") return "Most plausible recent change";
  if (state === "limited_coverage") return "Candidate, with limited coverage";
  return "Candidate, not a conclusion";
}

function emptyTitle(state: AssessmentState): string {
  if (state === "limited_coverage") return "The journal has limited coverage.";
  if (state === "no_recent_changes") return "No candidate changes yet.";
  return "No reliable candidate change yet.";
}

function emptyBody(state: AssessmentState): string {
  if (state === "limited_coverage") return "Run a clean scan and establish the missing baselines before relying on this investigation.";
  if (state === "no_recent_changes") return "The journal did not contain a change in the selected window.";
  return "The journal did not contain enough matching evidence to rank a likely cause.";
}

function Candidate({ hypothesis, onFeedback, incidentId }: { hypothesis: Hypothesis; onFeedback: Props["onFeedback"]; incidentId: string }) {
  const [open, setOpen] = useState(false);
  const [feedbackBusy, setFeedbackBusy] = useState(false);
  const [feedbackError, setFeedbackError] = useState<string | null>(null);

  async function giveFeedback() {
    if (feedbackBusy) return;
    setFeedbackBusy(true); setFeedbackError(null);
    try { await onFeedback(incidentId, "correct", hypothesis.event.id || undefined); } catch (reason) { setFeedbackError(reason instanceof Error ? reason.message : "Feedback could not be saved."); } finally { setFeedbackBusy(false); }
  }

  return <div className={`candidate ${open ? "is-open" : ""}`}><button type="button" className="candidate-toggle" onClick={() => setOpen((value) => !value)} aria-expanded={open}><span className={`confidence-mini confidence-${hypothesis.confidence.toLowerCase()}`}>{hypothesis.confidence}</span><span className="candidate-copy"><strong>{hypothesis.event.title}</strong><small>{subsystemLabel(hypothesis.event.subsystem)} · {relativeTime(hypothesis.event.occurred_at)}</small></span><Icon name="chevron" size={15} className={open ? "rotated" : ""} /></button>{open && <div className="candidate-body"><EvidenceList items={hypothesis.evidence} />{hypothesis.counter_evidence.length > 0 && <EvidenceList items={hypothesis.counter_evidence} counter />}<button type="button" className="quiet-link" disabled={feedbackBusy} aria-busy={feedbackBusy} onClick={() => void giveFeedback()}>{feedbackBusy ? "Saving feedback..." : "Mark this as the useful cause"} <Icon name={feedbackBusy ? "clock" : "arrow"} size={14} /></button>{feedbackError && <div className="form-error" role="alert"><Icon name="alert" size={14} /> {feedbackError}</div>}</div>}</div>;
}

async function copyText(value: string) {
  try { await navigator.clipboard.writeText(value); } catch { /* Clipboard permissions are optional. */ }
}
