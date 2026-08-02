import { useState } from "react";
import type { Incident, Hypothesis } from "../types";
import { formatDateTime, relativeTime, subsystemLabel } from "../format";
import { Icon } from "../components/Icon";
import { EvidenceList } from "../components/EvidenceList";

interface Props {
  incident: Incident;
  onFeedback: (incidentId: string, outcome: "correct" | "incorrect" | "unknown", eventId?: string) => Promise<void>;
}

export function InvestigationDetail({ incident, onFeedback }: Props) {
  const [feedbackBusy, setFeedbackBusy] = useState(false);
  const [feedbackError, setFeedbackError] = useState<string | null>(null);
  const lead = incident.results[0];

  async function giveFeedback(outcome: "correct" | "incorrect" | "unknown", eventId?: string) {
    setFeedbackBusy(true); setFeedbackError(null);
    try { await onFeedback(incident.id, outcome, eventId); } catch (reason) { setFeedbackError(reason instanceof Error ? reason.message : "Feedback could not be saved."); } finally { setFeedbackBusy(false); }
  }

  return (
    <div className="incident-detail-page">
      <section className="incident-heading">
        <div><span className="eyebrow">Investigation · {relativeTime(incident.created_at)}</span><h2>{incident.description}</h2><div className="heading-meta"><span>{subsystemLabel(incident.subsystem)}</span><span>·</span><span>Started {formatDateTime(incident.onset_start)}</span><span>·</span><span>{incident.lookback_days}-day lookback</span></div></div>
        <div className="method-note"><Icon name="shield" size={15} /> Deterministic evidence signals</div>
      </section>

      {!lead ? <div className="large-empty"><div className="empty-icon"><Icon name="timeline" size={22} /></div><h3>No candidate changes yet.</h3><p>The journal did not contain a change in the selected window that Difftrail could connect to this problem.</p></div> : <>
        <section className={`lead-card confidence-border-${lead.confidence.toLowerCase()}`}>
          <div className="lead-card-top"><span className={`confidence-badge confidence-${lead.confidence.toLowerCase()}`}><span className="confidence-dot" />{lead.confidence} confidence</span><span className="rank-label">Lead candidate</span></div>
          <div className="lead-card-body"><div className="lead-icon"><Icon name="spark" size={24} /></div><div><span className="eyebrow">Most plausible recent change</span><h3>{lead.event.title}</h3><p className="lead-subtitle">{lead.event.entity || subsystemLabel(lead.event.subsystem)} · {formatDateTime(lead.event.occurred_at)}</p></div></div>
          <div className="lead-divider" />
          <div className="why-grid"><div><span className="eyebrow">Why it is here</span><EvidenceList items={lead.evidence} /></div><div className="next-step"><span className="eyebrow">Safest next step</span><p>{lead.next_action}</p><button type="button" className="button button-tertiary button-small" onClick={() => copyText(lead.safe_diagnostic.target)}><Icon name="copy" size={14} /> Copy {lead.safe_diagnostic.label} target</button><small>{lead.safe_diagnostic.note}</small></div></div>
          {lead.counter_evidence.length > 0 && <div className="counter-block"><span className="eyebrow">What weakens the case</span><EvidenceList items={lead.counter_evidence} counter /></div>}
        </section>

        <section className="feedback-panel panel"><div><span className="eyebrow">Close the loop</span><h3>Was this useful?</h3><p>Your label stays local and helps measure whether the ranking is useful over time.</p></div><div className="feedback-actions">{incident.feedback.outcome ? <div className="feedback-recorded"><Icon name="check" size={15} /> Marked {incident.feedback.outcome}</div> : <><button type="button" className="button button-secondary" disabled={feedbackBusy} onClick={() => giveFeedback("incorrect")}><Icon name="close" size={15} /> Not this</button><button type="button" className="button button-secondary" disabled={feedbackBusy} onClick={() => giveFeedback("unknown")}><Icon name="clock" size={15} /> Not sure</button><button type="button" className="button button-primary" disabled={feedbackBusy} onClick={() => giveFeedback("correct", lead.event.id || undefined)}><Icon name="check" size={15} /> This helped</button></>}</div>{feedbackError && <div className="form-error" role="alert"><Icon name="alert" size={14} /> {feedbackError}</div>}</section>

        {incident.results.length > 1 && <section className="panel candidates-panel"><div className="section-heading"><div><span className="eyebrow">The rest of the window</span><h3>Other candidate changes</h3></div><span className="muted-count">{incident.results.length - 1} more</span></div><div className="candidate-list">{incident.results.slice(1).map((hypothesis, index) => <Candidate key={`${hypothesis.event.id}-${index}`} hypothesis={hypothesis} onFeedback={onFeedback} incidentId={incident.id} />)}</div></section>}
      </>}
    </div>
  );
}

function Candidate({ hypothesis, onFeedback, incidentId }: { hypothesis: Hypothesis; onFeedback: Props["onFeedback"]; incidentId: string }) {
  const [open, setOpen] = useState(false);
  const [feedbackBusy, setFeedbackBusy] = useState(false);
  const [feedbackError, setFeedbackError] = useState<string | null>(null);

  async function giveFeedback() {
    if (feedbackBusy) return;
    setFeedbackBusy(true); setFeedbackError(null);
    try {
      await onFeedback(incidentId, "correct", hypothesis.event.id || undefined);
    } catch (reason) {
      setFeedbackError(reason instanceof Error ? reason.message : "Feedback could not be saved.");
    } finally {
      setFeedbackBusy(false);
    }
  }

  return <div className={`candidate ${open ? "is-open" : ""}`}><button type="button" className="candidate-toggle" onClick={() => setOpen((value) => !value)} aria-expanded={open}><span className={`confidence-mini confidence-${hypothesis.confidence.toLowerCase()}`}>{hypothesis.confidence}</span><span className="candidate-copy"><strong>{hypothesis.event.title}</strong><small>{subsystemLabel(hypothesis.event.subsystem)} · {relativeTime(hypothesis.event.occurred_at)}</small></span><Icon name="chevron" size={15} className={open ? "rotated" : ""} /></button>{open && <div className="candidate-body"><EvidenceList items={hypothesis.evidence} />{hypothesis.counter_evidence.length > 0 && <EvidenceList items={hypothesis.counter_evidence} counter />}<button type="button" className="quiet-link" disabled={feedbackBusy} aria-busy={feedbackBusy} onClick={() => void giveFeedback()}>{feedbackBusy ? "Saving feedback…" : "Mark this as the useful cause"} <Icon name={feedbackBusy ? "clock" : "arrow"} size={14} /></button>{feedbackError && <div className="form-error" role="alert"><Icon name="alert" size={14} /> {feedbackError}</div>}</div>}</div>;
}

async function copyText(value: string) {
  try { await navigator.clipboard.writeText(value); } catch { /* Clipboard permissions are optional. */ }
}
