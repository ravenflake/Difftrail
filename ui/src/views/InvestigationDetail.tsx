import { useEffect, useRef, useState } from "react";
import type { AssessmentState, FeedbackReason, Incident, Hypothesis } from "../types";
import { formatDateTime, relativeTime, sourceLabel, subsystemLabel } from "../format";
import { feedbackLabel, supportLabel } from "../review-language";
import { Icon } from "../components/Icon";
import { EvidenceList } from "../components/EvidenceList";

type ReviewOutcome = Exclude<Incident["feedback"]["outcome"], null>;
const LEAD_OUTCOMES = new Set<ReviewOutcome>(["confirmed_cause", "useful_lead", "irrelevant_lead"]);
const FEEDBACK_REASON_OPTIONS: Record<ReviewOutcome, Array<{ value: FeedbackReason; label: string }>> = {
  confirmed_cause: [
    { value: "reproduced", label: "Reproduced through controlled testing" },
    { value: "resolved_after_change", label: "Resolved after the cause was changed" },
    { value: "independent_confirmation", label: "Confirmed by an independent diagnostic or source" },
    { value: "other", label: "Verified another way" },
  ],
  useful_lead: [
    { value: "narrowed_investigation", label: "Narrowed the investigation" },
    { value: "guided_diagnostic", label: "Led to a useful diagnostic check" },
    { value: "ruled_out_candidate", label: "Helped rule out a candidate" },
    { value: "other", label: "Useful another way" },
  ],
  irrelevant_lead: [
    { value: "disproved_by_testing", label: "Testing disproved the lead" },
    { value: "unrelated_to_symptom", label: "The change was unrelated to the symptom" },
    { value: "timing_only", label: "Timing was the only apparent connection" },
    { value: "other", label: "Irrelevant for another reason" },
  ],
  uncaptured_cause: [
    { value: "before_first_baseline", label: "Cause occurred before the first baseline" },
    { value: "between_scans", label: "Cause occurred between scans" },
    { value: "unsupported_source", label: "Relevant evidence source is not collected" },
    { value: "provider_gap", label: "A provider warning or failed read left a gap" },
    { value: "outside_review_window", label: "Cause was outside the selected review window" },
    { value: "other", label: "Cause was missing for another reason" },
  ],
  unknown: [
    { value: "still_investigating", label: "Still investigating" },
    { value: "insufficient_information", label: "Not enough information to decide" },
    { value: "other", label: "Unknown for another reason" },
  ],
};

interface Props {
  incident: Incident;
  connected: boolean;
  onFeedback: (incidentId: string, outcome: ReviewOutcome, reason: FeedbackReason, eventId?: string) => Promise<void>;
  onDelete: (incidentId: string) => Promise<void>;
  onExport: (incidentId: string) => Promise<void>;
  exportBusy: boolean;
  exportError: string | null;
  deleteBusy: boolean;
  deleteError: string | null;
}

export function InvestigationDetail({ incident, connected, onFeedback, onDelete, onExport, exportBusy, exportError, deleteBusy, deleteError }: Props) {
  const [feedbackBusy, setFeedbackBusy] = useState(false);
  const [feedbackError, setFeedbackError] = useState<string | null>(null);
  const initialOutcome = incident.feedback.outcome || "unknown";
  const [feedbackOutcome, setFeedbackOutcome] = useState<ReviewOutcome>(initialOutcome);
  const [feedbackEventId, setFeedbackEventId] = useState(incident.feedback.event_id || incident.results[0]?.event.id || "");
  const [feedbackReason, setFeedbackReason] = useState<FeedbackReason>(() => initialFeedbackReason(initialOutcome, incident.feedback.reason));
  const [removeConfirming, setRemoveConfirming] = useState(false);
  const [copyState, setCopyState] = useState<"idle" | "copied" | "failed">("idle");
  const copyResetTimer = useRef<number | null>(null);
  const lead = incident.results[0];
  const assessment = incident.assessment || "insufficient_evidence";
  const leadTieCount = lead ? Math.max(1, lead.tie_count || 1) : 1;
  const leadSupport = lead?.support_level;
  const feedbackEvent = incident.feedback.event_id
    ? incident.results.find((item) => item.event.id === incident.feedback.event_id)?.event
    : undefined;
  const coverageReasons = uniqueReasons([
    ...(incident.assessment_reasons || []),
    ...(incident.coverage?.reasons || []),
    ...(incident.coverage?.uninitialized_sources?.length
      ? [`No confirmed source read by onset: ${incident.coverage.uninitialized_sources.join(", ")}.`]
      : []),
    ...(incident.coverage?.warning_sources?.length
      ? [`Source warnings by onset: ${incident.coverage.warning_sources.join(", ")}.`]
      : []),
  ]);

  useEffect(() => () => {
    if (copyResetTimer.current !== null) window.clearTimeout(copyResetTimer.current);
  }, []);

  useEffect(() => {
    const outcome = incident.feedback.outcome || "unknown";
    setFeedbackOutcome(outcome);
    setFeedbackEventId(incident.feedback.event_id || incident.results[0]?.event.id || "");
    setFeedbackReason(initialFeedbackReason(outcome, incident.feedback.reason));
  }, [incident.feedback.outcome, incident.feedback.event_id, incident.feedback.reason, incident.feedback.recorded_at, incident.results]);

  function changeFeedbackOutcome(outcome: ReviewOutcome) {
    setFeedbackOutcome(outcome);
    setFeedbackReason(FEEDBACK_REASON_OPTIONS[outcome][0].value);
    if (LEAD_OUTCOMES.has(outcome) && !feedbackEventId) setFeedbackEventId(lead?.event.id || "");
  }

  async function giveFeedback() {
    setFeedbackBusy(true);
    setFeedbackError(null);
    try {
      await onFeedback(
        incident.id,
        feedbackOutcome,
        feedbackReason,
        LEAD_OUTCOMES.has(feedbackOutcome) ? feedbackEventId : undefined,
      );
    } catch (reason) {
      setFeedbackError(reason instanceof Error ? reason.message : "Feedback could not be saved.");
    } finally {
      setFeedbackBusy(false);
    }
  }

  async function removeReview() {
    try {
      await onDelete(incident.id);
      setRemoveConfirming(false);
    } catch {
      // The parent owns the error message so it can also report refresh failures.
    }
  }

  async function copyDiagnosticTarget() {
    if (!lead) return;
    const copied = await copyText(lead.safe_diagnostic.target);
    setCopyState(copied ? "copied" : "failed");
    if (copyResetTimer.current !== null) window.clearTimeout(copyResetTimer.current);
    if (copied) {
      copyResetTimer.current = window.setTimeout(() => {
        setCopyState("idle");
        copyResetTimer.current = null;
      }, 1800);
    }
  }

  return (
    <div className="incident-detail-page">
      <section className="incident-heading">
        <div>
          <span className="eyebrow">Evidence review</span>
          <h2>{incident.description}</h2>
          <div className="heading-meta"><span>{subsystemLabel(incident.subsystem)}</span><span>·</span><span>Onset {formatDateTime(incident.onset_start)}</span><span>·</span><span>{incident.lookback_days}-day lookback</span></div>
          {(incident.affected_entity || incident.suspected_change) && <div className="heading-context">{incident.affected_entity && <span><strong>Affected:</strong> {incident.affected_entity}</span>}{incident.suspected_change && <span><strong>User-provided lead:</strong> {incident.suspected_change}</span>}</div>}
        </div>
        <div className="incident-heading-actions">
          <button type="button" className="button button-secondary button-small" title={connected ? undefined : "Connect the local journal to export this evidence review"} onClick={() => void onExport(incident.id)} disabled={!connected || exportBusy}>{exportBusy ? "Preparing…" : "Export evidence report"}</button>
          {!removeConfirming
            ? <button type="button" className="button button-danger button-small" title={connected ? undefined : "Connect the local journal to remove this review"} onClick={() => setRemoveConfirming(true)} disabled={!connected || deleteBusy}>Remove review</button>
            : <div className="incident-remove-confirm" role="group" aria-label="Confirm evidence review removal"><span>Remove this saved review?</span><button type="button" className="button button-danger button-small" onClick={() => void removeReview()} disabled={deleteBusy} aria-busy={deleteBusy}>{deleteBusy ? "Removing..." : "Confirm remove"}</button><button type="button" className="button button-secondary button-small" onClick={() => setRemoveConfirming(false)} disabled={deleteBusy}>Cancel</button></div>}
        </div>
      </section>

      <AssessmentBanner state={assessment} reasons={coverageReasons} />
      {exportError && <div className="form-error" role="alert"><Icon name="alert" size={14} /> {exportError}</div>}
      {deleteError && <div className="form-error" role="alert"><Icon name="alert" size={14} /> {deleteError}</div>}

      {!lead ? <EmptyResult state={assessment} /> : <>
        <section className={`lead-card support-border-${leadSupport || "none"}`}>
          <div className="lead-card-top">
            <span className={`support-badge support-${leadSupport || "none"}`} title="Rule-based evidence support, not probability"><span className="support-dot" />{supportLabel(leadSupport)}</span>
            <span className="rank-label">{leadTieCount > 1 ? `Ranked first · tied with ${leadTieCount - 1} other${leadTieCount === 2 ? "" : "s"}` : "Ranked first for review"}</span>
          </div>
          <div className="lead-card-body"><div className="lead-icon"><Icon name="change" size={24} /></div><div><span className="eyebrow">{leadLabel(assessment, leadTieCount)}</span><h3>{lead.event.title}</h3><p className="lead-subtitle">{lead.event.entity || subsystemLabel(lead.event.subsystem)} · detected {formatDateTime(lead.event.occurred_at)}</p>{leadTieCount > 1 && <small className="candidate-ambiguity">These recorded changes are tied by the fixed ranking rules. The journal does not distinguish one as a unique lead.</small>}</div></div>

          <div className="lead-facts" role="group" aria-label="What the journal knows about this lead">
            <LeadFact label="Recorded source" value={sourceLabel(lead.event.source)} />
            <LeadFact label="Latest pre-onset scan" value={incident.coverage.latest_scan_at ? formatDateTime(incident.coverage.latest_scan_at) : "Not confirmed"} />
            <LeadFact label="Signals" value={`${lead.evidence.length} supporting · ${lead.counter_evidence.length} counter`} />
          </div>

          <div className="why-grid">
            <div><span className="eyebrow">Supporting signals</span><EvidenceList items={lead.evidence} />{!lead.evidence.length && <p className="evidence-empty">No supporting signal details were returned.</p>}</div>
            <div className="next-step"><span className="eyebrow">Safe next check</span><p>{lead.next_action}</p><button type="button" className="button button-tertiary button-small" onClick={() => void copyDiagnosticTarget()}><Icon name={copyState === "copied" ? "check" : "copy"} size={14} /> {copyState === "copied" ? "Target copied" : `Copy ${lead.safe_diagnostic.label} target`}</button><small>{lead.safe_diagnostic.note} Verify the lead before changing anything.</small>{copyState === "failed" && <small className="copy-error" role="alert">Clipboard access was unavailable. Open {lead.safe_diagnostic.label} manually.</small>}</div>
          </div>

          <div className="counter-block"><span className="eyebrow">What weakens this lead</span>{lead.counter_evidence.length ? <EvidenceList items={lead.counter_evidence} counter /> : <p className="counter-empty">No counter-signal was recorded. That absence does not confirm a relationship.</p>}</div>
          <div className="causality-boundary"><Icon name="shield" size={16} /><p><strong>Not established:</strong> whether this change caused the symptom, whether an uncollected change mattered, or whether changing it would fix the problem.</p></div>
        </section>
      </>}

        <section className="feedback-panel panel">
          <div>
            <h3>What was the real investigation outcome?</h3>
            <p>Choose only what you verified. Difftrail records the selected rank and a structured reason for local validation; it never turns correlation into confirmation.</p>
            {incident.feedback.outcome && <div className="feedback-recorded" role="status"><Icon name="check" size={15} /> Saved: {feedbackLabel(incident.feedback.outcome)}{feedbackEvent ? ` — ${feedbackEvent.title}` : ""}{incident.feedback.rank ? ` at rank #${incident.feedback.rank}` : ""}. You can update this answer.</div>}
          </div>
          <div className="feedback-actions feedback-form">
            <label><span>Outcome</span><select value={feedbackOutcome} onChange={(event) => changeFeedbackOutcome(event.target.value as ReviewOutcome)} disabled={!connected || feedbackBusy}><option value="confirmed_cause" disabled={!lead}>Confirmed cause</option><option value="useful_lead" disabled={!lead}>Useful lead</option><option value="irrelevant_lead" disabled={!lead}>Irrelevant lead</option><option value="uncaptured_cause">Cause was not captured</option><option value="unknown">Unknown outcome</option></select></label>
            {LEAD_OUTCOMES.has(feedbackOutcome) && <label><span>Ranked lead</span><select value={feedbackEventId} onChange={(event) => setFeedbackEventId(event.target.value)} disabled={!connected || feedbackBusy}>{incident.results.map((result, index) => <option key={result.event.id || index} value={result.event.id || ""}>#{index + 1} {result.event.title}</option>)}</select></label>}
            <label><span>Why</span><select value={feedbackReason} onChange={(event) => setFeedbackReason(event.target.value as FeedbackReason)} disabled={!connected || feedbackBusy}>{FEEDBACK_REASON_OPTIONS[feedbackOutcome].map((option) => <option key={option.value} value={option.value}>{option.label}</option>)}</select></label>
            <button type="button" className="button button-primary" title={connected ? undefined : "Connect the local journal to save feedback"} disabled={!connected || feedbackBusy || (LEAD_OUTCOMES.has(feedbackOutcome) && !feedbackEventId)} onClick={() => void giveFeedback()}><Icon name={feedbackBusy ? "clock" : "check"} size={15} /> {feedbackBusy ? "Saving…" : "Save outcome"}</button>
          </div>
          {feedbackError && <div className="form-error" role="alert"><Icon name="alert" size={14} /> {feedbackError}</div>}
        </section>

        {incident.results.length > 1 && <section className="panel candidates-panel"><div className="section-heading"><div><h3>Other recorded changes to compare</h3><span className="section-subtitle">Lower ranking means weaker rule-based support, not that a change is cleared.</span></div><span className="muted-count">{incident.results.length - 1} more</span></div><div className="candidate-list">{incident.results.slice(1).map((hypothesis, index) => <Candidate key={`${hypothesis.event.id}-${index}`} hypothesis={hypothesis} rank={index + 2} selectedFeedbackId={incident.feedback.event_id} />)}</div></section>}
    </div>
  );
}

function AssessmentBanner({ state, reasons }: { state: AssessmentState; reasons: string[] }) {
  const labels: Record<AssessmentState, { title: string; body: string }> = {
    candidate_found: { title: "A recorded change is worth reviewing first", body: "Fixed ranking rules found stronger supporting signals for this lead. It is a starting point, not a diagnosis." },
    insufficient_evidence: { title: "No recorded change is sufficiently supported", body: "Nearby changes may still be useful context, but their signals are weak, tied, or contradicted." },
    no_recent_changes: { title: "No changes were recorded in this window", body: "The journal has no state difference before the reported onset within the selected lookback." },
    limited_coverage: { title: "Evidence coverage is incomplete", body: "Provider warnings or unconfirmed source reads mean the relevant change may not be in the journal." },
  };
  const copy = labels[state];
  return <section className={`assessment-banner assessment-${state}`} role="status"><div className="assessment-icon"><Icon name={state === "candidate_found" ? "change" : "alert"} size={17} /></div><div><strong>{copy.title}</strong><p>{copy.body}</p>{reasons.length > 0 && <ul aria-label="Assessment limits">{reasons.map((reason, index) => <li key={`${reason}-${index}`}>{reason}</li>)}</ul>}</div></section>;
}

function EmptyResult({ state }: { state: AssessmentState }) {
  return <div className="large-empty result-empty"><div className="empty-icon"><Icon name={state === "limited_coverage" ? "alert" : "timeline"} size={22} /></div><h3>{emptyTitle(state)}</h3><p>{emptyBody(state)}</p><div className="empty-next"><strong>What to do next</strong><span>{emptyNext(state)}</span></div></div>;
}

function LeadFact({ label, value }: { label: string; value: string }) {
  return <div><span>{label}</span><strong>{value}</strong></div>;
}

function leadLabel(state: AssessmentState, tieCount: number): string {
  if (tieCount > 1) return "Tied lead to compare";
  if (state === "candidate_found") return "Recorded change to review first";
  if (state === "limited_coverage") return "Lead ranked with incomplete coverage";
  return "Nearby recorded change";
}

function emptyTitle(state: AssessmentState): string {
  if (state === "limited_coverage") return "The journal cannot support a reliable lead.";
  if (state === "no_recent_changes") return "Nothing changed in the recorded window.";
  return "No lead stands out from the recorded evidence.";
}

function emptyBody(state: AssessmentState): string {
  if (state === "limited_coverage") return "An unconfirmed source read or provider warning leaves a gap around this problem.";
  if (state === "no_recent_changes") return "This does not mean the PC did not change—only that Difftrail recorded no matching state difference in the selected window.";
  return "Nearby changes were absent, tied, weakly related, or outweighed by counter-signals.";
}

function emptyNext(state: AssessmentState): string {
  if (state === "limited_coverage") return "Review Collection & system, run another completed scan, and use future evidence cautiously until the relevant sources have valid baselines.";
  if (state === "no_recent_changes") return "If the onset may be earlier, start another review with a wider lookback. Scans cannot recover changes that were never recorded.";
  return "Inspect the evidence timeline around the onset or narrow the problem with an exact app, device, area, and time.";
}

function Candidate({ hypothesis, rank, selectedFeedbackId }: { hypothesis: Hypothesis; rank: number; selectedFeedbackId: string | null }) {
  const [open, setOpen] = useState(false);
  const selected = Boolean(hypothesis.event.id && selectedFeedbackId === hypothesis.event.id);
  return <div className={`candidate ${open ? "is-open" : ""} ${selected ? "is-feedback-selected" : ""}`}><button type="button" className="candidate-toggle" onClick={() => setOpen((value) => !value)} aria-expanded={open}><span className="candidate-rank">#{rank}</span><span className={`support-mini support-${hypothesis.support_level}`} title="Rule-based evidence support, not probability">{supportLabel(hypothesis.support_level)}</span><span className="candidate-copy"><strong>{hypothesis.event.title}</strong><small>{subsystemLabel(hypothesis.event.subsystem)} · detected {relativeTime(hypothesis.event.occurred_at)}{selected ? " · included in saved outcome" : ""}</small></span><Icon name="chevron" size={15} className={open ? "rotated" : ""} /></button>{open && <div className="candidate-body"><div><span className="eyebrow">Supporting signals</span><EvidenceList items={hypothesis.evidence} /></div><div className="candidate-counter"><span className="eyebrow">Counter-signals</span>{hypothesis.counter_evidence.length ? <EvidenceList items={hypothesis.counter_evidence} counter /> : <p className="counter-empty">None recorded; this does not confirm a relationship.</p>}</div><p className="candidate-limit">This ranking orders what to inspect. It is not a probability or proof of cause.</p></div>}</div>;
}

function initialFeedbackReason(outcome: ReviewOutcome, saved: FeedbackReason | null): FeedbackReason {
  if (saved && saved !== "legacy_unspecified" && FEEDBACK_REASON_OPTIONS[outcome].some((option) => option.value === saved)) return saved;
  return FEEDBACK_REASON_OPTIONS[outcome][0].value;
}

function uniqueReasons(reasons: string[]): string[] {
  return [...new Set(reasons.map((reason) => reason.trim()).filter(Boolean))];
}

async function copyText(value: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(value);
    return true;
  } catch {
    return false;
  }
}
