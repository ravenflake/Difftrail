import { FormEvent, useState } from "react";
import type { InvestigationInput, InvestigationResponse } from "../types";
import { Icon } from "../components/Icon";
import { subsystemLabel, subsystemOptions } from "../subsystems";

interface Props {
  busy: boolean;
  connected: boolean;
  onInvestigate: (input: InvestigationInput) => Promise<InvestigationResponse>;
}

export function InvestigateView({ busy, connected, onInvestigate }: Props) {
  const [description, setDescription] = useState("");
  const [subsystem, setSubsystem] = useState("general");
  const [lookback, setLookback] = useState("7");
  const [onset, setOnset] = useState("");
  const [affectedEntity, setAffectedEntity] = useState("");
  const [suspectedChange, setSuspectedChange] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  async function submit(event: FormEvent) {
    event.preventDefault();
    if (!description.trim()) { setError("Describe the problem in a sentence first."); return; }
    setError(null);
    setSubmitting(true);
    try {
      await onInvestigate({
        description: description.trim(),
        subsystem: subsystem === "general" ? undefined : subsystem,
        onset: localDateTimeToUtcIso(onset),
        lookback_days: Number(lookback),
        affected_entity: affectedEntity.trim() || undefined,
        suspected_change: suspectedChange.trim() || undefined,
      });
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "The evidence review could not be completed.");
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="page-stack investigate-page">
      <section className="view-header"><h2>Review a problem</h2><p>Compare journaled changes with a symptom window. Difftrail ranks leads with fixed rules; it does not diagnose a cause.</p></section>
      <section className="review-method" aria-label="How evidence review works">
        <div><span className="review-method-number">1</span><p><strong>You set the problem window.</strong> A precise onset helps exclude unrelated changes.</p></div>
        <div><span className="review-method-number">2</span><p><strong>Difftrail ranks recorded changes.</strong> Timing, area, symptoms, and counter-signals affect order.</p></div>
        <div><span className="review-method-number">3</span><p><strong>You verify the leads.</strong> Results are evidence to inspect, never proof or automatic remediation.</p></div>
      </section>
      <p className="review-method-note"><Icon name="shield" size={14} /> No AI reads this description. With automatic area matching, predefined keywords select a Windows area; optional names are compared as normalized text. Timing and recorded evidence do the rest.</p>
      <form className="investigation-form-wrap" onSubmit={submit}>
        <section className="panel investigation-form">
          <div className="form-step"><span className="step-number">01</span><div><h3>Describe what you observed</h3><p>Include the affected app or device and what failed. Avoid guessing the cause here.</p></div></div>
          <textarea autoFocus value={description} maxLength={1000} onChange={(event) => setDescription(event.target.value)} placeholder="e.g. My games started crashing after launch" rows={5} aria-label="Problem description" />
          <div className="example-row"><span>Examples</span><button type="button" onClick={() => setDescription("My graphics started failing after an update")}>Graphics failure</button><button type="button" onClick={() => setDescription("My USB headset stopped working")}>Audio device</button><button type="button" onClick={() => setDescription("An app started crashing on launch")}>App crash</button></div>
          <div className="form-divider" />
          <div className="form-step"><span className="step-number">02</span><div><h3>Narrow the evidence window</h3><p>The onset time and affected area are the strongest ways to reduce unrelated changes.</p></div></div>
          <div className="form-grid">
            <label className="field-label"><span>Affected area <em>optional</em></span><select value={subsystem} onChange={(event) => setSubsystem(event.target.value)}>{subsystemOptions.map((option) => <option key={option} value={option}>{option === "general" ? "Match predefined keywords" : subsystemLabel(option)}</option>)}</select></label>
            <label className="field-label"><span>Look back</span><select value={lookback} onChange={(event) => setLookback(event.target.value)}><option value="1">24 hours</option><option value="3">3 days</option><option value="7">7 days</option><option value="14">14 days</option><option value="30">30 days</option></select></label>
          </div>
          <div className="form-grid context-grid">
            <label className="field-label"><span>Affected app, process, or device <em>optional</em></span><input value={affectedEntity} maxLength={200} onChange={(event) => setAffectedEntity(event.target.value)} placeholder="e.g. explorer.exe or USB headset" /><small>Exact names help match recorded entities.</small></label>
            <label className="field-label"><span>Change you want to check <em>optional</em></span><input value={suspectedChange} maxLength={200} onChange={(event) => setSuspectedChange(event.target.value)} placeholder="e.g. display driver update" /><small>This adds a ranking hint; it does not confirm your suspicion.</small></label>
          </div>
          <label className="field-label onset-field"><span>When did you first notice it? <em>recommended</em></span><input type="datetime-local" value={onset} max={currentLocalDateTime()} onChange={(event) => setOnset(event.target.value)} /><small>Leave blank only if it began just now. Difftrail searches changes before this time.</small></label>
          {error && <div className="form-error" role="alert"><Icon name="alert" size={15} /> {error}</div>}
          <button type="submit" className="button button-primary investigate-submit" title={connected ? undefined : "Connect the local journal to review recorded evidence"} disabled={!connected || busy || submitting}>{busy || submitting ? <><span className="button-spinner" /> Comparing recorded evidence...</> : <>Find related changes <Icon name="arrow" size={16} /></>}</button>
        </section>
      </form>
    </div>
  );
}

function localDateTimeToUtcIso(value: string): string | undefined {
  if (!value) return undefined;
  const localDate = new Date(value);
  return Number.isNaN(localDate.getTime()) ? undefined : localDate.toISOString();
}

function currentLocalDateTime(): string {
  const now = new Date();
  const local = new Date(now.getTime() - now.getTimezoneOffset() * 60_000);
  return local.toISOString().slice(0, 16);
}
