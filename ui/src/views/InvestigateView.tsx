import { FormEvent, useState } from "react";
import type { InvestigationInput, InvestigationResponse } from "../types";
import { Icon } from "../components/Icon";
import { subsystemLabel, subsystemOptions } from "../subsystems";

interface Props {
  busy: boolean;
  onInvestigate: (input: InvestigationInput) => Promise<InvestigationResponse>;
}

export function InvestigateView({ busy, onInvestigate }: Props) {
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
      setError(reason instanceof Error ? reason.message : "The investigation could not be completed.");
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="page-stack investigate-page">
      <section className="view-header"><h2>Investigate</h2><p>Describe a symptom to rank recent changes.</p></section>
      <form className="investigation-form-wrap" onSubmit={submit}>
        <section className="panel investigation-form">
          <div className="form-step"><span className="step-number">01</span><div><h3>Describe the symptom</h3><p>Keep it specific enough to connect to a subsystem.</p></div></div>
          <textarea autoFocus value={description} onChange={(event) => setDescription(event.target.value)} placeholder="e.g. My games started crashing after launch" rows={5} aria-label="Problem description" />
          <div className="example-row"><span>Examples</span><button type="button" onClick={() => setDescription("My graphics started failing after an update")}>Graphics failure</button><button type="button" onClick={() => setDescription("My USB headset stopped working")}>Audio device</button><button type="button" onClick={() => setDescription("An app started crashing on launch")}>App crash</button></div>
          <div className="form-divider" />
          <div className="form-step"><span className="step-number">02</span><div><h3>Set the context</h3><p>Choose an area and time window.</p></div></div>
          <div className="form-grid">
            <label className="field-label"><span>Area <em>optional</em></span><select value={subsystem} onChange={(event) => setSubsystem(event.target.value)}>{subsystemOptions.map((option) => <option key={option} value={option}>{option === "general" ? "Let Difftrail infer it" : subsystemLabel(option)}</option>)}</select></label>
            <label className="field-label"><span>Look back</span><select value={lookback} onChange={(event) => setLookback(event.target.value)}><option value="1">24 hours</option><option value="3">3 days</option><option value="7">7 days</option><option value="14">14 days</option><option value="30">30 days</option></select></label>
          </div>
          <div className="form-grid context-grid">
            <label className="field-label"><span>Affected app, process, or device <em>optional</em></span><input value={affectedEntity} maxLength={200} onChange={(event) => setAffectedEntity(event.target.value)} placeholder="e.g. Difftrail.exe" /></label>
            <label className="field-label"><span>Suspected recent change <em>optional</em></span><input value={suspectedChange} maxLength={200} onChange={(event) => setSuspectedChange(event.target.value)} placeholder="e.g. Difftrail update" /></label>
          </div>
          <label className="field-label onset-field"><span>When did it begin? <em>optional</em></span><input type="datetime-local" value={onset} onChange={(event) => setOnset(event.target.value)} /><small>Leave blank if it is happening now.</small></label>
          {error && <div className="form-error" role="alert"><Icon name="alert" size={15} /> {error}</div>}
          <button type="submit" className="button button-primary investigate-submit" disabled={busy || submitting}>{busy || submitting ? <><span className="button-spinner" /> Reconstructing the window...</> : <>Investigate this problem <Icon name="arrow" size={16} /></>}</button>
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
