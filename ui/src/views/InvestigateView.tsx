import { FormEvent, useState } from "react";
import type { InvestigationResponse } from "../types";
import { Icon } from "../components/Icon";

interface Props {
  busy: boolean;
  onInvestigate: (input: { description: string; subsystem?: string; onset?: string; lookback_days: number }) => Promise<InvestigationResponse>;
}

const subsystemOptions = ["general", "graphics", "audio", "network", "bluetooth", "driver", "startup", "windows-update", "application", "device"];

export function InvestigateView({ busy, onInvestigate }: Props) {
  const [description, setDescription] = useState("");
  const [subsystem, setSubsystem] = useState("general");
  const [lookback, setLookback] = useState("7");
  const [onset, setOnset] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  async function submit(event: FormEvent) {
    event.preventDefault();
    if (!description.trim()) { setError("Describe the problem in a sentence first."); return; }
    setError(null);
    setSubmitting(true);
    try {
      await onInvestigate({ description: description.trim(), subsystem: subsystem === "general" ? undefined : subsystem, onset: onset || undefined, lookback_days: Number(lookback) });
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "The investigation could not be completed.");
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="page-stack investigate-page">
      <section className="page-intro"><span className="eyebrow">Evidence before confidence</span><h2>What started behaving differently?</h2><p>Describe the problem the way you would explain it to a person. Difftrail will choose a relevant area, reconstruct the time window, and show the changes it can support.</p></section>
      <form className="investigate-layout" onSubmit={submit}>
        <section className="panel investigation-form">
          <div className="form-step"><span className="step-number">01</span><div><h3>Describe the symptom</h3><p>Keep it specific enough to connect to a subsystem.</p></div></div>
          <textarea autoFocus value={description} onChange={(event) => setDescription(event.target.value)} placeholder="e.g. My games started crashing after launch" rows={5} aria-label="Problem description" />
          <div className="example-row"><span>Try an example</span><button type="button" onClick={() => setDescription("My graphics started failing after an update")}>Graphics failure</button><button type="button" onClick={() => setDescription("My USB headset stopped working")}>Audio device</button><button type="button" onClick={() => setDescription("An app started crashing on launch")}>App crash</button></div>
          <div className="form-divider" />
          <div className="form-step"><span className="step-number">02</span><div><h3>Set the context</h3><p>These are starting points, not irreversible choices.</p></div></div>
          <div className="form-grid">
            <label className="field-label"><span>Area <em>optional</em></span><select value={subsystem} onChange={(event) => setSubsystem(event.target.value)}>{subsystemOptions.map((option) => <option key={option} value={option}>{option === "general" ? "Let Difftrail infer it" : option.replace("windows-update", "Windows update")}</option>)}</select></label>
            <label className="field-label"><span>Look back</span><select value={lookback} onChange={(event) => setLookback(event.target.value)}><option value="1">24 hours</option><option value="3">3 days</option><option value="7">7 days</option><option value="14">14 days</option><option value="30">30 days</option></select></label>
          </div>
          <label className="field-label onset-field"><span>When did it begin? <em>optional</em></span><input type="datetime-local" value={onset} onChange={(event) => setOnset(event.target.value)} /><small>Leave blank if it is happening now.</small></label>
          {error && <div className="form-error" role="alert"><Icon name="alert" size={15} /> {error}</div>}
          <button type="submit" className="button button-primary investigate-submit" disabled={busy || submitting}>{busy || submitting ? <><span className="button-spinner" /> Reconstructing the window…</> : <>Investigate this problem <Icon name="arrow" size={16} /></>}</button>
        </section>
        <aside className="investigate-aside">
          <div className="aside-note"><div className="aside-note-icon"><Icon name="shield" size={18} /></div><h3>Deterministic by design</h3><p>The core diagnosis does not require AI or cloud access. Each candidate is ranked from inspectable timing, subsystem, baseline, and counter-evidence signals.</p></div>
          <div className="aside-note aside-note-quiet"><Icon name="clock" size={17} /><div><strong>Useful after a baseline</strong><p>Difftrail needs a little history to make a meaningful comparison. A quiet first scan is expected.</p></div></div>
        </aside>
      </form>
    </div>
  );
}
