import type { Bootstrap, Incident, View } from "../types";
import { relativeTime, subsystemLabel } from "../format";
import { Icon } from "../components/Icon";
import { EventRow } from "../components/EventRow";
import { Metric } from "../components/Metric";
import { assessmentLabel } from "../review-language";

interface Props {
  data: Bootstrap;
  connection: "local" | "preview";
  scanning: boolean;
  onNavigate: (view: View) => void;
  onScan: () => void;
  onOpenIncident: (incident: Incident) => void;
}

export function HomeView({ data, connection, scanning, onNavigate, onScan, onOpenIncident }: Props) {
  const { status, events, incidents } = data;
  const preview = connection === "preview";
  const hasScan = Boolean(status.last_scan?.finished_at);
  const attention = !hasScan || status.last_scan?.status !== "ok" || sourceCount(status) < status.sources.length;
  const changes = events.filter((event) => event.kind === "change").slice(0, 5);
  const recentIncidents = incidents.slice(0, 3);
  const readySources = sourceCount(status);

  return (
    <div className="page-stack">
      <section className={`status-panel ${attention ? "is-attention" : ""}`}>
        <div>
          <div className="status-panel-label"><span className="live-pulse" /> {preview ? "Synthetic preview only" : attention ? "Journal coverage needs attention" : "Source baselines established"}</div>
          <strong>{preview ? "These examples demonstrate the workflow; they are not observations from this PC." : !hasScan ? "Run the first scan to establish baselines." : attention ? "Review coverage before relying on ranked leads." : `${readySources}/${status.sources.length} source baselines set`}</strong>
          <span>{preview ? "Connect the local journal to review real evidence" : hasScan ? `Last scan ${relativeTime(status.last_scan?.finished_at)}` : "No scan recorded"}</span>
        </div>
        {!preview && !hasScan && <button type="button" className="button button-primary button-small" onClick={onScan} disabled={scanning}><Icon name={scanning ? "refresh" : "spark"} size={14} className={scanning ? "spin" : ""} /> {scanning ? "Scanning…" : "Run first scan"}</button>}
        {!preview && hasScan && attention && <button type="button" className="button button-secondary button-small" onClick={() => onNavigate("health")}>Review collection <Icon name="arrow" size={14} /></button>}
      </section>

      <section className="metric-grid" aria-label="Journal summary">
        <Metric label={preview ? "Example changes" : "Recorded changes"} value={String(status.changes)} note={preview ? "synthetic workflow records" : "filtered state differences"} icon={<Icon name="change" size={18} />} />
        <Metric label={preview ? "Example symptoms" : "Recorded symptoms"} value={String(status.symptoms)} note={preview ? "synthetic failure signals" : "Windows crashes, hangs, and resets"} icon={<Icon name="symptom" size={18} />} />
        <Metric label={preview ? "Example baselines" : "Baselines set"} value={`${readySources}/${status.sources.length}`} note={preview ? "illustrative source coverage" : "read-only Windows sources"} icon={<Icon name="shield" size={18} />} />
        <Metric label={preview ? "Example reviews" : "Saved reviews"} value={String(status.incidents)} note={preview ? "illustrative problem windows" : "problem windows you compared"} icon={<Icon name="investigate" size={18} />} />
      </section>

      <div className="home-grid">
        <section className="panel changes-panel">
          <div className="section-heading">
            <div><span className="eyebrow">{preview ? "Synthetic examples" : "Known from the journal"}</span><h3>{preview ? "Example recorded changes" : "Recent recorded changes"}</h3></div>
            <button type="button" className="quiet-link" onClick={() => onNavigate("timeline")}>Open evidence timeline <Icon name="arrow" size={14} /></button>
          </div>
          {changes.length ? (
            <div className="event-list">{changes.map((event) => <EventRow key={event.id || `${event.occurred_at}-${event.title}`} event={event} compact />)}</div>
          ) : (
            <EmptyPanel icon="timeline" title="The journal is still quiet" body={hasScan ? "Later scans will show filtered state changes here." : "Run a scan to establish a baseline. Later scans will show filtered state changes here."} action={hasScan ? "Review collection" : scanning ? "Scanning…" : "Run first scan"} onClick={hasScan ? () => onNavigate("health") : onScan} disabled={hasScan ? false : scanning} />
          )}
        </section>

        <section className="panel incidents-panel">
          <div className="section-heading">
            <div><span className="eyebrow">{preview ? "Ranked synthetic example" : "Ranked, not proven"}</span><h3>{preview ? "Example evidence reviews" : "Recent evidence reviews"}</h3></div>
            <button type="button" className="icon-button" onClick={() => onNavigate("investigate")} aria-label="Review a problem" title="Review a problem"><Icon name="plus" size={17} /></button>
          </div>
          {recentIncidents.length ? (
            <div className="incident-list">{recentIncidents.map((incident) => <IncidentListItem key={incident.id} incident={incident} onClick={() => onOpenIncident(incident)} />)}</div>
          ) : (
            <EmptyPanel icon="investigate" title="No evidence reviews yet" body="When something goes wrong, describe the symptom and time. Difftrail will compare the recorded changes around it." action="Review a problem" onClick={() => onNavigate("investigate")} />
          )}
        </section>
      </div>

    </div>
  );
}

function EmptyPanel({ icon, title, body, action, onClick, disabled = false }: { icon: "timeline" | "investigate"; title: string; body: string; action: string; onClick: () => void; disabled?: boolean }) {
  return <div className="empty-panel"><div className="empty-icon"><Icon name={icon} size={19} /></div><div><h4>{title}</h4><p>{body}</p><button type="button" className="quiet-link" onClick={onClick} disabled={disabled}>{action} <Icon name={disabled ? "refresh" : "arrow"} size={14} className={disabled ? "spin" : ""} /></button></div></div>;
}

function IncidentListItem({ incident, onClick }: { incident: Incident; onClick: () => void }) {
  const lead = incident.results[0];
  return (
    <button type="button" className="incident-list-item" onClick={onClick}>
      <span className="incident-list-mark"><Icon name="incidents" size={15} /></span>
      <span className="incident-list-copy"><strong>{incident.description}</strong><small>{subsystemLabel(incident.subsystem)} · {relativeTime(incident.created_at)}</small></span>
      <span className={`support-mini support-${lead?.support_level || "none"}`} title="Review state, not a probability of cause">{assessmentLabel(incident)}</span>
      <Icon name="chevron" size={15} />
    </button>
  );
}

function sourceCount(status: Bootstrap["status"]): number {
  return status.sources.filter((source) => source.initialized).length;
}
