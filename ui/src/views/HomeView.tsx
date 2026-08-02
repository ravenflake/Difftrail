import type { Bootstrap, Incident, View } from "../types";
import { formatDateTime, relativeTime, subsystemLabel } from "../format";
import { Icon } from "../components/Icon";
import { EventRow } from "../components/EventRow";
import { Metric } from "../components/Metric";

interface Props {
  data: Bootstrap;
  onNavigate: (view: View) => void;
  onOpenIncident: (incident: Incident) => void;
}

export function HomeView({ data, onNavigate, onOpenIncident }: Props) {
  const { status, events, incidents, validation } = data;
  const attention = status.last_scan?.status === "partial" || validation.scans.provider_error_count > 0;
  const changes = events.filter((event) => event.kind === "change").slice(0, 5);
  const recentIncidents = incidents.slice(0, 3);
  const sourceCount = status.sources.filter((source) => source.initialized).length;

  return (
    <div className="page-stack">
      <section className={`hero-status ${attention ? "is-attention" : ""}`}>
        <div className="hero-status-copy">
          <div className="overline"><span className="live-pulse" /> {attention ? "Needs a look" : "Quietly observing"}</div>
          <h2>{attention ? "One scan needs your attention." : "Your system has context."}</h2>
          <p>{attention ? "Some sources returned warnings. Your existing journal is safe; review coverage before relying on a diagnosis." : "Difftrail is keeping a compact history of meaningful changes and symptoms on this PC."}</p>
          <div className="hero-meta">
            <span><Icon name="clock" size={14} /> Last scan {relativeTime(status.last_scan?.finished_at)}</span>
            <span><Icon name="shield" size={14} /> Local journal</span>
          </div>
        </div>
        <div className="hero-status-art" aria-hidden="true">
          <div className="orbit orbit-one" />
          <div className="orbit orbit-two" />
          <div className="orbit-core"><Icon name={attention ? "alert" : "spark"} size={27} /></div>
        </div>
      </section>

      <section className="metric-grid" aria-label="Journal summary">
        <Metric label="Meaningful changes" value={String(status.changes)} note="in the local journal" icon={<Icon name="change" size={18} />} />
        <Metric label="Symptoms recorded" value={String(status.symptoms)} note="crashes, resets, and signals" icon={<Icon name="symptom" size={18} />} />
        <Metric label="Sources capturing" value={`${sourceCount}/${status.sources.length}`} note="read-only Windows sources" icon={<Icon name="shield" size={18} />} />
        <Metric label="Investigations" value={String(status.incidents)} note="problems you have explored" icon={<Icon name="investigate" size={18} />} />
      </section>

      <div className="home-grid">
        <section className="panel changes-panel">
          <div className="section-heading">
            <div><span className="eyebrow">The journal</span><h3>Recent meaningful changes</h3></div>
            <button type="button" className="quiet-link" onClick={() => onNavigate("timeline")}>Open timeline <Icon name="arrow" size={14} /></button>
          </div>
          {changes.length ? (
            <div className="event-list">{changes.map((event) => <EventRow key={event.id || `${event.occurred_at}-${event.title}`} event={event} compact />)}</div>
          ) : (
            <EmptyPanel icon="timeline" title="The journal is still quiet" body="Run a scan to establish a baseline. Later scans will show meaningful state changes here." action="Go to system health" onClick={() => onNavigate("health")} />
          )}
        </section>

        <section className="panel incidents-panel">
          <div className="section-heading">
            <div><span className="eyebrow">Your questions</span><h3>Recent investigations</h3></div>
            <button type="button" className="icon-button" onClick={() => onNavigate("investigate")} aria-label="Investigate a problem" title="Investigate a problem"><Icon name="plus" size={17} /></button>
          </div>
          {recentIncidents.length ? (
            <div className="incident-list">{recentIncidents.map((incident) => <IncidentListItem key={incident.id} incident={incident} onClick={() => onOpenIncident(incident)} />)}</div>
          ) : (
            <EmptyPanel icon="investigate" title="Nothing investigated yet" body="When something feels wrong, describe it in your own words and Difftrail will reconstruct the window." action="Investigate a problem" onClick={() => onNavigate("investigate")} />
          )}
        </section>
      </div>

      <section className="panel quiet-baseline">
        <div className="baseline-graphic" aria-hidden="true"><div /><div /><div /><div /><div /></div>
        <div className="baseline-copy"><span className="eyebrow">A useful distinction</span><h3>Events, not logs.</h3><p>Difftrail keeps the story small enough to understand: what changed, when it changed, and what happened next. The underlying evidence stays local and can be inspected when you need it.</p></div>
        <button type="button" className="button button-tertiary" onClick={() => onNavigate("timeline")}>See the journal <Icon name="arrow" size={15} /></button>
      </section>

      <section className="privacy-strip">
        <div className="privacy-strip-icon"><Icon name="shield" size={18} /></div>
        <div><strong>Private by default.</strong><span>No screenshots, document contents, or network uploads. The UI only receives redacted summaries from the local engine.</span></div>
        <button type="button" className="quiet-link" onClick={() => onNavigate("health")}>Review health <Icon name="arrow" size={14} /></button>
      </section>
    </div>
  );
}

function EmptyPanel({ icon, title, body, action, onClick }: { icon: "timeline" | "investigate"; title: string; body: string; action: string; onClick: () => void }) {
  return <div className="empty-panel"><div className="empty-icon"><Icon name={icon} size={19} /></div><div><h4>{title}</h4><p>{body}</p><button type="button" className="quiet-link" onClick={onClick}>{action} <Icon name="arrow" size={14} /></button></div></div>;
}

function IncidentListItem({ incident, onClick }: { incident: Incident; onClick: () => void }) {
  const lead = incident.results[0];
  return (
    <button type="button" className="incident-list-item" onClick={onClick}>
      <span className="incident-list-mark"><Icon name="incidents" size={15} /></span>
      <span className="incident-list-copy"><strong>{incident.description}</strong><small>{subsystemLabel(incident.subsystem)} · {relativeTime(incident.created_at)}</small></span>
      <span className={`confidence-mini confidence-${lead?.confidence?.toLowerCase() || "none"}`}>{lead?.confidence || "Open"}</span>
      <Icon name="chevron" size={15} />
    </button>
  );
}
