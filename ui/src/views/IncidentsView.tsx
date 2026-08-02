import type { Incident } from "../types";
import { relativeTime, subsystemLabel } from "../format";
import { Icon } from "../components/Icon";
import { InvestigationDetail } from "./InvestigationDetail";

interface Props {
  incidents: Incident[];
  selected: Incident | null;
  onSelect: (incident: Incident) => void;
  onNavigate: () => void;
  onFeedback: (incidentId: string, outcome: "correct" | "incorrect" | "unknown", eventId?: string) => Promise<void>;
}

export function IncidentsView({ incidents, selected, onSelect, onNavigate, onFeedback }: Props) {
  return (
    <div className="page-stack">
      <section className="page-intro split-intro"><div><span className="eyebrow">Your investigation history</span><h2>Questions worth keeping.</h2><p>Each investigation preserves the window Difftrail used, the candidates it found, and what you thought afterward.</p></div><button type="button" className="button button-primary" onClick={onNavigate}><Icon name="plus" size={16} /> Investigate a problem</button></section>
      <div className="incidents-layout">
        <section className="panel incident-sidebar"><div className="panel-heading-line"><span className="eyebrow">All incidents</span><span className="muted-count">{incidents.length}</span></div>{incidents.length ? <div className="incident-nav-list">{incidents.map((incident) => <button type="button" className={`incident-nav-item ${selected?.id === incident.id ? "is-selected" : ""}`} key={incident.id} onClick={() => onSelect(incident)}><span className="incident-nav-icon"><Icon name="incidents" size={15} /></span><span><strong>{incident.description}</strong><small>{subsystemLabel(incident.subsystem)} · {relativeTime(incident.created_at)}</small></span><Icon name="chevron" size={14} /></button>)}</div> : <div className="sidebar-empty"><Icon name="investigate" size={18} /><p>No investigations yet.</p></div>}</section>
        <section className="incident-detail-column">{selected ? <InvestigationDetail incident={selected} onFeedback={onFeedback} /> : <div className="panel choose-incident"><div className="choose-art"><Icon name="incidents" size={27} /></div><h3>Choose an investigation.</h3><p>Review the evidence behind a past problem, or start a new investigation when something changes.</p><button type="button" className="quiet-link" onClick={onNavigate}>Investigate a problem <Icon name="arrow" size={14} /></button></div>}</section>
      </div>
    </div>
  );
}
