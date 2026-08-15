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
  onExport: (incidentId: string) => Promise<void>;
  onDelete: (incidentId: string) => Promise<void>;
  exportBusy: boolean;
  exportError: string | null;
}

export function IncidentsView({ incidents, selected, onSelect, onNavigate, onFeedback, onExport, onDelete, exportBusy, exportError }: Props) {
  return (
    <div className="page-stack">
      <section className="view-header split-intro"><div><h2>Investigations</h2><p>Saved symptom analyses and feedback.</p></div><button type="button" className="button button-primary" onClick={onNavigate}><Icon name="plus" size={16} /> New investigation</button></section>
      <div className="incidents-layout">
        <section className="panel incident-sidebar"><div className="panel-heading-line"><h3>Saved investigations</h3><span className="muted-count">{incidents.length}</span></div>{incidents.length ? <div className="incident-nav-list">{incidents.map((incident) => <button type="button" className={`incident-nav-item ${selected?.id === incident.id ? "is-selected" : ""}`} key={incident.id} onClick={() => onSelect(incident)}><span className="incident-nav-icon"><Icon name="incidents" size={15} /></span><span><strong>{incident.description}</strong><small>{subsystemLabel(incident.subsystem)} · {relativeTime(incident.created_at)}</small></span><Icon name="chevron" size={14} /></button>)}</div> : <div className="sidebar-empty"><Icon name="investigate" size={18} /><p>No investigations yet.</p></div>}</section>
        <section className="incident-detail-column">{selected ? <InvestigationDetail incident={selected} onFeedback={onFeedback} onExport={onExport} onDelete={onDelete} exportBusy={exportBusy} exportError={exportError} /> : <div className="panel choose-incident"><h3>Select an investigation</h3><p>Choose a saved investigation to review its ranked changes.</p><button type="button" className="quiet-link" onClick={onNavigate}>Start an investigation <Icon name="arrow" size={14} /></button></div>}</section>
      </div>
    </div>
  );
}
