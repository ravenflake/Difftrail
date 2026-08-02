import { useState } from "react";
import type { EventRecord } from "../types";
import { formatDateTime, relativeTime, sourceLabel, subsystemLabel } from "../format";
import { Icon, type IconName } from "./Icon";

function eventIcon(event: EventRecord): IconName {
  if (event.kind === "symptom") return "symptom";
  if (event.source === "drivers") return "driver";
  if (event.source === "apps") return "application";
  if (event.source === "devices") return "device";
  if (event.source === "services" || event.source === "tasks") return "service";
  if (event.source === "startup") return "startup";
  if (event.source === "updates") return "update";
  return "change";
}

interface Props {
  event: EventRecord;
  compact?: boolean;
  groupedEvents?: EventRecord[];
}

export function EventRow({ event, compact = false, groupedEvents }: Props) {
  const [open, setOpen] = useState(false);
  const isSymptom = event.kind === "symptom";
  const records = groupedEvents && groupedEvents.length > 1 ? groupedEvents : [event];
  const isBurst = records.length > 1;
  return (
    <div className={`event-row ${open ? "is-open" : ""} ${isSymptom ? "is-symptom" : ""}`}>
      <button type="button" className="event-main" onClick={() => setOpen((value) => !value)} aria-expanded={open}>
        <span className={`event-icon event-icon-${event.kind}`}><Icon name={eventIcon(event)} size={17} /></span>
        <span className="event-copy">
          <span className="event-title">{event.title}{isBurst && <span className="event-burst-count">{records.length} records</span>}</span>
          <span className="event-meta"><span>{sourceLabel(event.source)}</span><span className="meta-dot" aria-hidden="true" /><span>{subsystemLabel(event.subsystem)}</span></span>
        </span>
        <span className="event-time" title={formatDateTime(event.occurred_at)}>{relativeTime(event.occurred_at)}</span>
        {!compact && <span className={`severity-dot severity-${event.severity}`} aria-label={`${event.severity} importance`} />}
        <Icon name="chevron" size={15} className={`row-chevron ${open ? "rotated" : ""}`} />
      </button>
      {open && (
        <div className="event-detail">
          <div className="detail-line"><span>Recorded</span><strong>{formatDateTime(event.occurred_at)}</strong></div>
          <div className="detail-line"><span>Action</span><strong>{event.action}</strong></div>
          {event.entity && <div className="detail-line"><span>Entity</span><strong>{event.entity}</strong></div>}
          {isBurst && <>
            <div className="detail-line"><span>Burst</span><strong>{records.length} records within {burstDuration(records)}</strong></div>
            <div className="burst-records" aria-label="Grouped event records">
              {records.map((record) => <div className="burst-record" key={record.id || `${record.occurred_at}-${record.entity}`}><span>{formatDateTime(record.occurred_at)}</span><strong>{record.entity || sourceLabel(record.source)}</strong></div>)}
            </div>
          </>}
          {event.detail_summary && <DetailSummary summary={event.detail_summary} />}
          <div className="detail-note"><Icon name="shield" size={14} /> Parsed details are shown locally; raw messages and paths stay in the journal.</div>
        </div>
      )}
    </div>
  );
}

function DetailSummary({ summary }: { summary: NonNullable<EventRecord["detail_summary"]> }) {
  return <div className="detail-summary">
    {summary.application_name && <div className="detail-line"><span>Application</span><strong>{summary.application_name}</strong></div>}
    {summary.event_id !== undefined && <div className="detail-line"><span>Event ID</span><strong>{summary.event_id}</strong></div>}
    {summary.log_name && <div className="detail-line"><span>Log</span><strong>{summary.log_name}</strong></div>}
    {summary.provider && <div className="detail-line"><span>Provider</span><strong>{summary.provider}</strong></div>}
    {summary.record_id && <div className="detail-line"><span>Record</span><strong>{summary.record_id}</strong></div>}
    {summary.changed_fields?.length ? <div className="detail-line"><span>Changed fields</span><strong>{summary.changed_fields.join(", ")}</strong></div> : null}
    {summary.before && <div className="detail-line"><span>Before</span><strong>{formatValues(summary.before)}</strong></div>}
    {summary.after && <div className="detail-line"><span>After</span><strong>{formatValues(summary.after)}</strong></div>}
  </div>;
}

function formatValues(values: Record<string, string | number | boolean>): string {
  return Object.entries(values).map(([key, value]) => `${key}: ${String(value)}`).join(" · ");
}

function burstDuration(records: EventRecord[]): string {
  const times = records.map((record) => new Date(record.occurred_at).getTime()).filter((value) => Number.isFinite(value));
  if (times.length < 2) return "the same time";
  const seconds = Math.round((Math.max(...times) - Math.min(...times)) / 1000);
  return seconds < 60 ? `${seconds}s` : `${Math.round(seconds / 60)}m`;
}
