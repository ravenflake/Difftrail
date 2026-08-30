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
  const synthetic = event.source === "demo" || event.source.startsWith("fixture:");
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
          <div className="detail-line"><span>{isSymptom ? "Source timestamp" : "Detected by scan"}</span><strong>{formatDateTime(event.occurred_at)}</strong></div>
          <div className="detail-line"><span>Action</span><strong>{humanizeKey(event.action)}</strong></div>
          {event.entity && <div className="detail-line"><span>Entity</span><strong>{event.entity}</strong></div>}
          {isBurst && <>
            <div className="detail-line"><span>Burst</span><strong>{records.length} records within {burstDuration(records)}</strong></div>
            <div className="burst-records" aria-label="Grouped event records">
              {records.map((record) => <div className="burst-record" key={record.id || `${record.occurred_at}-${record.entity}`}><span>{formatDateTime(record.occurred_at)}</span><strong>{record.entity || sourceLabel(record.source)}</strong></div>)}
            </div>
          </>}
          {event.detail_summary && <DetailSummary summary={event.detail_summary} />}
          <div className="detail-note"><Icon name={synthetic ? "alert" : "shield"} size={14} /> {synthetic ? "This is synthetic fixture data, not evidence from this PC." : isSymptom ? "This is a reduced, redacted source record. Its presence on the timeline does not establish a cause." : "This inventory difference was detected at scan time; Windows may not expose when the state actually changed. It does not establish a cause."}</div>
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
    {summary.changed_fields?.length ? <div className="detail-line"><span>Changed fields</span><strong>{summary.changed_fields.map(detailKeyLabel).join(", ")}</strong></div> : null}
    {summary.before && <div className="detail-line"><span>Before</span><strong>{formatValues(summary.before)}</strong></div>}
    {summary.after && <div className="detail-line"><span>After</span><strong>{formatValues(summary.after)}</strong></div>}
  </div>;
}

function formatValues(values: Record<string, string | number | boolean>): string {
  return Object.entries(values).map(([key, value]) => `${detailKeyLabel(key)}: ${formatDetailValue(value)}`).join(" · ");
}

function formatDetailValue(value: string | number | boolean): string {
  if (typeof value === "boolean") return value ? "Yes" : "No";
  return String(value);
}

function detailKeyLabel(key: string): string {
  const labels: Record<string, string> = {
    class: "Device class",
    description: "Description",
    display_name: "Name",
    driver_date: "Driver date",
    install_date: "Install date",
    installed_on: "Installed on",
    location: "Scope",
    manufacturer: "Manufacturer",
    publisher: "Publisher",
    service_type: "Service type",
    signed: "Digitally signed",
    start_mode: "Startup type",
    state: "State",
    status: "Status",
    version: "Version",
  };
  return labels[key] || humanizeKey(key);
}

function humanizeKey(value: string): string {
  const text = value.replace(/[_-]+/g, " ").trim();
  return text ? text[0].toUpperCase() + text.slice(1) : "Unknown";
}

function burstDuration(records: EventRecord[]): string {
  const times = records.map((record) => new Date(record.occurred_at).getTime()).filter((value) => Number.isFinite(value));
  if (times.length < 2) return "the same time";
  const seconds = Math.round((Math.max(...times) - Math.min(...times)) / 1000);
  return seconds < 60 ? `${seconds}s` : `${Math.round(seconds / 60)}m`;
}
