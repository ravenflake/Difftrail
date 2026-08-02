import { useState } from "react";
import type { EventRecord } from "../types";
import { formatDateTime, kindLabel, relativeTime, sourceLabel, subsystemLabel } from "../format";
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
}

export function EventRow({ event, compact = false }: Props) {
  const [open, setOpen] = useState(false);
  const isSymptom = event.kind === "symptom";
  return (
    <div className={`event-row ${open ? "is-open" : ""} ${isSymptom ? "is-symptom" : ""}`}>
      <button type="button" className="event-main" onClick={() => setOpen((value) => !value)} aria-expanded={open}>
        <span className={`event-icon event-icon-${event.kind}`}><Icon name={eventIcon(event)} size={17} /></span>
        <span className="event-copy">
          <span className="event-title">{event.title}</span>
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
          <div className="detail-note"><Icon name="shield" size={14} /> Raw event details stay in the local journal and are not shown in this summary.</div>
        </div>
      )}
    </div>
  );
}
