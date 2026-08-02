import { useEffect, useState } from "react";
import type { EventRecord, TimelineFilters } from "../types";
import { formatDate } from "../format";
import { Icon } from "../components/Icon";
import { EventRow } from "../components/EventRow";
import { subsystemLabel, timelineSubsystemOptions } from "../subsystems";

interface Props {
  events: EventRecord[];
  onLoad: (filters: TimelineFilters) => Promise<EventRecord[]>;
}

export function TimelineView({ events, onLoad }: Props) {
  const [filters, setFilters] = useState<TimelineFilters>({ kind: "all", subsystem: "all", search: "" });
  const [visibleEvents, setVisibleEvents] = useState(events);
  const [loading, setLoading] = useState(false);

  useEffect(() => setVisibleEvents(events), [events]);
  useEffect(() => {
    const timer = window.setTimeout(async () => {
      setLoading(true);
      try { setVisibleEvents(await onLoad(filters)); } finally { setLoading(false); }
    }, 180);
    return () => window.clearTimeout(timer);
  }, [filters, onLoad]);

  const grouped = groupByDay(visibleEvents);
  return (
    <div className="page-stack">
      <section className="page-intro split-intro"><div><span className="eyebrow">The semantic journal</span><h2>See the story, not the noise.</h2><p>Meaningful changes and symptoms, arranged around time. Select an event to see its local summary.</p></div><div className="intro-aside"><span className="intro-aside-number">{visibleEvents.length}</span><span>events in view</span></div></section>
      <section className="panel timeline-toolbar">
        <div className="filter-tabs" aria-label="Event type">
          {(["all", "change", "symptom"] as const).map((kind) => <button type="button" aria-pressed={filters.kind === kind} className={filters.kind === kind ? "is-selected" : ""} key={kind} onClick={() => setFilters((current) => ({ ...current, kind }))}>{kind === "all" ? "Everything" : kind === "change" ? "Changes" : "Symptoms"}</button>)}
        </div>
        <div className="toolbar-fields">
          <label className="search-field"><Icon name="search" size={16} /><span className="sr-only">Search timeline</span><input value={filters.search} onChange={(event) => setFilters((current) => ({ ...current, search: event.target.value }))} placeholder="Search the journal" /></label>
          <label className="select-field"><Icon name="filter" size={15} /><span className="sr-only">Filter by subsystem</span><select value={filters.subsystem} onChange={(event) => setFilters((current) => ({ ...current, subsystem: event.target.value }))}>{timelineSubsystemOptions.map((subsystem) => <option key={subsystem} value={subsystem}>{subsystem === "all" ? "All areas" : subsystemLabel(subsystem)}</option>)}</select></label>
        </div>
      </section>
      <section className="timeline-stream" aria-live="polite">
        {loading && <div className="loading-line"><span className="loading-bar" /> Updating the journal…</div>}
        {Object.entries(grouped).map(([day, dayEvents]) => <div className="timeline-day" key={day}><div className="day-label"><span>{day}</span><span className="day-rule" /></div><div className="timeline-events">{dayEvents.map((event) => <EventRow key={event.id || `${event.occurred_at}-${event.title}`} event={event} />)}</div></div>)}
        {!visibleEvents.length && !loading && <div className="large-empty"><div className="empty-icon"><Icon name="timeline" size={22} /></div><h3>No events match that view.</h3><p>Try a broader area or run another scan when you expect something to have changed.</p></div>}
      </section>
    </div>
  );
}

function groupByDay(events: EventRecord[]): Record<string, EventRecord[]> {
  return events.reduce<Record<string, EventRecord[]>>((groups, event) => {
    const key = formatDate(event.occurred_at);
    (groups[key] ||= []).push(event);
    return groups;
  }, {});
}
