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
  const [loadError, setLoadError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    const timer = window.setTimeout(async () => {
      setLoading(true);
      setLoadError(null);
      try {
        const next = await onLoad(filters);
        if (!cancelled) setVisibleEvents(next);
      } catch (reason) {
        if (!cancelled) setLoadError(reason instanceof Error ? reason.message : "The evidence timeline could not be updated.");
      } finally {
        if (!cancelled) setLoading(false);
      }
    }, 180);
    return () => { cancelled = true; window.clearTimeout(timer); };
  }, [events, filters, onLoad]);

  const grouped = groupByDay(visibleEvents);
  const burstCount = Object.values(grouped).reduce((total, dayEvents) => total + groupBursts(dayEvents).filter((group) => group.length > 1).length, 0);
  return (
    <div className="page-stack">
      <section className="view-header split-intro"><div><h2>Evidence timeline</h2><p>Read-only records from Windows sources. Inventory changes use scan-detection time; Windows signals use their source timestamp. Proximity is context, not proof of cause.</p></div><div className="intro-aside"><span className="intro-aside-number">{visibleEvents.length}</span><span>recorded events in view</span>{burstCount > 0 && <small>{burstCount} repeated symptom group{burstCount === 1 ? "" : "s"}</small>}</div></section>
      <section className="panel timeline-toolbar">
        <div className="filter-tabs" role="group" aria-label="Event type">
          {(["all", "change", "symptom"] as const).map((kind) => <button type="button" aria-pressed={filters.kind === kind} className={filters.kind === kind ? "is-selected" : ""} key={kind} onClick={() => setFilters((current) => ({ ...current, kind }))}>{kind === "all" ? "Everything" : kind === "change" ? "Changes" : "Symptoms"}</button>)}
        </div>
        <div className="toolbar-fields">
          <label className="search-field"><Icon name="search" size={16} /><span className="sr-only">Search timeline</span><input value={filters.search} maxLength={200} onChange={(event) => setFilters((current) => ({ ...current, search: event.target.value }))} placeholder="Search the journal" />{filters.search && <button type="button" className="search-clear" aria-label="Clear search" title="Clear search" onClick={() => setFilters((current) => ({ ...current, search: "" }))}><Icon name="close" size={13} /></button>}</label>
          <label className="select-field"><Icon name="filter" size={15} /><span className="sr-only">Filter by subsystem</span><select value={filters.subsystem} onChange={(event) => setFilters((current) => ({ ...current, subsystem: event.target.value }))}>{timelineSubsystemOptions.map((subsystem) => <option key={subsystem} value={subsystem}>{subsystem === "all" ? "All areas" : subsystemLabel(subsystem)}</option>)}</select></label>
        </div>
      </section>
      <section className="timeline-stream" aria-live="polite">
        {loading && <div className="loading-line"><span className="loading-bar" /> Updating the journal…</div>}
        {loadError && <div className="form-error timeline-error" role="alert"><Icon name="alert" size={14} /><span><strong>Could not refresh this view.</strong> {loadError} The last available results remain visible.</span></div>}
        {Object.entries(grouped).map(([day, dayEvents]) => <div className="timeline-day" key={day}><div className="day-label"><span>{day}</span><span className="day-rule" /></div><div className="timeline-events">{groupBursts(dayEvents).map((group) => <EventRow key={group[0].id || `${group[0].occurred_at}-${group[0].title}`} event={group[0]} groupedEvents={group.length > 1 ? group : undefined} />)}</div></div>)}
        {!visibleEvents.length && !loading && !loadError && (
          <div className="large-empty">
            <div className="empty-icon"><Icon name={events.length ? "filter" : "timeline"} size={22} /></div>
            <h3>{events.length ? "No recorded events match these filters." : "No changes or symptoms have been recorded yet."}</h3>
            <p>{events.length ? "Try a broader event type or area, or clear the search." : "The first valid scan establishes quiet baselines. Future scans can then record differences; they cannot reconstruct changes that happened before collection began."}</p>
            {events.length ? <button type="button" className="button button-secondary button-small timeline-clear-filters" onClick={() => setFilters({ kind: "all", subsystem: "all", search: "" })}><Icon name="close" size={13} /> Clear filters</button> : null}
          </div>
        )}
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

const BURST_WINDOW_MS = 2 * 60 * 1000;

function groupBursts(events: EventRecord[]): EventRecord[][] {
  const groups: EventRecord[][] = [];
  for (const event of events) {
    const previous = groups[groups.length - 1];
    if (previous && isBurstMember(previous[0], event)) {
      const anchor = new Date(previous[0].occurred_at).getTime();
      const current = new Date(event.occurred_at).getTime();
      if (Number.isFinite(anchor) && Number.isFinite(current) && Math.abs(anchor - current) <= BURST_WINDOW_MS) {
        previous.push(event);
        continue;
      }
    }
    groups.push([event]);
  }
  return groups;
}

function isBurstMember(first: EventRecord, candidate: EventRecord): boolean {
  return first.kind === "symptom"
    && candidate.kind === "symptom"
    && first.action === candidate.action
    && (first.action === "crash" || first.action === "hang")
    && first.source === candidate.source
    && first.subsystem === candidate.subsystem
    && first.entity === candidate.entity;
}
