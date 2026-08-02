import type { Bootstrap } from "../types";
import { formatDateTime, number, relativeTime, sourceLabel } from "../format";
import { Icon } from "../components/Icon";
import { Metric } from "../components/Metric";

export function HealthView({ data }: { data: Bootstrap }) {
  const { status, validation } = data;
  const ready = status.sources.filter((source) => source.initialized).length;
  const warnings = validation.scans.provider_error_count;
  return (
    <div className="page-stack">
      <section className="page-intro"><span className="eyebrow">A quiet system check</span><h2>Is Difftrail seeing enough?</h2><p>Health is about the journal itself: source coverage, scan stability, and whether the watcher is light enough to leave installed.</p></section>
      <section className={`health-banner ${warnings ? "is-warning" : ""}`}><div className="health-banner-icon"><Icon name={warnings ? "alert" : "shield"} size={21} /></div><div><strong>{warnings ? `${warnings} provider warning${warnings === 1 ? "" : "s"} in this window` : "All active sources are reporting cleanly"}</strong><span>{validation.scans.total ? `${validation.scans.total} scans across the last ${validation.period.days} days · ${ready} of ${status.sources.length} sources initialized` : "Run a scan to start building a local baseline."}</span></div><span className="health-banner-date">{relativeTime(status.last_scan?.finished_at)}</span></section>

      <section className="metric-grid health-metrics"><Metric label="Quiet scans" value={validation.scans.quiet_rate === null ? "—" : `${Math.round(validation.scans.quiet_rate * 100)}%`} note={`${validation.scans.quiet} of ${validation.scans.total} scans`} icon={<Icon name="timeline" size={18} />} /><Metric label="Provider errors" value={String(validation.scans.provider_error_count)} note="in the selected window" icon={<Icon name="shield" size={18} />} /><Metric label="Watcher CPU" value={validation.overhead.cpu_percent_mean === null ? "—" : `${number(validation.overhead.cpu_percent_mean, 2)}%`} note="recorded mean" icon={<Icon name="health" size={18} />} /><Metric label="Memory peak" value={validation.overhead.rss_mb_peak === null ? "—" : `${number(validation.overhead.rss_mb_peak, 0)} MB`} note="recorded RSS peak" icon={<Icon name="device" size={18} />} /></section>

      <section className="panel source-panel"><div className="section-heading"><div><span className="eyebrow">Read-only collection</span><h3>Source coverage</h3></div><span className="muted-count">{ready}/{status.sources.length} initialized</span></div><div className="source-grid">{status.sources.map((source) => <div className={`source-card ${source.initialized ? "is-ready" : "is-waiting"}`} key={source.source}><span className="source-card-icon"><Icon name={sourceIcon(source.source)} size={17} /></span><div><strong>{source.label}</strong><span>{source.initialized ? `${number(source.item_count)} items · ${relativeTime(source.last_seen_at)}` : "Waiting for its first baseline"}</span></div><span className={`source-state ${source.initialized ? "" : "waiting"}`}><span className="status-dot" />{source.initialized ? "Capturing" : "Waiting"}</span></div>)}</div></section>

      <div className="health-grid"><section className="panel overhead-panel"><div className="section-heading"><div><span className="eyebrow">Passive validation</span><h3>Watcher footprint</h3></div><span className="muted-count">{validation.overhead.measurements} sample{validation.overhead.measurements === 1 ? "" : "s"}</span></div>{validation.overhead.measurements ? <><div className="overhead-values"><div><strong>{number(validation.overhead.cpu_percent_mean, 2)}%</strong><span>CPU mean</span></div><div><strong>{number(validation.overhead.rss_mb_peak, 0)} MB</strong><span>RSS peak</span></div><div><strong>{number(validation.overhead.disk_read_mb_total, 1)} MB</strong><span>Disk read</span></div></div><p className="panel-footnote">Measured locally from the watcher process tree. Latest sample {relativeTime(validation.overhead.last_measured_at)}.</p></> : <div className="inline-empty"><Icon name="health" size={18} /><p>No overhead measurements recorded yet. Use the CLI <code>overhead --record</code> command to add one.</p></div>}</section><section className="panel privacy-panel"><div className="privacy-large-icon"><Icon name="shield" size={22} /></div><span className="eyebrow">Trust boundary</span><h3>Local and evidence-led.</h3><p>{validation.privacy}</p><ul><li>No cloud account is required.</li><li>The UI receives redacted summaries.</li><li>Difftrail never changes system state automatically.</li></ul></section></div>
      <p className="health-disclaimer">Health reports collection behavior. They do not prove that a candidate caused an incident. {validation.limits[0]}</p>
    </div>
  );
}

function sourceIcon(source: string) {
  if (source === "drivers") return "driver" as const;
  if (source === "apps") return "application" as const;
  if (source === "devices") return "device" as const;
  if (source === "services" || source === "tasks") return "service" as const;
  if (source === "startup") return "startup" as const;
  return "update" as const;
}
