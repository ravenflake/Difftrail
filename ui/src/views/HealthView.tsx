import type { Bootstrap } from "../types";
import { number, relativeTime } from "../format";
import { Icon } from "../components/Icon";
import { Metric } from "../components/Metric";

interface Props {
  data: Bootstrap;
  onRecordOverhead: () => Promise<void>;
  recording: boolean;
  error: string | null;
}

export function HealthView({ data, onRecordOverhead, recording, error }: Props) {
  const { status, validation } = data;
  const ready = status.sources.filter((source) => source.initialized).length;
  const warnings = validation.scans.provider_error_count;

  return (
    <div className="page-stack">
      <section className="view-header">
        <h2>System health</h2>
        <p>Scan coverage, provider warnings, and watcher footprint.</p>
      </section>

      <section className={`health-banner ${warnings ? "is-warning" : ""}`}>
        <div className="health-banner-icon"><Icon name={warnings ? "alert" : "shield"} size={21} /></div>
        <div>
          <strong>{warnings ? `${warnings} provider warning${warnings === 1 ? "" : "s"} in this window` : "All active sources are reporting cleanly"}</strong>
          <span>{validation.scans.total ? `${validation.scans.total} scans across the last ${validation.period.days} days · ${ready} of ${status.sources.length} sources initialized` : "Run a scan to start building a local baseline."}</span>
        </div>
        <span className="health-banner-date">{relativeTime(status.last_scan?.finished_at)}</span>
      </section>

      <section className="metric-grid health-metrics" aria-label="Health metrics">
        <Metric label="Quiet scans" value={validation.scans.quiet_rate === null ? "—" : `${Math.round(validation.scans.quiet_rate * 100)}%`} note={`${validation.scans.quiet} of ${validation.scans.total} scans`} icon={<Icon name="timeline" size={18} />} />
        <Metric label="Provider errors" value={String(validation.scans.provider_error_count)} note="in the selected window" icon={<Icon name="shield" size={18} />} />
        <Metric label="Watcher CPU" value={validation.overhead.cpu_percent_mean === null ? "—" : `${number(validation.overhead.cpu_percent_mean, 2)}%`} note="recorded mean" icon={<Icon name="health" size={18} />} />
        <Metric label="Memory peak" value={validation.overhead.rss_mb_peak === null ? "—" : `${number(validation.overhead.rss_mb_peak, 0)} MB`} note="recorded RSS peak" icon={<Icon name="device" size={18} />} />
      </section>

      <section className="panel source-panel">
        <div className="section-heading">
          <div><h3>Source coverage</h3><span className="section-subtitle">Read-only sources used by the journal.</span></div>
          <span className="muted-count">{ready}/{status.sources.length} initialized</span>
        </div>
        <div className="source-grid">
          {status.sources.map((source) => (
            <div className={`source-card ${source.initialized ? "is-ready" : "is-waiting"}`} key={source.source}>
              <span className="source-card-icon"><Icon name={sourceIcon(source.source)} size={17} /></span>
              <div><strong>{source.label}</strong><span>{source.initialized ? `${number(source.item_count)} items · ${relativeTime(source.last_seen_at)}` : "Waiting for first baseline"}</span></div>
              <span className={`source-state ${source.initialized ? "" : "waiting"}`}><span className="status-dot" />{source.initialized ? "Capturing" : "Waiting"}</span>
            </div>
          ))}
        </div>
      </section>

      <section className="panel overhead-panel">
        <div className="section-heading overhead-heading">
          <div><h3>Watcher footprint</h3><span className="section-subtitle">Local CPU, memory, and disk use for the watcher process tree.</span></div>
          <div className="overhead-actions"><span className="muted-count">{validation.overhead.measurements} sample{validation.overhead.measurements === 1 ? "" : "s"}</span><button type="button" className="button button-secondary button-small" onClick={() => void onRecordOverhead()} disabled={recording} aria-busy={recording}>{recording ? "Measuring..." : validation.overhead.measurements ? "Record another" : "Record footprint"}</button></div>
        </div>
        {validation.overhead.measurements ? <><div className="overhead-values"><div><strong>{number(validation.overhead.cpu_percent_mean, 2)}%</strong><span>CPU mean</span></div><div><strong>{number(validation.overhead.rss_mb_peak, 0)} MB</strong><span>RSS peak</span></div><div><strong>{number(validation.overhead.disk_read_mb_total, 1)} MB</strong><span>Disk read</span></div></div><p className="panel-footnote">Latest sample {relativeTime(validation.overhead.last_measured_at)}.</p></> : <div className="inline-empty"><Icon name="health" size={18} /><p>No footprint sample recorded.</p></div>}
        {error && <div className="form-error" role="alert"><Icon name="alert" size={14} /> {error}</div>}
      </section>
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
