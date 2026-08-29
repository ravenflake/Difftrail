import type { Bootstrap } from "../types";
import { number, relativeTime } from "../format";
import { Icon } from "../components/Icon";
import { Metric } from "../components/Metric";

interface Props {
  data: Bootstrap;
  connected: boolean;
  onRecordOverhead: () => Promise<void>;
  recording: boolean;
  error: string | null;
  onExport: () => Promise<void>;
  exportBusy: boolean;
  exportError: string | null;
}

export function HealthView({ data, connected, onRecordOverhead, recording, error, onExport, exportBusy, exportError }: Props) {
  const { status, validation, automation } = data;
  const ready = status.sources.filter((source) => source.initialized).length;
  const warnings = validation.scans.provider_error_count;
  const integrityChecked = status.journal.integrity !== "not checked";
  const watcherInstalled = automation.watcher.installed && automation.watcher.state?.toLowerCase() !== "disabled";
  const watcherAttention = automation.watcher.needs_repair || (watcherInstalled && automation.watcher.last_task_result !== null && automation.watcher.last_task_result !== 0);
  const diskAttention = status.host.system_disk_used_percent !== null && status.host.system_disk_used_percent >= 90;
  const memoryAttention = status.host.memory_used_percent !== null && status.host.memory_used_percent >= 90;
  const needsAttention = warnings > 0 || !status.journal.ok || watcherAttention || diskAttention || memoryAttention;
  const bannerTitle = watcherAttention
    ? "Background collection needs attention"
    : diskAttention
      ? "System drive space is running low"
      : memoryAttention
        ? "Memory pressure is high"
    : warnings
      ? `${warnings} provider warning${warnings === 1 ? "" : "s"} in this window`
      : !status.journal.ok
        ? "The local journal needs attention"
        : "System monitoring is healthy";
  const bannerNote = watcherAttention
    ? automation.watcher.message || "Review the background watcher status below."
    : diskAttention
      ? `${formatBytes(status.host.system_disk_free_bytes)} remains free on the Windows system drive.`
      : memoryAttention
        ? `${formatBytes(status.host.memory_available_bytes)} of memory remains available.`
        : validation.scans.total
          ? `${validation.scans.total} scans across the last ${validation.period.days} days · ${ready} of ${status.sources.length} sources initialized`
          : "Run a scan to start building a local baseline.";

  return (
    <div className="page-stack">
      <section className="view-header health-view-header">
        <div><h2>System health</h2><p>A quick machine snapshot plus the health of Difftrail&apos;s local monitoring.</p></div>
        <button type="button" className="button button-secondary button-small" title={connected ? undefined : "Connect the local journal to export a report"} onClick={() => void onExport()} disabled={!connected || exportBusy} aria-busy={exportBusy}>{exportBusy ? "Preparing report…" : "Export diagnostic report"}</button>
      </section>
      {exportError && <div className="form-error" role="alert"><Icon name="alert" size={14} /> {exportError}</div>}

      <section className={`health-banner ${needsAttention ? "is-warning" : ""}`}>
        <div className="health-banner-icon"><Icon name={needsAttention ? "alert" : "shield"} size={21} /></div>
        <div><strong>{bannerTitle}</strong><span>{bannerNote}</span></div>
        <span className="health-banner-date">{relativeTime(status.last_scan?.finished_at)}</span>
      </section>

      <section className="metric-grid health-metrics" aria-label="Machine snapshot">
        <Metric label="System uptime" value={formatUptime(status.host.uptime_seconds)} note="since the last Windows boot" icon={<Icon name="health" size={18} />} />
        <Metric label="Memory available" value={formatBytes(status.host.memory_available_bytes)} note={status.host.memory_used_percent === null ? "live value unavailable" : `${number(status.host.memory_used_percent, 0)}% used of ${formatBytes(status.host.memory_total_bytes)}`} icon={<Icon name="device" size={18} />} />
        <Metric label="System drive free" value={formatBytes(status.host.system_disk_free_bytes)} note={status.host.system_disk_used_percent === null ? "live value unavailable" : `${number(status.host.system_disk_used_percent, 0)}% used of ${formatBytes(status.host.system_disk_total_bytes)}`} icon={<Icon name="driver" size={18} />} />
        <Metric label="Recent symptoms" value={number(validation.journal.symptoms)} note={`during the last ${validation.period.days} days`} icon={<Icon name="alert" size={18} />} />
      </section>

      <section className="panel collection-health-panel">
        <div className="section-heading"><div><h3>Collection health</h3><span className="section-subtitle">The useful status checks for unattended monitoring.</span></div></div>
        <div className="collection-health-grid">
          <HealthFact label="Last scan" value={status.last_scan?.finished_at ? relativeTime(status.last_scan.finished_at) : "Never"} detail={status.last_scan ? `${status.last_scan.status} · ${status.last_scan.summary.error_count || 0} warnings` : "No scan recorded"} tone={status.last_scan?.status === "partial" ? "warning" : "good"} />
          <HealthFact label="Background scans" value={watcherAttention ? "Needs attention" : watcherInstalled ? "Enabled" : "Off"} detail={watcherInstalled ? `Every ${formatInterval(automation.config.interval_seconds)} · next ${relativeTime(automation.watcher.next_run_at)}` : "No scheduled scans"} tone={watcherAttention ? "warning" : watcherInstalled ? "good" : "neutral"} />
          <HealthFact label="Source coverage" value={`${ready}/${status.sources.length} ready`} detail={ready === status.sources.length ? "All read-only baselines initialized" : `${status.sources.length - ready} waiting for baseline`} tone={ready === status.sources.length ? "good" : "warning"} />
          <HealthFact label="Local journal" value={status.journal.ok ? "Healthy" : "Needs attention"} detail={`${number(status.journal.journal.events)} events · ${status.journal.scans.stale_running.length} stuck scans`} tone={status.journal.ok ? "good" : "warning"} />
        </div>
      </section>

      <section className={`journal-health-card ${status.journal.ok ? "" : "is-warning"}`} aria-live="polite">
        <div className="journal-health-copy"><span className="eyebrow">Journal integrity</span><strong>{status.journal.ok ? (integrityChecked ? "Journal is healthy" : "Journal structure looks healthy") : "Journal needs attention"}</strong><span>{integrityChecked ? `${status.journal.integrity} integrity` : "Full integrity check available in Doctor"} · schema {status.journal.schema.current_version}/{status.journal.schema.supported_version}</span></div>
        <div className="journal-health-stats"><span><strong>{status.journal.scans.running}</strong> active scan{status.journal.scans.running === 1 ? "" : "s"}</span><span><strong>{status.journal.scans.stale_running.length}</strong> stale scan{status.journal.scans.stale_running.length === 1 ? "" : "s"}</span></div>
      </section>

      <section className="panel source-panel">
        <div className="section-heading">
          <div><h3>Source coverage</h3><span className="section-subtitle">Read-only Windows sources feeding the journal.</span></div>
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
          <div><h3>Background scan footprint</h3><span className="section-subtitle">Measures one disposable watcher run on this PC. It is a diagnostic benchmark, not a process that stays resident.</span></div>
          <div className="overhead-actions"><span className="muted-count">{validation.overhead.measurements} sample{validation.overhead.measurements === 1 ? "" : "s"}</span><button type="button" className="button button-secondary button-small" title={connected ? undefined : "Connect the local journal to measure a scan"} onClick={() => void onRecordOverhead()} disabled={!connected || recording} aria-busy={recording}>{recording ? "Measuring one scan…" : validation.overhead.measurements ? "Measure again" : "Measure one scan"}</button></div>
        </div>
        {validation.overhead.measurements ? <><div className="overhead-values"><div><strong>{number(validation.overhead.cpu_percent_mean, 2)}%</strong><span>CPU mean</span></div><div><strong>{number(validation.overhead.rss_mb_peak, 0)} MB</strong><span>memory peak</span></div><div><strong>{number(validation.overhead.disk_read_mb_total, 1)} MB</strong><span>disk read</span></div></div><p className="panel-footnote">Latest sample {relativeTime(validation.overhead.last_measured_at)}. Between scheduled scans, the watcher has no persistent process; only the small tray companion remains.</p></> : <div className="inline-empty"><Icon name="health" size={18} /><p>No scan-footprint sample recorded yet. This is optional and does not affect monitoring.</p></div>}
        {error && <div className="form-error" role="alert"><Icon name="alert" size={14} /> {error}</div>}
      </section>
    </div>
  );
}

function HealthFact({ label, value, detail, tone }: { label: string; value: string; detail: string; tone: "good" | "warning" | "neutral" }) {
  return <div className={`collection-health-fact is-${tone}`}><span>{label}</span><strong>{value}</strong><small>{detail}</small></div>;
}

function formatBytes(value: number | null): string {
  if (value === null) return "—";
  const gib = value / 1_073_741_824;
  if (gib >= 1024) return `${number(gib / 1024, 1)} TB`;
  return `${number(gib, gib >= 100 ? 0 : 1)} GB`;
}

function formatUptime(seconds: number | null): string {
  if (seconds === null) return "—";
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  if (days) return `${days}d ${hours}h`;
  const minutes = Math.floor((seconds % 3600) / 60);
  return hours ? `${hours}h ${minutes}m` : `${minutes}m`;
}

function formatInterval(seconds: number): string {
  if (seconds % 3600 === 0) return `${seconds / 3600} hour${seconds === 3600 ? "" : "s"}`;
  return `${Math.round(seconds / 60)} minutes`;
}

function sourceIcon(source: string) {
  if (source === "drivers") return "driver" as const;
  if (source === "apps") return "application" as const;
  if (source === "devices") return "device" as const;
  if (source === "services" || source === "tasks") return "service" as const;
  if (source === "startup") return "startup" as const;
  return "update" as const;
}
