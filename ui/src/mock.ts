import type { AutomationSummary, Bootstrap, EventRecord, Incident, ValidationReport } from "./types";

const ago = (hours: number) => new Date(Date.now() - hours * 3_600_000).toISOString();

const graphicsChange: EventRecord = {
  id: "preview-driver-change",
  occurred_at: ago(15),
  kind: "change",
  time_basis: "scan_observation",
  subsystem: "graphics",
  action: "updated",
  title: "NVIDIA display driver updated",
  entity: "NVIDIA GeForce RTX",
  severity: "high",
  source: "drivers",
  source_label: "Driver",
};

const symptom: EventRecord = {
  id: "preview-display-reset",
  occurred_at: ago(1.8),
  kind: "symptom",
  time_basis: "source_timestamp",
  subsystem: "graphics",
  action: "detected",
  title: "Display driver reset detected",
  entity: "Windows reliability signal",
  severity: "high",
  source: "event-log",
  source_label: "Windows signal",
};

const previewIncident: Incident = {
  id: "preview-incident",
  created_at: ago(1),
  description: "Games started closing after launch",
  subsystem: "graphics",
  onset_start: ago(2),
  onset_end: ago(1),
  lookback_days: 7,
  affected_entity: null,
  suspected_change: null,
  status: "investigating",
  assessment: "insufficient_evidence",
  assessment_reasons: ["The top-ranked change has compatible timing, but the symptom record is not specific enough to establish a strong lead."],
  coverage: { known: true, limited: false, reasons: [] },
  feedback: { outcome: null, event_id: null, recorded_at: null },
  results: [
    {
      event: graphicsChange,
      tie_count: 1,
      support_level: "moderate",
      evidence: [
        { signal: "temporal proximity", strength: "strong", explanation: "This change was recorded 13.0 hours before the selected onset. Timing determines rank but does not establish a connection.", event_id: graphicsChange.id },
        { signal: "subsystem relevance", strength: "strong", explanation: "The change and problem are both in the graphics area.", event_id: graphicsChange.id },
        { signal: "baseline break", strength: "strong", explanation: "1 related symptom record appeared after this change was recorded and before the problem window ended.", event_id: symptom.id },
      ],
      counter_evidence: [{ signal: "limited symptom specificity", strength: "moderate", explanation: "The recorded symptom is compatible but does not identify which component produced it.", event_id: symptom.id }],
      next_action: "In Device Manager, compare the current driver provider, version, and date with this journaled change. Do not roll back a driver based on rank alone.",
      safe_diagnostic: { label: "Device Manager", target: "devmgmt.msc", note: "Opening this surface does not change system state." },
    },
  ],
};

const validation: ValidationReport = {
  period: { start: ago(24 * 7), end: new Date().toISOString(), days: 7 },
  scans: { total: 14, by_status: { ok: 14 }, quiet: 10, quiet_rate: 10 / 14, with_changes: 4, with_symptoms: 2, reported_changes: 4, reported_symptoms: 2, provider_error_count: 0, error_buckets: {}, sources_per_scan_mean: 8, change_bearing_scan_rate: 4 / 14 },
  journal: { changes: 4, symptoms: 2, changes_per_day: 0.57, changes_by_source: { drivers: 1, apps: 1, devices: 1, services: 1 }, changes_by_subsystem: { graphics: 1, application: 1, device: 1, startup: 1 }, symptoms_by_subsystem: { graphics: 1, application: 1 } },
  overhead: { measurements: 2, first_measured_at: ago(48), last_measured_at: ago(4), cpu_percent_mean: 1.1, cpu_percent_peak: 1.6, rss_mb_mean: 82, rss_mb_peak: 182, disk_read_mb_total: 8.2, disk_write_mb_total: 0.01, startup_cpu_percent_peak: 2.1, startup_rss_mb_peak: 148 },
  investigations: { total: 2, with_feedback: 1, outcomes: { helpful: 1, not_helpful: 0, unsure: 0 }, helpful_lead_top3_hits: 1, helpful_lead_top3_rate: 1, helpful_lead_rank_distribution: { rank_1: 1, rank_2: 0, rank_3: 0, outside_top3: 0 }, assessment_distribution: { insufficient_evidence: 1, candidate_found: 1 } },
  privacy: "Aggregate local report; raw evidence and paths are omitted.",
  limits: ["This report measures collection and labeled ranking feedback; it is not causal proof.", "Longer and cross-machine data is still needed."],
};

const automation: AutomationSummary = {
  config: {
    interval_seconds: 300,
    notifications_enabled: true,
    notify_on_crashes: true,
    notify_on_changes: true,
    notify_on_warnings: true,
    draft_investigations: true,
  },
  watcher: {
    task_name: "Difftrail Watcher",
    supported: false,
    installed: false,
    running: false,
    state: null,
    last_run_at: null,
    next_run_at: null,
    last_task_result: null,
    needs_repair: false,
    message: "Connect the local journal to control background automation.",
  },
  notifications: { unread: 0, recent: [] },
  drafts: 0,
};

export function makePreviewBootstrap(): Bootstrap {
  return {
    version: "preview",
    status: {
      events: 6,
      changes: 4,
      symptoms: 2,
      incidents: 1,
      retention_days: 30,
      last_scan: { finished_at: ago(0.5), status: "ok", summary: { scan_id: "preview-scan", status: "ok", sources: 8, state_events: 0, symptom_events: 0, collected_sources: ["updates", "apps", "drivers", "services", "tasks", "startup", "devices", "eventlog"], failed_sources: [], errors: [] } },
      sources: [
        ["updates", "Windows updates"], ["apps", "Applications"], ["drivers", "Drivers"], ["services", "Services"], ["tasks", "Scheduled tasks"], ["startup", "Startup entries"], ["devices", "Devices"], ["eventlog", "Windows signals"],
      ].map(([source, label]) => ({ source, label, initialized: true, item_count: source === "drivers" ? 12 : source === "eventlog" ? 2 : 5, last_seen_at: ago(0.5), last_successful_at: ago(0.5), status: "capturing" })),
      schema: { current_version: 5, supported_version: 5, up_to_date: true },
      journal: { ok: true, integrity: "ok", schema: { current_version: 5, supported_version: 5, up_to_date: true }, scans: { running: 0, stale_running: [], stale_after_seconds: 900 }, journal: { events: 6, state_items: 36, incidents: 1 } },
      host: { captured_at_epoch: Math.floor(Date.now() / 1000), uptime_seconds: 172800, memory_total_bytes: 34_359_738_368, memory_available_bytes: 18_253_611_008, memory_used_percent: 46.9, system_disk_total_bytes: 1_000_000_000_000, system_disk_free_bytes: 420_000_000_000, system_disk_used_percent: 58 },
    },
    events: [symptom, graphicsChange, { ...graphicsChange, id: "preview-app-update", occurred_at: ago(17), subsystem: "application", title: "Discord updated", entity: "Discord", severity: "low", source: "apps", source_label: "Application" }, { ...graphicsChange, id: "preview-service", occurred_at: ago(30), subsystem: "startup", title: "Background service added", entity: "Difftrail Fixture Helper", severity: "medium", source: "services", source_label: "Service" }],
    incidents: [previewIncident],
    validation,
    automation,
  };
}
