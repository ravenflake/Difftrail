export type View = "home" | "timeline" | "investigate" | "incidents" | "health" | "automation";

export type EventKind = "change" | "symptom";
export type Confidence = "High" | "Medium" | "Low";
export type AssessmentState = "candidate_found" | "insufficient_evidence" | "no_recent_changes" | "limited_coverage";

export interface EventDetailSummary {
  application_name?: string;
  event_id?: number;
  log_name?: string;
  provider?: string;
  record_id?: string;
  changed_fields?: string[];
  before?: Record<string, string | number | boolean>;
  after?: Record<string, string | number | boolean>;
  raw_message_retained?: boolean;
}

export interface EventRecord {
  id: string | null;
  occurred_at: string;
  kind: EventKind;
  subsystem: string;
  action: string;
  title: string;
  entity: string;
  severity: string;
  source: string;
  source_label?: string;
  detail_summary?: EventDetailSummary;
}

export interface Evidence {
  signal: string;
  strength: string;
  explanation: string;
  event_id?: string | null;
}

export interface Hypothesis {
  event: EventRecord;
  score: number;
  tie_count: number;
  confidence: Confidence;
  evidence: Evidence[];
  counter_evidence: Evidence[];
  next_action: string;
  safe_diagnostic: {
    label: string;
    target: string;
    note: string;
  };
}

export interface Feedback {
  outcome: "correct" | "incorrect" | "unknown" | null;
  event_id: string | null;
  recorded_at: string | null;
}

export interface Incident {
  id: string;
  created_at: string;
  description: string;
  subsystem: string;
  onset_start: string;
  onset_end: string;
  lookback_days: number;
  affected_entity: string | null;
  suspected_change: string | null;
  status: string;
  assessment: AssessmentState;
  assessment_reasons: string[];
  coverage: {
    known?: boolean;
    limited?: boolean;
    reasons?: string[];
    uninitialized_sources?: string[];
  };
  results: Hypothesis[];
  feedback: Feedback;
}

export interface ScanSummary {
  scan_id: string;
  status: string;
  sources: number;
  state_events: number;
  symptom_events: number;
  errors: string[];
  error_count?: number;
  error_buckets?: string[];
}

export interface OverheadResponse {
  measurement_id: string;
  report: {
    status: string;
    interval_seconds: number;
    warmup_seconds: number;
    sample_seconds: number;
    startup_process_tree_cpu_percent: number;
    process_tree_cpu_percent: number;
    startup_rss_mb_peak: number;
    rss_mb_mean: number;
    rss_mb_peak: number;
    startup_disk_read_mb: number;
    startup_disk_write_mb: number;
    disk_read_mb: number;
    disk_write_mb: number;
    sample_count: number;
    scope: string;
  };
}

export interface LastScan {
  finished_at: string | null;
  status: string;
  summary: ScanSummary;
}

export interface SourceStatus {
  source: string;
  label: string;
  initialized: boolean;
  item_count: number;
  last_seen_at: string | null;
  status: string;
}

export interface Status {
  events: number;
  changes: number;
  symptoms: number;
  incidents: number;
  retention_days: number;
  sources: SourceStatus[];
  last_scan: LastScan | null;
  schema: {
    current_version: number;
    supported_version: number;
    up_to_date: boolean;
  };
  journal: {
    ok: boolean;
    integrity: string;
    schema: {
      current_version: number;
      supported_version: number;
      up_to_date: boolean;
    };
    scans: { running: number; stale_running: Array<{ id: string; started_at: string }>; stale_after_seconds: number };
    journal: { events: number; state_items: number; incidents: number };
  };
}

export interface ValidationReport {
  period: { start: string; end: string; days: number };
  scans: {
    total: number;
    by_status: Record<string, number>;
    quiet: number;
    quiet_rate: number | null;
    with_changes: number;
    with_symptoms: number;
    reported_changes: number;
    reported_symptoms: number;
    provider_error_count: number;
    error_buckets: Record<string, number>;
    sources_per_scan_mean: number | null;
    change_bearing_scan_rate: number | null;
  };
  journal: {
    changes: number;
    symptoms: number;
    changes_per_day: number;
    changes_by_source: Record<string, number>;
    changes_by_subsystem: Record<string, number>;
    symptoms_by_subsystem: Record<string, number>;
  };
  overhead: {
    measurements: number;
    first_measured_at: string | null;
    last_measured_at: string | null;
    cpu_percent_mean: number | null;
    cpu_percent_peak: number | null;
    rss_mb_mean: number | null;
    rss_mb_peak: number | null;
    disk_read_mb_total: number;
    disk_write_mb_total: number;
    startup_cpu_percent_peak: number | null;
    startup_rss_mb_peak: number | null;
  };
  investigations: {
    total: number;
    with_feedback: number;
    outcomes: { correct: number; incorrect: number; unknown: number };
    correct_cause_top3_hits: number;
    correct_cause_top3_rate: number | null;
    correct_cause_rank_distribution: Record<string, number>;
    assessment_distribution: Record<string, number>;
  };
  privacy: string;
  limits: string[];
}

export interface AutomationConfig {
  interval_seconds: number;
  notifications_enabled: boolean;
  notify_on_crashes: boolean;
  notify_on_changes: boolean;
  notify_on_warnings: boolean;
  draft_investigations: boolean;
}

export interface WatcherStatus {
  task_name: string;
  supported: boolean;
  installed: boolean;
  running: boolean;
  state: string | null;
  last_run_at: string | null;
  next_run_at: string | null;
  last_task_result: number | null;
  needs_repair: boolean;
  message: string | null;
}

export interface AutomationNotification {
  id: string;
  created_at: string;
  kind: string;
  title: string;
  body: string;
  event_id: string | null;
  incident_id: string | null;
  read_at: string | null;
}

export interface AutomationSummary {
  config: AutomationConfig;
  watcher: WatcherStatus;
  notifications: {
    unread: number;
    recent: AutomationNotification[];
  };
  drafts: number;
}

export interface Bootstrap {
  version: string;
  status: Status;
  events: EventRecord[];
  incidents: Incident[];
  validation: ValidationReport;
  automation: AutomationSummary;
}

export interface InvestigationResponse {
  summary: {
    description: string;
    subsystem: string;
    onset_start: string;
    onset_end: string;
    lookback_days: number;
    affected_entity: string | null;
    suspected_change: string | null;
    method: string;
    incident_id: string;
    assessment: {
      state: AssessmentState;
      reasons: string[];
      coverage: Record<string, unknown>;
    };
    hypotheses: Hypothesis[];
  };
  incident: Incident;
}

export interface InvestigationInput {
  description: string;
  subsystem?: string;
  onset?: string;
  lookback_days: number;
  affected_entity?: string;
  suspected_change?: string;
}

export interface BundleResponse {
  filename: string;
  bundle: Record<string, unknown>;
}

export interface TimelineFilters {
  kind: "all" | EventKind;
  subsystem: string;
  search: string;
}
