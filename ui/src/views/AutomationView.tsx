import { useEffect, useRef, useState } from "react";
import type { AutomationConfig, AutomationNotification, AutomationSummary } from "../types";
import { formatDateTime, relativeTime } from "../format";
import { Icon } from "../components/Icon";

interface Props {
  automation: AutomationSummary;
  connection: "local" | "preview";
  busy: "config" | "enable" | "disable" | "run" | "read" | null;
  error: string | null;
  notice: string | null;
  onConfigSave: (config: AutomationConfig) => Promise<void>;
  onWatcherAction: (action: "enable" | "disable" | "run", intervalSeconds?: number) => Promise<boolean>;
  onMarkRead: () => Promise<void>;
  onOpenReview: (incidentId: string) => void;
}

const intervalOptions = [
  { value: 300, label: "Every 5 minutes" },
  { value: 600, label: "Every 10 minutes" },
  { value: 900, label: "Every 15 minutes" },
  { value: 1800, label: "Every 30 minutes" },
  { value: 3600, label: "Every hour" },
  { value: 7200, label: "Every 2 hours" },
  { value: 21600, label: "Every 6 hours" },
  { value: 43200, label: "Every 12 hours" },
  { value: 86400, label: "Every day" },
];

export function AutomationView({ automation, connection, busy, error, notice, onConfigSave, onWatcherAction, onMarkRead, onOpenReview }: Props) {
  const [draft, setDraft] = useState<AutomationConfig>(automation.config);
  const [intervalApplied, setIntervalApplied] = useState(false);
  const intervalDoneTimer = useRef<number | null>(null);
  useEffect(() => setDraft(automation.config), [automation.config]);
  useEffect(() => () => {
    if (intervalDoneTimer.current !== null) window.clearTimeout(intervalDoneTimer.current);
  }, []);

  const watcher = automation.watcher;
  const watcherInstalled = watcher.installed && watcher.state?.toLowerCase() !== "disabled";
  const watcherRunning = watcherInstalled && watcher.running;
  const watcherAttention = watcherInstalled && (watcher.needs_repair || (!watcherRunning && watcher.last_task_result !== null && watcher.last_task_result !== 0));
  const watcherNeedsSetup = !watcherInstalled || watcher.needs_repair;
  const watcherActionLabel = watcher.needs_repair ? "Update watcher" : !watcherInstalled ? "Enable watcher" : "Save interval";
  const canControl = connection === "local" && watcher.supported;
  const intervalChanged = draft.interval_seconds !== automation.config.interval_seconds;
  const rulesDirty = JSON.stringify({ ...draft, interval_seconds: automation.config.interval_seconds }) !== JSON.stringify(automation.config);
  const statusLabel = !watcher.supported ? "Unavailable" : watcherAttention ? "Needs attention" : watcherRunning ? "Scanning" : watcherInstalled ? "Enabled" : "Not enabled";
  const intervals = intervalOptions.some((option) => option.value === draft.interval_seconds)
    ? intervalOptions
    : [{ value: draft.interval_seconds, label: `Every ${formatInterval(draft.interval_seconds)}` }, ...intervalOptions];

  const setBoolean = (key: keyof Pick<AutomationConfig, "notifications_enabled" | "notify_on_crashes" | "notify_on_changes" | "notify_on_warnings" | "draft_investigations">) => {
    setDraft((current) => ({ ...current, [key]: !current[key] }));
  };

  const handleIntervalChange = (intervalSeconds: number) => {
    if (intervalDoneTimer.current !== null) {
      window.clearTimeout(intervalDoneTimer.current);
      intervalDoneTimer.current = null;
    }
    setIntervalApplied(false);
    setDraft((current) => ({ ...current, interval_seconds: intervalSeconds }));
  };

  const handleIntervalApply = async () => {
    const applied = await onWatcherAction("enable", draft.interval_seconds);
    if (!applied) return;
    if (intervalDoneTimer.current !== null) window.clearTimeout(intervalDoneTimer.current);
    setIntervalApplied(true);
    intervalDoneTimer.current = window.setTimeout(() => {
      setIntervalApplied(false);
      intervalDoneTimer.current = null;
    }, 2000);
  };

  return (
    <div className="page-stack">
      <section className="view-header">
        <h2>Background scans</h2>
        <p>Schedule read-only snapshots and choose which fixed rule matches appear locally for review.</p>
      </section>
      {error && <div className="form-error automation-feedback" role="alert"><Icon name="alert" size={14} /> {error}</div>}
      {notice && <div className="automation-run-notice automation-feedback" role="status"><Icon name="check" size={14} /> {notice}</div>}

      <div className="automation-grid">
        <section className="panel automation-panel automation-watcher-panel">
          <div className="section-heading">
            <div><h3>Scheduled snapshots</h3><span className="section-subtitle">Difftrail&apos;s read-only collector, managed through its own Windows scheduled task.</span></div>
            <span className={`automation-badge ${watcherAttention ? "is-attention" : watcherInstalled ? "is-enabled" : ""}`}><span className="status-dot" />{statusLabel}</span>
          </div>

          <div className={`automation-status-block ${watcherAttention ? "is-attention" : watcherInstalled ? "is-enabled" : ""}`}>
            <div className="automation-status-icon"><Icon name={watcherAttention ? "alert" : watcherInstalled ? "check" : "clock"} size={20} /></div>
            <div className="automation-status-copy">
              <strong>{watcherAttention ? "Background collection needs attention" : watcherRunning ? "A background scan is running" : watcherInstalled ? "Background collection is enabled" : "Background collection is off"}</strong>
              <span>{watcher.message || (watcherRunning ? "The local journal is being refreshed now." : watcherInstalled ? `Background scans are scheduled every ${formatInterval(automation.config.interval_seconds)}.` : "Enable the watcher when you want scans without opening the app.")}</span>
            </div>
          </div>

          <div className="automation-interval-control">
            <label htmlFor="watcher-interval"><strong>Background scan interval</strong><span>Five minutes is the default. Longer intervals reduce scan frequency.</span></label>
            <select id="watcher-interval" aria-label="Background scan interval" value={draft.interval_seconds} onChange={(event) => handleIntervalChange(Number(event.target.value))} disabled={!canControl || busy !== null}>{intervals.map((option) => <option value={option.value} key={option.value}>{option.label}</option>)}</select>
          </div>

          <div className="automation-meta-grid">
            <AutomationMeta label="Interval" value={formatInterval(automation.config.interval_seconds)} />
            <AutomationMeta label={watcher.needs_repair ? "Registered task last run" : "Last background scan"} value={watcher.last_run_at ? relativeTime(watcher.last_run_at) : "Not recorded"} detail={watcher.last_run_at ? formatDateTime(watcher.last_run_at) : undefined} />
            <AutomationMeta label={watcher.needs_repair ? "Registered task next run" : "Next background scan"} value={watcher.next_run_at ? relativeTime(watcher.next_run_at) : "At next logon"} detail={watcher.next_run_at ? formatDateTime(watcher.next_run_at) : undefined} />
          </div>
          {watcher.needs_repair && <p className="panel-footnote">These times belong to the registered Windows task. Update the watcher before treating them as activity for this journal.</p>}

          <div className="automation-actions">
            <button type="button" className="button button-primary" onClick={() => void handleIntervalApply()} disabled={!canControl || (!intervalChanged && !watcherNeedsSetup) || intervalApplied || busy !== null} aria-busy={busy === "enable"}>{busy === "enable" ? (watcher.needs_repair ? "Updating..." : watcherNeedsSetup ? "Enabling..." : "Saving...") : intervalApplied ? "Saved" : watcherActionLabel}</button>
            <button type="button" className="button button-secondary" onClick={() => void onWatcherAction("run")} disabled={!canControl || busy !== null} aria-busy={busy === "run"}>{busy === "run" ? "Scanning..." : "Scan now"}</button>
            {watcherInstalled && <button type="button" className="button button-tertiary" onClick={() => void onWatcherAction("disable")} disabled={!canControl || busy !== null} aria-busy={busy === "disable"}>{busy === "disable" ? "Disabling..." : "Disable"}</button>}
          </div>
          {!canControl && <p className="panel-footnote">{connection === "preview" ? "Connect the local journal to manage automation." : watcher.message || "This control is only available on Windows."}</p>}
        </section>

        <section className="panel automation-panel automation-rules-panel">
          <div className="section-heading"><div><h3>Signals and draft reviews</h3><span className="section-subtitle">Choose which fixed rule matches create a local notification or saved evidence review.</span></div></div>
          <fieldset className="automation-fieldset automation-rules">
            <legend>Automation rules</legend>
            <RuleToggle checked={draft.notifications_enabled} onChange={() => setBoolean("notifications_enabled")} label="Show local notifications" note="Keep a small inbox of selected signals to review." />
            <RuleToggle checked={draft.notify_on_crashes} onChange={() => setBoolean("notify_on_crashes")} label="High-severity symptoms" note="Crashes, hangs, resets, and similar signals." disabled={!draft.notifications_enabled} />
            <RuleToggle checked={draft.notify_on_changes} onChange={() => setBoolean("notify_on_changes")} label="Selected system changes" note="Fixed high-impact categories only; routine churn stays quiet." disabled={!draft.notifications_enabled} />
            <RuleToggle checked={draft.notify_on_warnings} onChange={() => setBoolean("notify_on_warnings")} label="Scan warnings" note="Provider coverage problems and partial scans." disabled={!draft.notifications_enabled} />
            <RuleToggle checked={draft.draft_investigations} onChange={() => setBoolean("draft_investigations")} label="Draft evidence reviews" note="Save a problem window around a high-severity symptom. Drafts are not diagnoses." />
          </fieldset>
          <div className="automation-actions"><button type="button" className="button button-primary" onClick={() => void onConfigSave({ ...draft, interval_seconds: automation.config.interval_seconds })} disabled={!canControl || !rulesDirty || intervalChanged || busy !== null} aria-busy={busy === "config"}>{busy === "config" ? "Saving..." : "Save rules"}</button><span className="muted-count">{intervalChanged ? "Apply interval first" : rulesDirty ? "Unsaved changes" : "Saved"}</span></div>
        </section>

        <section className="panel automation-panel automation-inbox-panel">
          <div className="section-heading">
            <div><h3>Signals inbox</h3><span className="section-subtitle">{automation.notifications.unread ? `${automation.notifications.unread} unread signal${automation.notifications.unread === 1 ? "" : "s"}.` : "No unread signals."} A signal invites evidence review; it does not identify a cause.</span></div>
            <div className="automation-inbox-actions"><span className="muted-count">{automation.drafts} draft review{automation.drafts === 1 ? "" : "s"}</span>{automation.notifications.unread > 0 && <button type="button" className="quiet-link" onClick={() => void onMarkRead()} disabled={busy !== null}>{busy === "read" ? "Marking read..." : "Mark all read"}</button>}</div>
          </div>
          {automation.notifications.recent.length ? <div className="automation-notification-list">{automation.notifications.recent.map((notification) => <NotificationRow key={notification.id} notification={notification} onOpenReview={onOpenReview} />)}</div> : <div className="inline-empty"><Icon name="check" size={18} /><p>No rule-matched signals yet. Scheduled scans continue to record evidence even when this inbox stays quiet.</p></div>}
        </section>
      </div>
      <p className="panel-footnote automation-boundary">Collection only observes Windows state. These controls manage Difftrail&apos;s own scheduled task and local notifications; they do not repair, roll back, or change the observed system.</p>
    </div>
  );
}

function AutomationMeta({ label, value, detail }: { label: string; value: string; detail?: string }) {
  return <div className="automation-meta"><span>{label}</span><strong>{value}</strong>{detail && <small>{detail}</small>}</div>;
}

function RuleToggle({ checked, onChange, label, note, disabled = false }: { checked: boolean; onChange: () => void; label: string; note: string; disabled?: boolean }) {
  return <label className={`automation-rule ${disabled ? "is-disabled" : ""}`}><input type="checkbox" checked={checked} onChange={onChange} disabled={disabled} /><span className="automation-rule-copy"><strong>{label}</strong><small>{note}</small></span></label>;
}

function NotificationRow({ notification, onOpenReview }: { notification: AutomationNotification; onOpenReview: (incidentId: string) => void }) {
  const icon = notification.kind === "warning" ? "alert" : notification.kind === "change" ? "change" : "symptom";
  return <article className={`automation-notification ${notification.read_at ? "" : "is-unread"}`}><span className="automation-notification-icon"><Icon name={icon} size={16} /></span><div className="automation-notification-copy"><div><strong>{notification.title}</strong>{!notification.read_at && <span className="automation-unread">New</span>}</div><p>{notification.body}</p><small>{relativeTime(notification.created_at)} · {formatDateTime(notification.created_at)}</small></div>{notification.incident_id && <button type="button" className="quiet-link" onClick={() => onOpenReview(notification.incident_id!)}>Open draft review <Icon name="arrow" size={13} /></button>}</article>;
}

function formatInterval(seconds: number): string {
  if (seconds % 3600 === 0) return `${seconds / 3600} hour${seconds === 3600 ? "" : "s"}`;
  if (seconds % 60 === 0) return `${seconds / 60} minute${seconds === 60 ? "" : "s"}`;
  return `${seconds} seconds`;
}
