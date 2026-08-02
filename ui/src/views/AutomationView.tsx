import { useEffect, useRef, useState } from "react";
import type { AutomationConfig, AutomationNotification, AutomationSummary, View } from "../types";
import { formatDateTime, relativeTime } from "../format";
import { Icon } from "../components/Icon";

interface Props {
  automation: AutomationSummary;
  connection: "local" | "preview";
  busy: "config" | "enable" | "disable" | "run" | "read" | null;
  error: string | null;
  onConfigSave: (config: AutomationConfig) => Promise<void>;
  onWatcherAction: (action: "enable" | "disable" | "run", intervalSeconds?: number) => Promise<boolean>;
  onMarkRead: () => Promise<void>;
  onNavigate: (view: View) => void;
}

const intervalOptions = [
  { value: 300, label: "Every 5 minutes" },
  { value: 900, label: "Every 15 minutes" },
  { value: 1800, label: "Every 30 minutes" },
  { value: 3600, label: "Every hour" },
];

export function AutomationView({ automation, connection, busy, error, onConfigSave, onWatcherAction, onMarkRead, onNavigate }: Props) {
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
  const canControl = connection === "local" && watcher.supported;
  const intervalChanged = draft.interval_seconds !== automation.config.interval_seconds;
  const rulesDirty = JSON.stringify({ ...draft, interval_seconds: automation.config.interval_seconds }) !== JSON.stringify(automation.config);
  const statusLabel = !watcher.supported ? "Unavailable" : watcherRunning ? "Up to date" : watcherInstalled ? "Not running" : "Not enabled";
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
        <h2>Automation</h2>
        <p>Keep the evidence loop running in the background and bring only meaningful signals back to you.</p>
      </section>

      <div className="automation-grid">
        <section className="panel automation-panel automation-watcher-panel">
          <div className="section-heading">
            <div><h3>Background watcher</h3><span className="section-subtitle">The existing read-only collector, managed through Windows Task Scheduler.</span></div>
            <span className={`automation-badge ${watcherRunning ? "is-enabled" : watcherInstalled ? "is-attention" : ""}`}><span className="status-dot" />{statusLabel}</span>
          </div>

          <div className={`automation-status-block ${watcherRunning ? "is-enabled" : watcherInstalled ? "is-attention" : ""}`}>
            <div className="automation-status-icon"><Icon name={watcherRunning ? "check" : watcherInstalled ? "alert" : "clock"} size={20} /></div>
            <div className="automation-status-copy">
              <strong>{watcherRunning ? "Journal is up to date" : watcherInstalled ? "Watcher is enabled but not running" : "Background collection is off"}</strong>
              <span>{watcher.message || (watcherRunning ? `Watching for changes and checking every ${formatInterval(automation.config.interval_seconds)}.` : "Enable the watcher when you want scans without opening the app.")}</span>
            </div>
          </div>

          <div className="automation-meta-grid">
            <AutomationMeta label="Interval" value={formatInterval(automation.config.interval_seconds)} />
            <AutomationMeta label="Last task run" value={watcher.last_run_at ? relativeTime(watcher.last_run_at) : "Not recorded"} detail={watcher.last_run_at ? formatDateTime(watcher.last_run_at) : undefined} />
            <AutomationMeta label="Next task run" value={watcher.next_run_at ? relativeTime(watcher.next_run_at) : "At next logon"} detail={watcher.next_run_at ? formatDateTime(watcher.next_run_at) : undefined} />
          </div>

          <div className="automation-actions">
            <button type="button" className="button button-primary" onClick={() => void handleIntervalApply()} disabled={!canControl || !intervalChanged || intervalApplied || busy !== null} aria-busy={busy === "enable"}>{busy === "enable" ? "Applying..." : intervalApplied ? "Done" : "Apply interval"}</button>
            <button type="button" className="button button-secondary" onClick={() => void onWatcherAction("run")} disabled={!canControl || busy !== null} aria-busy={busy === "run"}>{busy === "run" ? "Scanning..." : "Run now"}</button>
            {watcherInstalled && <button type="button" className="button button-tertiary" onClick={() => void onWatcherAction("disable")} disabled={!canControl || busy !== null} aria-busy={busy === "disable"}>{busy === "disable" ? "Disabling..." : "Disable"}</button>}
          </div>
          {!canControl && <p className="panel-footnote">{connection === "preview" ? "Connect the local journal to manage automation." : watcher.message || "This control is only available on Windows."}</p>}
        </section>

        <section className="panel automation-panel automation-rules-panel">
          <div className="section-heading"><div><h3>Rules</h3><span className="section-subtitle">Choose what earns a notification or a draft.</span></div></div>
          <fieldset className="automation-fieldset">
            <legend>Scan interval</legend>
            <label className="automation-select-label"><span>Run a scan</span><select aria-label="Scan interval" value={draft.interval_seconds} onChange={(event) => handleIntervalChange(Number(event.target.value))}>{intervals.map((option) => <option value={option.value} key={option.value}>{option.label}</option>)}</select></label>
          </fieldset>
          <fieldset className="automation-fieldset automation-rules">
            <legend>Automation rules</legend>
            <RuleToggle checked={draft.notifications_enabled} onChange={() => setBoolean("notifications_enabled")} label="Show local notifications" note="Keep a small inbox of actionable signals." />
            <RuleToggle checked={draft.notify_on_crashes} onChange={() => setBoolean("notify_on_crashes")} label="High-severity symptoms" note="Crashes, hangs, resets, and similar signals." disabled={!draft.notifications_enabled} />
            <RuleToggle checked={draft.notify_on_changes} onChange={() => setBoolean("notify_on_changes")} label="Meaningful system changes" note="High-impact changes only; routine churn stays quiet." disabled={!draft.notifications_enabled} />
            <RuleToggle checked={draft.notify_on_warnings} onChange={() => setBoolean("notify_on_warnings")} label="Scan warnings" note="Provider coverage problems and partial scans." disabled={!draft.notifications_enabled} />
            <RuleToggle checked={draft.draft_investigations} onChange={() => setBoolean("draft_investigations")} label="Draft investigations" note="Prepare a reviewable incident for high-severity symptoms." />
          </fieldset>
          <div className="automation-actions"><button type="button" className="button button-primary" onClick={() => void onConfigSave({ ...draft, interval_seconds: automation.config.interval_seconds })} disabled={!canControl || !rulesDirty || intervalChanged || busy !== null} aria-busy={busy === "config"}>{busy === "config" ? "Saving..." : "Save rules"}</button><span className="muted-count">{intervalChanged ? "Apply interval first" : rulesDirty ? "Unsaved changes" : "Saved"}</span></div>
        </section>

        <section className="panel automation-panel automation-inbox-panel">
          <div className="section-heading">
            <div><h3>Automation inbox</h3><span className="section-subtitle">{automation.notifications.unread ? `${automation.notifications.unread} unread notification${automation.notifications.unread === 1 ? "" : "s"}.` : "No unread notifications."}</span></div>
            <div className="automation-inbox-actions"><span className="muted-count">{automation.drafts} draft{automation.drafts === 1 ? "" : "s"}</span>{automation.notifications.unread > 0 && <button type="button" className="quiet-link" onClick={() => void onMarkRead()} disabled={busy !== null}>{busy === "read" ? "Marking read..." : "Mark all read"}</button>}</div>
          </div>
          {automation.notifications.recent.length ? <div className="automation-notification-list">{automation.notifications.recent.map((notification) => <NotificationRow key={notification.id} notification={notification} onNavigate={onNavigate} />)}</div> : <div className="inline-empty"><Icon name="check" size={18} /><p>The inbox is clear. New high-value signals will appear here after a scan.</p></div>}
        </section>
      </div>

      {error && <div className="form-error" role="alert"><Icon name="alert" size={14} /> {error}</div>}
      <p className="panel-footnote automation-boundary">Automation observes, records, and drafts. It does not change Windows settings or apply remediation without your action.</p>
    </div>
  );
}

function AutomationMeta({ label, value, detail }: { label: string; value: string; detail?: string }) {
  return <div className="automation-meta"><span>{label}</span><strong>{value}</strong>{detail && <small>{detail}</small>}</div>;
}

function RuleToggle({ checked, onChange, label, note, disabled = false }: { checked: boolean; onChange: () => void; label: string; note: string; disabled?: boolean }) {
  return <label className={`automation-rule ${disabled ? "is-disabled" : ""}`}><input type="checkbox" checked={checked} onChange={onChange} disabled={disabled} /><span className="automation-rule-copy"><strong>{label}</strong><small>{note}</small></span></label>;
}

function NotificationRow({ notification, onNavigate }: { notification: AutomationNotification; onNavigate: (view: View) => void }) {
  const icon = notification.kind === "warning" ? "alert" : notification.kind === "change" ? "change" : "symptom";
  return <article className={`automation-notification ${notification.read_at ? "" : "is-unread"}`}><span className="automation-notification-icon"><Icon name={icon} size={16} /></span><div className="automation-notification-copy"><div><strong>{notification.title}</strong>{!notification.read_at && <span className="automation-unread">New</span>}</div><p>{notification.body}</p><small>{relativeTime(notification.created_at)} · {formatDateTime(notification.created_at)}</small></div>{notification.incident_id && <button type="button" className="quiet-link" onClick={() => onNavigate("incidents")}>Review draft <Icon name="arrow" size={13} /></button>}</article>;
}

function formatInterval(seconds: number): string {
  if (seconds % 3600 === 0) return `${seconds / 3600} hour${seconds === 3600 ? "" : "s"}`;
  if (seconds % 60 === 0) return `${seconds / 60} minutes`;
  return `${seconds} seconds`;
}
