import { useCallback, useEffect, useMemo, useState } from "react";
import { createInvestigation, deleteInvestigation, exportBundle, loadBootstrap, loadTimeline, markAutomationNotificationsRead, recordFeedback, recordOverhead, runScan, updateAutomationConfig, updateAutomationWatcher, waitForApi } from "./api";
import { makePreviewBootstrap } from "./mock";
import type { AutomationConfig, Bootstrap, Incident, InvestigationInput, TimelineFilters, View } from "./types";
import { AppShell } from "./components/AppShell";
import { BrandMark } from "./components/BrandMark";
import { Icon } from "./components/Icon";
import { HomeView } from "./views/HomeView";
import { TimelineView } from "./views/TimelineView";
import { InvestigateView } from "./views/InvestigateView";
import { IncidentsView } from "./views/IncidentsView";
import { HealthView } from "./views/HealthView";
import { AutomationView } from "./views/AutomationView";

function routeFromHash(): View {
  const route = window.location.hash.replace(/^#/, "") as View;
  return ["home", "timeline", "investigate", "incidents", "health", "automation"].includes(route) ? route : "home";
}

async function loadBootstrapWithRetry() {
  let lastError: unknown;
  for (let attempt = 0; attempt < 4; attempt += 1) {
    try {
      await waitForApi();
      return await loadBootstrap();
    } catch (reason) {
      lastError = reason;
      if (attempt < 3) await new Promise((resolve) => window.setTimeout(resolve, 150 * 2 ** attempt));
    }
  }
  throw lastError instanceof Error ? lastError : new Error("The local journal is not available.");
}

function removeIncidentFromBootstrap(current: Bootstrap, incidentId: string): Bootstrap {
  const removed = current.incidents.find((incident) => incident.id === incidentId);
  if (!removed) return current;
  return {
    ...current,
    incidents: current.incidents.filter((incident) => incident.id !== incidentId),
    status: {
      ...current.status,
      incidents: Math.max(0, current.status.incidents - 1),
      journal: {
        ...current.status.journal,
        journal: {
          ...current.status.journal.journal,
          incidents: Math.max(0, current.status.journal.journal.incidents - 1),
        },
      },
    },
    automation: {
      ...current.automation,
      drafts: removed.status === "draft" ? Math.max(0, current.automation.drafts - 1) : current.automation.drafts,
      notifications: {
        ...current.automation.notifications,
        recent: current.automation.notifications.recent.map((notification) => notification.incident_id === incidentId ? { ...notification, incident_id: null } : notification),
      },
    },
  };
}

export default function App() {
  const [view, setView] = useState<View>(routeFromHash);
  const [data, setData] = useState<Bootstrap | null>(null);
  const [connection, setConnection] = useState<"local" | "preview">("local");
  const [loading, setLoading] = useState(true);
  const [scanning, setScanning] = useState(false);
  const [recordingOverhead, setRecordingOverhead] = useState(false);
  const [overheadError, setOverheadError] = useState<string | null>(null);
  const [exportBusy, setExportBusy] = useState(false);
  const [exportError, setExportError] = useState<string | null>(null);
  const [deleteBusy, setDeleteBusy] = useState(false);
  const [deleteError, setDeleteError] = useState<string | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [scanError, setScanError] = useState<string | null>(null);
  const [scanNotice, setScanNotice] = useState<string | null>(null);
  const [selectedIncidentId, setSelectedIncidentId] = useState<string | null>(null);
  const [automationBusy, setAutomationBusy] = useState<"config" | "enable" | "disable" | "run" | "read" | null>(null);
  const [automationError, setAutomationError] = useState<string | null>(null);
  const [automationNotice, setAutomationNotice] = useState<string | null>(null);

  const navigate = useCallback((next: View) => {
    window.location.hash = next;
    setView(next);
    if (next === "investigate") setSelectedIncidentId(null);
    setExportError(null);
    setDeleteError(null);
    setScanError(null);
    setScanNotice(null);
  }, []);

  const refresh = useCallback(async (initial = false): Promise<boolean> => {
    if (initial) setLoading(true);
    try {
      const next = await loadBootstrapWithRetry();
      setData(next);
      setConnection("local");
      setLoadError(null);
      return true;
    } catch (reason) {
      const message = connectionErrorMessage(reason);
      if (initial) {
        if (import.meta.env.DEV) {
          setData(makePreviewBootstrap());
          setConnection("preview");
        } else {
          setData(null);
          setConnection("local");
        }
      }
      setLoadError(message);
      return false;
    } finally {
      if (initial) setLoading(false);
    }
  }, []);

  useEffect(() => {
    void refresh(true);
    const onHashChange = () => setView(routeFromHash());
    window.addEventListener("hashchange", onHashChange);
    return () => window.removeEventListener("hashchange", onHashChange);
  }, [refresh]);

  useEffect(() => {
    if (view !== "incidents" || selectedIncidentId || !data?.incidents.length) return;
    setSelectedIncidentId(data.incidents[0].id);
  }, [data?.incidents, selectedIncidentId, view]);

  useEffect(() => {
    if (connection !== "local") return;
    const poll = window.setInterval(() => {
      void loadBootstrap()
        .then((next) => {
          setData(next);
          setLoadError(null);
        })
        .catch(() => {
          // Keep the last usable local state visible until the next retry.
        });
    }, 30_000);
    return () => window.clearInterval(poll);
  }, [connection]);

  const handleScan = useCallback(async () => {
    if (connection === "preview") {
      setScanError("Start the local Difftrail UI API to scan the real journal.");
      return;
    }
    setScanning(true);
    setScanError(null);
    setScanNotice(null);
    try {
      const response = await runScan();
      const refreshed = await refresh();
      const warnings = response.scan.error_count ?? response.scan.errors.length;
      const coverage = response.scan.collected_sources.length || response.scan.sources;
      const failedSources = response.scan.failed_sources.length ? ` (${response.scan.failed_sources.join(", ")})` : "";
      setScanNotice(`Scan completed: ${response.scan.state_events} changes and ${response.scan.symptom_events} symptoms recorded across ${coverage} source${coverage === 1 ? "" : "s"}${warnings ? ` · ${warnings} collection warning${warnings === 1 ? "" : "s"}${failedSources}` : ""}${refreshed ? "" : " · the view could not refresh yet"}.`);
    } catch (reason) {
      setScanError(reason instanceof Error ? reason.message : "The scan could not be completed.");
    } finally {
      setScanning(false);
    }
  }, [connection, refresh]);

  const handleRecordOverhead = useCallback(async () => {
    if (connection === "preview") {
      setOverheadError("Start the local Difftrail UI API to record a real watcher footprint.");
      return;
    }
    setRecordingOverhead(true);
    setOverheadError(null);
    try {
      await recordOverhead();
      const refreshed = await refresh();
      if (!refreshed) setOverheadError("The measurement was saved, but this view could not refresh yet.");
    } catch (reason) {
      setOverheadError(reason instanceof Error ? reason.message : "The watcher footprint could not be recorded.");
    } finally {
      setRecordingOverhead(false);
    }
  }, [connection, refresh]);

  const handleExportBundle = useCallback(async (incidentId?: string) => {
    if (connection === "preview") {
      setExportError("Connect the local journal to export a redacted evidence report.");
      return;
    }
    setExportBusy(true);
    setExportError(null);
    try {
      const response = await exportBundle(incidentId ? { incident_id: incidentId } : { days: 30 });
      const blob = new Blob([JSON.stringify(response.bundle, null, 2)], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = response.filename;
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.setTimeout(() => URL.revokeObjectURL(url), 0);
    } catch (reason) {
      setExportError(reason instanceof Error ? reason.message : "The redacted evidence report could not be exported.");
    } finally {
      setExportBusy(false);
    }
  }, [connection]);

  const handleLoadTimeline = useCallback(async (filters: TimelineFilters) => {
    if (connection === "preview" && data) {
      const needle = filters.search.trim().toLowerCase();
      return data.events.filter((event) => (filters.kind === "all" || event.kind === filters.kind) && (filters.subsystem === "all" || event.subsystem === filters.subsystem) && (!needle || `${event.title} ${event.entity} ${event.source}`.toLowerCase().includes(needle)));
    }
    return loadTimeline(filters);
  }, [connection, data]);

  const handleInvestigate = useCallback(async (input: InvestigationInput) => {
    if (connection === "preview") throw new Error("The local UI API is not connected. Start it to review the real journal.");
    const response = await createInvestigation(input);
    setData((current) => current ? { ...current, incidents: [response.incident, ...current.incidents.filter((incident) => incident.id !== response.incident.id)], status: { ...current.status, incidents: current.status.incidents + 1 } } : current);
    setSelectedIncidentId(response.incident.id);
    navigate("incidents");
    return response;
  }, [connection, navigate]);

  const handleFeedback = useCallback(async (incidentId: string, outcome: NonNullable<Incident["feedback"]["outcome"]>, eventId?: string) => {
    if (connection === "preview") throw new Error("Feedback is only saved when the local journal is connected.");
    const response = await recordFeedback(incidentId, outcome, eventId);
    setData((current) => current ? { ...current, incidents: current.incidents.map((incident) => incident.id === incidentId ? response.incident : incident) } : current);
  }, [connection]);

  const handleDeleteInvestigation = useCallback(async (incidentId: string) => {
    if (connection === "preview") {
      const error = new Error("Connect the local journal to remove an evidence review.");
      setDeleteError(error.message);
      throw error;
    }
    setDeleteBusy(true);
    setDeleteError(null);
    try {
      await deleteInvestigation(incidentId);
      try {
        const next = await loadBootstrap();
        setData(next);
        setSelectedIncidentId(next.incidents[0]?.id ?? null);
      } catch {
        setData((current) => current ? removeIncidentFromBootstrap(current, incidentId) : current);
        setSelectedIncidentId(null);
        setDeleteError("Evidence review removed, but the dashboard could not refresh.");
      }
    } catch (reason) {
      const error = reason instanceof Error ? reason : new Error("The evidence review could not be removed.");
      setDeleteError(error.message);
      throw error;
    } finally {
      setDeleteBusy(false);
    }
  }, [connection]);

  const handleAutomationConfig = useCallback(async (config: AutomationConfig) => {
    if (connection === "preview") {
      setAutomationError("Connect the local journal to save automation settings.");
      return;
    }
    setAutomationBusy("config");
    setAutomationError(null);
    setAutomationNotice(null);
    try {
      const response = await updateAutomationConfig(config);
      setData((current) => current ? { ...current, automation: response.automation } : current);
    } catch (reason) {
      setAutomationError(reason instanceof Error ? reason.message : "Automation settings could not be saved.");
    } finally {
      setAutomationBusy(null);
    }
  }, [connection]);

  const handleAutomationWatcher = useCallback(async (action: "enable" | "disable" | "run", intervalSeconds?: number): Promise<boolean> => {
    if (connection === "preview") {
      setAutomationError("Connect the local journal to control background automation.");
      return false;
    }
    setAutomationBusy(action);
    setAutomationError(null);
    setAutomationNotice(null);
    try {
      const interval = action === "enable" ? intervalSeconds ?? data?.automation.config.interval_seconds : undefined;
      const response = await updateAutomationWatcher(action, interval);
      if (action === "run") {
        const refreshed = await refresh();
        if (response.scan) {
          const warnings = response.scan.error_count ?? response.scan.errors.length;
          const failedSources = response.scan.failed_sources.length ? ` (${response.scan.failed_sources.join(", ")})` : "";
          const warning = warnings ? ` with ${warnings} collection warning${warnings === 1 ? "" : "s"}${failedSources}` : "";
          setAutomationNotice(`Scan completed${warning}: ${response.scan.state_events} changes and ${response.scan.symptom_events} symptoms recorded${refreshed ? "" : "; the view could not refresh yet"}.`);
        }
      } else {
        const installed = response.automation.watcher.installed && response.automation.watcher.state?.toLowerCase() !== "disabled";
        if (action === "enable" && !installed) throw new Error(response.automation.watcher.message || "The watcher did not remain enabled.");
        if (action === "disable" && installed) throw new Error(response.automation.watcher.message || "The watcher is still enabled.");
        setData((current) => current ? { ...current, automation: response.automation } : current);
        setAutomationNotice(action === "enable"
          ? `Background collection enabled. Difftrail will scan every ${formatInterval(response.automation.config.interval_seconds)}.`
          : "Background collection disabled. No scheduled scans will run until you enable it again.");
      }
      return true;
    } catch (reason) {
      setAutomationError(reason instanceof Error ? reason.message : "The automation action could not be completed.");
      return false;
    } finally {
      setAutomationBusy(null);
    }
  }, [connection, data?.automation.config.interval_seconds, refresh]);

  const handleMarkAutomationRead = useCallback(async () => {
    if (connection === "preview") return;
    setAutomationBusy("read");
    setAutomationError(null);
    try {
      const response = await markAutomationNotificationsRead();
      setData((current) => current ? { ...current, automation: response.automation } : current);
    } catch (reason) {
      setAutomationError(reason instanceof Error ? reason.message : "Notifications could not be marked as read.");
    } finally {
      setAutomationBusy(null);
    }
  }, [connection]);

  const selectedIncident = useMemo(() => data?.incidents.find((incident) => incident.id === selectedIncidentId) || null, [data, selectedIncidentId]);

  if (loading) return <LoadingScreen />;
  if (!data) return <UnavailableScreen message={loadError} onRetry={() => void refresh(true)} />;

  return (
    <AppShell view={view} status={data.status} version={data.version} connection={connection} scanning={scanning} onNavigate={navigate} onScan={handleScan}>
      {connection === "preview" && <div className="preview-notice" role="status"><Icon name="alert" size={15} /><span>Synthetic preview data is shown because the local journal is not connected. It is not evidence from this PC{loadError ? ` · ${loadError}` : ""}.</span><button type="button" onClick={() => void refresh(true)}>Try again</button></div>}
      {scanError && <div className="form-error global-action-feedback" role="alert"><Icon name="alert" size={14} /><span><strong>Scan did not complete.</strong> {scanError}</span></div>}
      {scanNotice && <div className="action-notice global-action-feedback" role="status"><Icon name="check" size={14} /> {scanNotice}</div>}
      {view === "home" && <HomeView data={data} connection={connection} onNavigate={navigate} onOpenIncident={(incident) => { setSelectedIncidentId(incident.id); navigate("incidents"); }} />}
      {view === "timeline" && <TimelineView events={data.events} onLoad={handleLoadTimeline} />}
      {view === "investigate" && <InvestigateView busy={false} connected={connection === "local"} onInvestigate={handleInvestigate} />}
      {view === "incidents" && <IncidentsView incidents={data.incidents} selected={selectedIncident} connected={connection === "local"} onSelect={(incident) => { setDeleteError(null); setSelectedIncidentId(incident.id); }} onNavigate={() => navigate("investigate")} onFeedback={handleFeedback} onDelete={handleDeleteInvestigation} onExport={handleExportBundle} exportBusy={exportBusy} exportError={exportError} deleteBusy={deleteBusy} deleteError={deleteError} />}
      {view === "health" && <HealthView data={data} connected={connection === "local"} onRecordOverhead={handleRecordOverhead} recording={recordingOverhead} error={overheadError} onExport={() => handleExportBundle()} exportBusy={exportBusy} exportError={exportError} />}
      {view === "automation" && <AutomationView automation={data.automation} connection={connection} busy={automationBusy} error={automationError} notice={automationNotice} onConfigSave={handleAutomationConfig} onWatcherAction={handleAutomationWatcher} onMarkRead={handleMarkAutomationRead} onOpenReview={(incidentId) => { setSelectedIncidentId(incidentId); navigate("incidents"); }} />}
    </AppShell>
  );
}

function formatInterval(seconds: number): string {
  if (seconds % 3600 === 0) return `${seconds / 3600} hour${seconds === 3600 ? "" : "s"}`;
  if (seconds % 60 === 0) return `${seconds / 60} minute${seconds === 60 ? "" : "s"}`;
  return `${seconds} seconds`;
}

function connectionErrorMessage(reason: unknown): string {
  const message = reason instanceof Error ? reason.message : "The local journal is not available";
  if (/failed to fetch/i.test(message)) return "The local API is not responding";
  return message.replace(/[.!?]+$/, "");
}

function LoadingScreen() {
  return <div className="loading-screen" role="status"><BrandMark size={52} className="loading-brand-mark" /><span>Opening the local journal…</span></div>;
}

function UnavailableScreen({ message, onRetry }: { message: string | null; onRetry: () => void }) {
  return <main className="unavailable-screen"><BrandMark size={52} className="loading-brand-mark" /><div><span className="eyebrow">Local journal unavailable</span><h1>Difftrail could not open its local evidence service.</h1><p>No sample results are being substituted. Your journal remains local and unchanged.</p>{message && <div className="unavailable-reason" role="alert">{message}</div>}<div className="unavailable-actions"><button type="button" className="button button-primary" onClick={onRetry}><Icon name="refresh" size={15} /> Try again</button><span>If this continues, restart Difftrail and check that its backend process is allowed to run.</span></div></div></main>;
}
