import { useCallback, useEffect, useMemo, useState } from "react";
import { createInvestigation, deleteInvestigation, exportBundle, loadBootstrap, loadTimeline, markAutomationNotificationsRead, recordFeedback, recordOverhead, runScan, updateAutomationConfig, updateAutomationWatcher, waitForApi } from "./api";
import { makePreviewBootstrap } from "./mock";
import type { AutomationConfig, Bootstrap, Incident, TimelineFilters, View } from "./types";
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
  const [loadError, setLoadError] = useState<string | null>(null);
  const [selectedIncidentId, setSelectedIncidentId] = useState<string | null>(null);
  const [automationBusy, setAutomationBusy] = useState<"config" | "enable" | "disable" | "run" | "read" | null>(null);
  const [automationError, setAutomationError] = useState<string | null>(null);
  const [automationNotice, setAutomationNotice] = useState<string | null>(null);

  const navigate = useCallback((next: View) => {
    window.location.hash = next;
    setView(next);
    if (next === "investigate") setSelectedIncidentId(null);
  }, []);

  const refresh = useCallback(async () => {
    setLoading(true);
    try {
      const next = await loadBootstrapWithRetry();
      setData(next);
      setConnection("local");
      setLoadError(null);
    } catch (reason) {
      setData(makePreviewBootstrap());
      setConnection("preview");
      setLoadError(reason instanceof Error ? reason.message : "The local journal is not available.");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void refresh();
    const onHashChange = () => setView(routeFromHash());
    window.addEventListener("hashchange", onHashChange);
    return () => window.removeEventListener("hashchange", onHashChange);
  }, [refresh]);

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
      setLoadError("Start the local Difftrail UI API to scan the real journal.");
      return;
    }
    setScanning(true);
    try { await runScan(); await refresh(); } catch (reason) { setLoadError(reason instanceof Error ? reason.message : "The scan could not be completed."); } finally { setScanning(false); }
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
      await refresh();
    } catch (reason) {
      setOverheadError(reason instanceof Error ? reason.message : "The watcher footprint could not be recorded.");
    } finally {
      setRecordingOverhead(false);
    }
  }, [connection, refresh]);

  const handleExportBundle = useCallback(async (incidentId?: string) => {
    if (connection === "preview") {
      setExportError("Connect the local journal to export a diagnostic report.");
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
      setExportError(reason instanceof Error ? reason.message : "The diagnostic bundle could not be exported.");
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

  const handleInvestigate = useCallback(async (input: { description: string; subsystem?: string; onset?: string; lookback_days: number }) => {
    if (connection === "preview") throw new Error("The local UI API is not connected. Start it to investigate the real journal.");
    const response = await createInvestigation(input);
    setData((current) => current ? { ...current, incidents: [response.incident, ...current.incidents.filter((incident) => incident.id !== response.incident.id)], status: { ...current.status, incidents: current.status.incidents + 1 } } : current);
    setSelectedIncidentId(response.incident.id);
    navigate("incidents");
    return response;
  }, [connection, navigate]);

  const handleFeedback = useCallback(async (incidentId: string, outcome: "correct" | "incorrect" | "unknown", eventId?: string) => {
    if (connection === "preview") throw new Error("Feedback is only saved when the local journal is connected.");
    const response = await recordFeedback(incidentId, outcome, eventId);
    setData((current) => current ? { ...current, incidents: current.incidents.map((incident) => incident.id === incidentId ? response.incident : incident) } : current);
  }, [connection]);

  const handleDeleteInvestigation = useCallback(async (incidentId: string) => {
    if (connection === "preview") throw new Error("Investigations can only be deleted from the local journal.");
    await deleteInvestigation(incidentId);
    setData((current) => current ? {
      ...current,
      incidents: current.incidents.filter((incident) => incident.id !== incidentId),
      status: { ...current.status, incidents: Math.max(0, current.status.incidents - 1) },
    } : current);
    setSelectedIncidentId(null);
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
        await refresh();
        if (response.scan) {
          const warning = response.scan.errors.length ? ` with ${response.scan.errors.length} warning${response.scan.errors.length === 1 ? "" : "s"}` : "";
          setAutomationNotice(`Scan completed${warning}: ${response.scan.state_events} changes and ${response.scan.symptom_events} symptoms recorded.`);
        }
      } else setData((current) => current ? { ...current, automation: response.automation } : current);
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

  if (loading || !data) return <LoadingScreen />;

  return (
    <AppShell view={view} status={data.status} version={data.version} connection={connection} scanning={scanning} onNavigate={navigate} onScan={handleScan}>
      {connection === "preview" && <div className="preview-notice" role="status"><Icon name="alert" size={15} /><span>Preview data is shown because the local journal is not connected{loadError ? ` · ${loadError}` : ""}.</span><button type="button" onClick={() => void refresh()}>Try again</button></div>}
      {view === "home" && <HomeView data={data} onNavigate={navigate} onOpenIncident={(incident) => { setSelectedIncidentId(incident.id); navigate("incidents"); }} />}
      {view === "timeline" && <TimelineView events={data.events} onLoad={handleLoadTimeline} />}
      {view === "investigate" && <InvestigateView busy={false} onInvestigate={handleInvestigate} />}
      {view === "incidents" && <IncidentsView incidents={data.incidents} selected={selectedIncident} onSelect={(incident) => setSelectedIncidentId(incident.id)} onNavigate={() => navigate("investigate")} onFeedback={handleFeedback} onExport={handleExportBundle} onDelete={handleDeleteInvestigation} exportBusy={exportBusy} exportError={exportError} />}
      {view === "health" && <HealthView data={data} onRecordOverhead={handleRecordOverhead} recording={recordingOverhead} error={overheadError} onExport={() => handleExportBundle()} exportBusy={exportBusy} exportError={exportError} />}
      {view === "automation" && <AutomationView automation={data.automation} connection={connection} busy={automationBusy} error={automationError} notice={automationNotice} onConfigSave={handleAutomationConfig} onWatcherAction={handleAutomationWatcher} onMarkRead={handleMarkAutomationRead} onNavigate={navigate} />}
    </AppShell>
  );
}

function LoadingScreen() {
  return <div className="loading-screen" role="status"><BrandMark size={52} className="loading-brand-mark" /><span>Opening the local journal…</span></div>;
}
