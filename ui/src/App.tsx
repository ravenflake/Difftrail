import { useCallback, useEffect, useMemo, useState } from "react";
import { createInvestigation, loadBootstrap, loadTimeline, recordFeedback, runScan, waitForApi } from "./api";
import { makePreviewBootstrap } from "./mock";
import type { Bootstrap, Incident, TimelineFilters, View } from "./types";
import { AppShell } from "./components/AppShell";
import { Icon } from "./components/Icon";
import { HomeView } from "./views/HomeView";
import { TimelineView } from "./views/TimelineView";
import { InvestigateView } from "./views/InvestigateView";
import { IncidentsView } from "./views/IncidentsView";
import { HealthView } from "./views/HealthView";

function routeFromHash(): View {
  const route = window.location.hash.replace(/^#/, "") as View;
  return ["home", "timeline", "investigate", "incidents", "health"].includes(route) ? route : "home";
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
  const [loadError, setLoadError] = useState<string | null>(null);
  const [selectedIncidentId, setSelectedIncidentId] = useState<string | null>(null);

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

  const handleScan = useCallback(async () => {
    if (connection === "preview") {
      setLoadError("Start the local Difftrail UI API to scan the real journal.");
      return;
    }
    setScanning(true);
    try { await runScan(); await refresh(); } catch (reason) { setLoadError(reason instanceof Error ? reason.message : "The scan could not be completed."); } finally { setScanning(false); }
  }, [connection, refresh]);

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

  const selectedIncident = useMemo(() => data?.incidents.find((incident) => incident.id === selectedIncidentId) || null, [data, selectedIncidentId]);

  if (loading || !data) return <LoadingScreen />;

  return (
    <AppShell view={view} status={data.status} version={data.version} connection={connection} scanning={scanning} onNavigate={navigate} onScan={handleScan}>
      {connection === "preview" && <div className="preview-notice" role="status"><Icon name="alert" size={15} /><span>Preview data is shown because the local journal is not connected{loadError ? ` · ${loadError}` : ""}.</span><button type="button" onClick={() => void refresh()}>Try again</button></div>}
      {view === "home" && <HomeView data={data} onNavigate={navigate} onOpenIncident={(incident) => { setSelectedIncidentId(incident.id); navigate("incidents"); }} />}
      {view === "timeline" && <TimelineView events={data.events} onLoad={handleLoadTimeline} />}
      {view === "investigate" && <InvestigateView busy={false} onInvestigate={handleInvestigate} />}
      {view === "incidents" && <IncidentsView incidents={data.incidents} selected={selectedIncident} onSelect={(incident) => setSelectedIncidentId(incident.id)} onNavigate={() => navigate("investigate")} onFeedback={handleFeedback} />}
      {view === "health" && <HealthView data={data} />}
    </AppShell>
  );
}

function LoadingScreen() {
  return <div className="loading-screen"><div className="brand-mark large" aria-hidden="true"><span /></div><span>Opening the local journal…</span></div>;
}
