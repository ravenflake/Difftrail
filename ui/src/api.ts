import type {
  Bootstrap,
  Incident,
  InvestigationResponse,
  TimelineFilters,
  EventRecord,
  ScanSummary,
} from "./types";

const API_BASE = (import.meta.env.VITE_DIFFTRAIL_API_URL || "http://127.0.0.1:45917/api").replace(/\/$/, "");

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`, {
    ...init,
    headers: {
      Accept: "application/json",
      ...(init?.body ? { "Content-Type": "application/json" } : {}),
      ...init?.headers,
    },
  });
  const payload = (await response.json()) as T & { error?: string };
  if (!response.ok) {
    throw new Error(payload.error || `Difftrail API returned ${response.status}`);
  }
  return payload;
}

export function loadBootstrap(days = 7): Promise<Bootstrap> {
  return request<Bootstrap>(`/bootstrap?days=${days}`);
}

export function loadTimeline(filters: TimelineFilters, limit = 240): Promise<EventRecord[]> {
  const params = new URLSearchParams({
    kind: filters.kind,
    subsystem: filters.subsystem,
    search: filters.search,
    limit: String(limit),
  });
  return request<EventRecord[]>(`/timeline?${params.toString()}`);
}

export function runScan(): Promise<{ scan: ScanSummary }> {
  return request<{ scan: ScanSummary }>("/scan", { method: "POST", body: "{}" });
}

export function createInvestigation(input: {
  description: string;
  subsystem?: string;
  onset?: string;
  lookback_days: number;
}): Promise<InvestigationResponse> {
  return request<InvestigationResponse>("/investigations", {
    method: "POST",
    body: JSON.stringify(input),
  });
}

export function recordFeedback(
  incidentId: string,
  outcome: "correct" | "incorrect" | "unknown",
  eventId?: string,
): Promise<{ incident: Incident }> {
  return request<{ incident: Incident }>(`/incidents/${encodeURIComponent(incidentId)}/feedback`, {
    method: "POST",
    body: JSON.stringify({ outcome, event_id: eventId }),
  });
}

export { API_BASE };
