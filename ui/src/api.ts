import type {
  Bootstrap,
  Incident,
  InvestigationResponse,
  TimelineFilters,
  EventRecord,
  ScanSummary,
} from "./types";

const API_BASE = (import.meta.env.VITE_DIFFTRAIL_API_URL || "http://127.0.0.1:45917/api").replace(/\/$/, "");
const REQUEST_TIMEOUT_MS = 10_000;

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const controller = new AbortController();
  const timeout = window.setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
  try {
    const response = await fetch(`${API_BASE}${path}`, {
      ...init,
      signal: controller.signal,
      headers: {
        Accept: "application/json",
        ...(init?.body ? { "Content-Type": "application/json" } : {}),
        ...init?.headers,
      },
    });

    let payload: (T & { error?: string }) | undefined;
    let parsedJson = false;
    try {
      payload = (await response.json()) as T & { error?: string };
      parsedJson = true;
    } catch {
      // The status is more useful than a JSON parser error for proxy/server failures.
    }
    if (!response.ok) {
      const status = `${response.status}${response.statusText ? ` ${response.statusText}` : ""}`;
      throw new Error(payload?.error || `Difftrail API returned ${status}`);
    }
    if (!parsedJson) {
      const status = `${response.status}${response.statusText ? ` ${response.statusText}` : ""}`;
      throw new Error(`Difftrail API returned a non-JSON response (${status})`);
    }
    return payload as T;
  } catch (reason) {
    if (reason instanceof DOMException && reason.name === "AbortError") {
      throw new Error(`Difftrail API request timed out after ${REQUEST_TIMEOUT_MS / 1000} seconds`);
    }
    throw reason;
  } finally {
    window.clearTimeout(timeout);
  }
}

export async function waitForApi(): Promise<void> {
  await request<{ status: unknown }>("/health");
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
