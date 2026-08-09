import { invoke } from "@tauri-apps/api/core";
import type {
  Bootstrap,
  BundleResponse,
  AutomationConfig,
  AutomationSummary,
  Incident,
  InvestigationResponse,
  TimelineFilters,
  EventRecord,
  OverheadResponse,
  ScanSummary,
} from "./types";

const DEFAULT_API_BASE = "http://127.0.0.1:45917/api";
const CONFIGURED_API_BASE = (import.meta.env.VITE_DIFFTRAIL_API_URL || "").replace(/\/$/, "");
const CONFIGURED_API_TOKEN = import.meta.env.VITE_DIFFTRAIL_API_TOKEN || "";
const REQUEST_TIMEOUT_MS = 10_000;

type ApiEndpoint = {
  base: string;
  port?: number;
  token?: string;
};

let apiEndpointPromise: Promise<ApiEndpoint> | undefined;

async function resolveApiEndpoint(): Promise<ApiEndpoint> {
  if (CONFIGURED_API_BASE) {
    return { base: CONFIGURED_API_BASE, token: CONFIGURED_API_TOKEN || undefined };
  }

  try {
    const [port, token] = await Promise.all([
      invoke<number>("api_port"),
      invoke<string>("api_token"),
    ]);
    if (!Number.isInteger(port) || port < 1 || port > 65_535) {
      throw new Error("Difftrail returned an invalid local API port");
    }
    if (token.length < 32) {
      throw new Error("Difftrail returned an invalid local API token");
    }
    return { base: `http://127.0.0.1:${port}/api`, port, token };
  } catch {
    return { base: DEFAULT_API_BASE, token: CONFIGURED_API_TOKEN || undefined };
  }
}

function getApiEndpoint(): Promise<ApiEndpoint> {
  apiEndpointPromise ??= resolveApiEndpoint();
  return apiEndpointPromise;
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const controller = new AbortController();
  const timeout = window.setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
  try {
    const endpoint = await getApiEndpoint();
    const response = await fetch(`${endpoint.base}${path}`, {
      ...init,
      signal: controller.signal,
      headers: {
        Accept: "application/json",
        ...(init?.body ? { "Content-Type": "application/json" } : {}),
        ...(endpoint.token ? { "X-Difftrail-Token": endpoint.token } : {}),
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
  const payload = await request<{ status: unknown; api_port?: number }>("/health");
  const endpoint = await getApiEndpoint();
  if (endpoint.port !== undefined && payload.api_port !== endpoint.port) {
    throw new Error("Difftrail API health response belongs to a different launch");
  }
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

export function updateAutomationConfig(input: AutomationConfig): Promise<{ automation: AutomationSummary }> {
  return request<{ automation: AutomationSummary }>("/automation/config", {
    method: "POST",
    body: JSON.stringify(input),
  });
}

export function updateAutomationWatcher(
  action: "enable" | "disable" | "run",
  intervalSeconds?: number,
): Promise<{ automation: AutomationSummary; scan?: ScanSummary }> {
  return request<{ automation: AutomationSummary; scan?: ScanSummary }>("/automation/watcher", {
    method: "POST",
    body: JSON.stringify({ action, interval_seconds: intervalSeconds }),
  });
}

export function markAutomationNotificationsRead(ids?: string[]): Promise<{ automation: AutomationSummary }> {
  return request<{ automation: AutomationSummary }>("/automation/notifications/read", {
    method: "POST",
    body: JSON.stringify(ids ? { ids } : {}),
  });
}

export function recordOverhead(): Promise<OverheadResponse> {
  return request<OverheadResponse>("/overhead", { method: "POST", body: "{}" });
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

export function exportBundle(options: { days?: number; incident_id?: string }): Promise<BundleResponse> {
  return request<BundleResponse>("/export-bundle", {
    method: "POST",
    body: JSON.stringify(options),
  });
}

export const API_BASE = CONFIGURED_API_BASE || DEFAULT_API_BASE;
