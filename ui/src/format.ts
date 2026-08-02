export { subsystemLabel } from "./subsystems";

const SOURCE_LABELS: Record<string, string> = {
  updates: "Windows update",
  "event-log": "Windows signal",
  "fixture:eventlog": "Windows signal",
  "windows-reliability": "Windows signal",
  apps: "Application",
  drivers: "Driver",
  services: "Service",
  tasks: "Scheduled task",
  startup: "Startup",
  devices: "Device",
};

export function sourceLabel(source: string): string {
  return SOURCE_LABELS[source] || source.replace(/[-_]/g, " ");
}

export function kindLabel(kind: string): string {
  return kind === "symptom" ? "Symptom" : "Change";
}

export function formatDateTime(value: string | null | undefined): string {
  if (!value) return "Not recorded";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return new Intl.DateTimeFormat(undefined, {
    month: "short",
    day: "numeric",
    year: "numeric",
    hour: "numeric",
    minute: "2-digit",
  }).format(date);
}

export function formatDate(value: string): string {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return new Intl.DateTimeFormat(undefined, { weekday: "short", month: "long", day: "numeric" }).format(date);
}

export function relativeTime(value: string | null | undefined): string {
  if (!value) return "Not yet";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "Unknown time";
  const delta = Date.now() - date.getTime();
  const minutes = Math.round(delta / 60_000);
  if (Math.abs(minutes) < 2) return "just now";
  if (Math.abs(minutes) < 60) return `${Math.abs(minutes)}m ${minutes >= 0 ? "ago" : "from now"}`;
  const hours = Math.round(minutes / 60);
  if (Math.abs(hours) < 48) return `${Math.abs(hours)}h ${hours >= 0 ? "ago" : "from now"}`;
  const days = Math.round(hours / 24);
  return `${Math.abs(days)}d ${days >= 0 ? "ago" : "from now"}`;
}

export function capitalize(value: string): string {
  return value ? value.charAt(0).toUpperCase() + value.slice(1) : value;
}

export function number(value: number | null | undefined, fractionDigits = 0): string {
  if (value === null || value === undefined || Number.isNaN(value)) return "—";
  return new Intl.NumberFormat(undefined, { maximumFractionDigits: fractionDigits }).format(value);
}

export function initials(value: string): string {
  const words = value.trim().split(/\s+/).filter(Boolean);
  return words.slice(0, 2).map((word) => word[0]).join("").toUpperCase() || "D";
}
