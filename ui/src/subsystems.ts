export const subsystemOptions = [
  "general",
  "graphics",
  "audio",
  "network",
  "bluetooth",
  "driver",
  "startup",
  "windows-update",
  "application",
  "device",
] as const;

export const timelineSubsystemOptions = [
  "all",
  ...subsystemOptions.filter((subsystem) => subsystem !== "general"),
] as const;

const SUBSYSTEM_LABELS: Record<string, string> = {
  graphics: "Graphics",
  audio: "Audio",
  network: "Network",
  bluetooth: "Bluetooth",
  driver: "Drivers",
  startup: "Startup",
  "windows-update": "Windows update",
  application: "Applications",
  device: "Devices",
  general: "General",
};

export function subsystemLabel(subsystem: string): string {
  return SUBSYSTEM_LABELS[subsystem] || subsystem.replace(/[-_]/g, " ");
}
