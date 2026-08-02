import type { ReactNode, SVGProps } from "react";

export type IconName =
  | "home"
  | "timeline"
  | "investigate"
  | "incidents"
  | "health"
  | "refresh"
  | "arrow"
  | "chevron"
  | "search"
  | "filter"
  | "plus"
  | "clock"
  | "shield"
  | "check"
  | "alert"
  | "change"
  | "symptom"
  | "driver"
  | "application"
  | "device"
  | "service"
  | "startup"
  | "update"
  | "external"
  | "copy"
  | "close"
  | "spark"
  | "sun"
  | "moon";

type Props = SVGProps<SVGSVGElement> & { name: IconName; size?: number };

const paths: Record<IconName, ReactNode> = {
  home: <><path d="m3 10 9-7 9 7" /><path d="M5 9.5V21h14V9.5" /><path d="M9 21v-6h6v6" /></>,
  timeline: <><path d="M4 5h16" /><path d="M4 12h10" /><path d="M4 19h16" /><circle cx="18" cy="12" r="2" /></>,
  investigate: <><circle cx="10.8" cy="10.8" r="6.8" /><path d="m16 16 5 5" /><path d="M10.8 7.5v6.6M7.5 10.8h6.6" /></>,
  incidents: <><path d="M12 3 2.8 19a1.5 1.5 0 0 0 1.3 2.2h15.8a1.5 1.5 0 0 0 1.3-2.2L12 3Z" /><path d="M12 9v4" /><path d="M12 17h.01" /></>,
  health: <><path d="M3 12h4l2-5 4 10 2-5h6" /></>,
  refresh: <><path d="M20 11a8 8 0 0 0-14-4L4 9" /><path d="M4 4v5h5" /><path d="M4 13a8 8 0 0 0 14 4l2-2" /><path d="M20 20v-5h-5" /></>,
  arrow: <><path d="M5 12h14" /><path d="m13 6 6 6-6 6" /></>,
  chevron: <path d="m9 18 6-6-6-6" />,
  search: <><circle cx="10.8" cy="10.8" r="6.8" /><path d="m16 16 5 5" /></>,
  filter: <><path d="M4 6h16" /><path d="M7 12h10" /><path d="M10 18h4" /></>,
  plus: <><path d="M12 5v14M5 12h14" /></>,
  clock: <><circle cx="12" cy="12" r="9" /><path d="M12 7v5l3 2" /></>,
  shield: <><path d="M12 3 19 6v5c0 4.5-2.8 8.1-7 10-4.2-1.9-7-5.5-7-10V6l7-3Z" /><path d="m9 12 2 2 4-4" /></>,
  check: <path d="m5 12 4 4L19 6" />,
  alert: <><path d="M12 3 2.8 19a1.5 1.5 0 0 0 1.3 2.2h15.8a1.5 1.5 0 0 0 1.3-2.2L12 3Z" /><path d="M12 9v4" /><path d="M12 17h.01" /></>,
  change: <><path d="M4 7h12" /><path d="m13 4 3 3-3 3" /><path d="M20 17H8" /><path d="m11 14-3 3 3 3" /></>,
  symptom: <><path d="M3 12h4l2-5 4 10 2-5h6" /></>,
  driver: <><rect x="4" y="4" width="16" height="16" rx="2" /><path d="M8 8h8v8H8z" /><path d="M12 4v4M12 16v4M4 12h4M16 12h4" /></>,
  application: <><rect x="4" y="4" width="16" height="16" rx="2" /><path d="M8 8h.01M12 8h.01M16 8h.01M8 12h.01M12 12h.01M16 12h.01M8 16h.01M12 16h.01M16 16h.01" /></>,
  device: <><rect x="6" y="3" width="12" height="18" rx="2" /><path d="M9 6h6M10 18h4" /></>,
  service: <><path d="M12 3v3M12 18v3M3 12h3M18 12h3M5.6 5.6l2.1 2.1M16.3 16.3l2.1 2.1M18.4 5.6l-2.1 2.1M7.7 16.3l-2.1 2.1" /><circle cx="12" cy="12" r="4" /></>,
  startup: <><path d="M12 3v11" /><path d="m7 9 5 5 5-5" /><path d="M5 19h14" /></>,
  update: <><path d="M4 7h12" /><path d="m13 4 3 3-3 3" /><path d="M20 17H8" /><path d="m11 14-3 3 3 3" /></>,
  external: <><path d="M14 4h6v6" /><path d="m20 4-9 9" /><path d="M18 13v5a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h5" /></>,
  copy: <><rect x="8" y="8" width="11" height="11" rx="2" /><path d="M16 8V6a2 2 0 0 0-2-2H6a2 2 0 0 0-2 2v8a2 2 0 0 0 2 2h2" /></>,
  close: <><path d="m6 6 12 12M18 6 6 18" /></>,
  spark: <><path d="m12 3 1.5 5.5L19 10l-5.5 1.5L12 17l-1.5-5.5L5 10l5.5-1.5L12 3Z" /><path d="m19 16 .5 2 2 .5-2 .5-.5 2-.5-2-2-.5 2-.5.5-2Z" /></>,
  sun: <><circle cx="12" cy="12" r="4" /><path d="M12 2v2M12 20v2M4.93 4.93l1.42 1.42M17.65 17.65l1.42 1.42M2 12h2M20 12h2M4.93 19.07l1.42-1.42M17.65 6.35l1.42-1.42" /></>,
  moon: <path d="M20.4 15.2A8.4 8.4 0 0 1 8.8 3.6 8.8 8.8 0 1 0 20.4 15.2Z" />,
};

export function Icon({ name, size = 18, strokeWidth = 1.7, ...props }: Props) {
  return (
    <svg
      aria-hidden="true"
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={strokeWidth}
      strokeLinecap="round"
      strokeLinejoin="round"
      focusable="false"
      {...props}
    >
      {paths[name]}
    </svg>
  );
}
