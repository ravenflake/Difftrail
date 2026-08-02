import { useEffect, useRef, useState, type ReactNode } from "react";
import type { Status, View } from "../types";
import { Icon, type IconName } from "./Icon";
import { BrandMark } from "./BrandMark";
import { relativeTime } from "../format";
import { applyTheme, getStoredThemeMode, getSystemTheme, persistThemeMode, type Theme, type ThemeMode } from "../theme";

interface AppShellProps {
  view: View;
  status: Status;
  version: string;
  connection: "local" | "preview";
  scanning: boolean;
  onNavigate: (view: View) => void;
  onScan: () => void;
  children: ReactNode;
}

const navItems: Array<{ id: View; label: string; icon: IconName; description: string }> = [
  { id: "home", label: "Overview", icon: "home", description: "What deserves attention" },
  { id: "timeline", label: "Timeline", icon: "timeline", description: "Meaningful system history" },
  { id: "investigate", label: "Investigate", icon: "investigate", description: "Connect a problem to a change" },
  { id: "incidents", label: "Incidents", icon: "incidents", description: "Your investigations" },
  { id: "health", label: "System health", icon: "health", description: "Coverage and overhead" },
];

const titles: Record<View, string> = {
  home: "Overview",
  timeline: "Timeline",
  investigate: "Investigate a problem",
  incidents: "Incidents",
  health: "System health",
};

export function AppShell({ view, status, version, connection, scanning, onNavigate, onScan, children }: AppShellProps) {
  const partial = status.last_scan?.status === "partial";
  const [themeMode, setThemeMode] = useState<ThemeMode>(() => getStoredThemeMode());
  const [systemTheme, setSystemTheme] = useState<Theme>(() => getSystemTheme());
  const [mobileNavOpen, setMobileNavOpen] = useState(false);
  const mobileMenuButtonRef = useRef<HTMLButtonElement>(null);
  const mobileCloseButtonRef = useRef<HTMLButtonElement>(null);
  const mobileNavWasOpen = useRef(false);
  const theme = themeMode === "system" ? systemTheme : themeMode;

  useEffect(() => {
    applyTheme(theme);
  }, [theme]);

  useEffect(() => {
    persistThemeMode(themeMode);
  }, [themeMode]);

  useEffect(() => {
    const media = window.matchMedia("(prefers-color-scheme: dark)");
    const handleChange = (event: MediaQueryListEvent) => setSystemTheme(event.matches ? "dark" : "light");
    media.addEventListener("change", handleChange);
    return () => media.removeEventListener("change", handleChange);
  }, []);

  useEffect(() => {
    if (!mobileNavOpen) {
      if (mobileNavWasOpen.current) mobileMenuButtonRef.current?.focus();
      mobileNavWasOpen.current = false;
      return;
    }

    mobileNavWasOpen.current = true;
    mobileCloseButtonRef.current?.focus();
    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        event.preventDefault();
        setMobileNavOpen(false);
        return;
      }
      if (event.key === "Tab") {
        const drawer = document.getElementById("mobile-navigation");
        const focusable = drawer?.querySelectorAll<HTMLElement>("button:not([disabled]), [href], input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex='-1'])");
        if (!focusable?.length) return;
        const first = focusable[0];
        const last = focusable[focusable.length - 1];
        if (event.shiftKey && document.activeElement === first) {
          event.preventDefault();
          last.focus();
        } else if (!event.shiftKey && document.activeElement === last) {
          event.preventDefault();
          first.focus();
        }
      }
    };
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [mobileNavOpen]);

  const toggleTheme = () => setThemeMode(theme === "dark" ? "light" : "dark");
  const useSystemTheme = () => setThemeMode("system");
  const closeMobileNav = () => setMobileNavOpen(false);
  const navigateFromMobileNav = (next: View) => {
    onNavigate(next);
    closeMobileNav();
  };

  return (
    <div className="app-frame">
      <aside className="sidebar" aria-label="Main navigation">
        <div className="brand-lockup">
          <BrandMark size={31} className="sidebar-brand-mark" />
          <div>
            <div className="brand-name">Difftrail</div>
            <div className="brand-tagline">Know what changed.</div>
          </div>
        </div>

        <NavigationList view={view} onNavigate={onNavigate} />

        <div className="sidebar-bottom">
          <ThemeControl theme={theme} mode={themeMode} onToggle={toggleTheme} onUseSystem={useSystemTheme} />
          <div className="version-line">Difftrail {version === "preview" ? "preview" : `v${version}`}</div>
        </div>
      </aside>

      {mobileNavOpen && <button type="button" className="mobile-nav-scrim" aria-label="Close navigation menu" onClick={closeMobileNav} />}
      <div
        id="mobile-navigation"
        className="mobile-nav-drawer"
        role="dialog"
        aria-modal="true"
        aria-labelledby="mobile-navigation-title"
        hidden={!mobileNavOpen}
      >
        <div className="mobile-nav-header">
          <span id="mobile-navigation-title">Workspace navigation</span>
          <button ref={mobileCloseButtonRef} type="button" className="mobile-nav-close" aria-label="Close navigation menu" onClick={closeMobileNav}>
            <Icon name="close" size={19} />
          </button>
        </div>
        <NavigationList view={view} onNavigate={navigateFromMobileNav} />
      </div>

      <div className="main-column" aria-hidden={mobileNavOpen ? "true" : undefined}>
        <header className="topbar">
          <button
            ref={mobileMenuButtonRef}
            type="button"
            className="mobile-menu-button"
            aria-label={mobileNavOpen ? "Close navigation menu" : "Open navigation menu"}
            aria-expanded={mobileNavOpen}
            aria-controls="mobile-navigation"
            aria-haspopup="dialog"
            onClick={() => setMobileNavOpen((open) => !open)}
          >
            <Icon name={mobileNavOpen ? "close" : "menu"} size={19} />
          </button>
          <div className="mobile-brand"><BrandMark size={24} className="mobile-brand-mark" />Difftrail</div>
          <div className="topbar-title">
            <span className="eyebrow">Workspace</span>
            <h1>{titles[view]}</h1>
          </div>
          <div className="topbar-actions">
            <ThemeControl compact theme={theme} mode={themeMode} onToggle={toggleTheme} onUseSystem={useSystemTheme} />
            <div
              className={`connection-pill ${connection === "preview" ? "is-preview" : ""}`}
              role="status"
              aria-live="polite"
              title={connection === "local" ? "Connected to the local journal" : "Showing preview data"}
            >
              <span className="status-dot" aria-hidden="true" />
              <span className="connection-label-full">{connection === "local" ? "Local journal" : "Preview data"}</span>
              <span className="connection-label-compact">{connection === "local" ? "Local" : "Preview"}</span>
            </div>
            <button type="button" className="button button-secondary scan-button" aria-label={scanning ? "Scanning" : "Scan now"} onClick={onScan} disabled={scanning}>
              <Icon name="refresh" size={15} className={scanning ? "spin" : ""} />
              {scanning ? "Scanning" : "Scan now"}
            </button>
          </div>
        </header>

        {partial && (
          <div className="notice-bar notice-warning" role="status">
            <Icon name="alert" size={16} />
            <span>The latest scan completed with provider warnings. Review System health for coverage details.</span>
            <button type="button" className="text-button" onClick={() => onNavigate("health")}>Review health <Icon name="arrow" size={14} /></button>
          </div>
        )}

        <main className="content"><div className="content-inner">{children}</div></main>
        <footer className="app-footer">
          <span>Last scan {relativeTime(status.last_scan?.finished_at)}</span>
          <span className="footer-separator" aria-hidden="true" />
          <span>{status.sources.filter((source) => source.initialized).length} of {status.sources.length} sources capturing</span>
        </footer>
      </div>
    </div>
  );
}

interface NavigationListProps {
  view: View;
  onNavigate: (view: View) => void;
}

function NavigationList({ view, onNavigate }: NavigationListProps) {
  return (
    <nav className="nav-list" aria-label="Workspace navigation">
      <div className="nav-label">Workspace</div>
      {navItems.map((item) => (
        <button
          type="button"
          key={item.id}
          className={`nav-item ${view === item.id ? "is-active" : ""}`}
          onClick={() => onNavigate(item.id)}
          aria-current={view === item.id ? "page" : undefined}
          title={item.description}
        >
          <span className="nav-icon"><Icon name={item.icon} size={17} /></span>
          <span className="nav-copy">
            <span>{item.label}</span>
            <small>{item.description}</small>
          </span>
        </button>
      ))}
    </nav>
  );
}

interface ThemeControlProps {
  theme: Theme;
  mode: ThemeMode;
  compact?: boolean;
  onToggle: () => void;
  onUseSystem: () => void;
}

function ThemeControl({ theme, mode, compact = false, onToggle, onUseSystem }: ThemeControlProps) {
  const nextTheme = theme === "dark" ? "light" : "dark";
  return (
    <div className={`theme-control ${compact ? "theme-control-compact" : ""}`}>
      {!compact && (
        <div className="theme-control-heading">
          <span>Appearance</span>
          <span className="theme-control-mode">{mode === "system" ? "System" : "Manual"}</span>
        </div>
      )}
      <button
        type="button"
        className={`theme-toggle ${theme === "dark" ? "is-dark" : ""}`}
        role="switch"
        aria-checked={theme === "dark"}
        aria-label={`Switch to ${nextTheme} mode`}
        title={`Switch to ${nextTheme} mode`}
        onClick={onToggle}
      >
        <span className="theme-toggle-icon" aria-hidden="true">
          <span className="theme-icon theme-icon-moon"><Icon name="moon" size={14} /></span>
          <span className="theme-icon theme-icon-sun"><Icon name="sun" size={15} /></span>
        </span>
        <span className="theme-toggle-label">{theme === "dark" ? "Dark mode" : "Light mode"}</span>
        <span className="theme-toggle-track" aria-hidden="true"><span className="theme-toggle-thumb" /></span>
      </button>
      {!compact && mode !== "system" && (
        <button type="button" className="theme-system-link" onClick={onUseSystem}>Use system theme</button>
      )}
    </div>
  );
}
