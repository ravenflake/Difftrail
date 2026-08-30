# Changelog

## Unreleased

- Reframed problem review around ranked evidence leads instead of root-cause
  claims: support labels now describe the recorded signals, ambiguity and
  counter-evidence reduce support, and next steps stay read-only.
- Expanded the reduced public event context, per-source collection recency, and
  scan coverage reporting while preserving redaction and local-only boundaries.
- Made scan-detection time versus Windows source time explicit and retained
  source-specific failure metadata without exposing provider exception text.
- Replaced public ranking scores and confidence fields with Strong, Moderate,
  or Weak evidence-support levels in the UI, CLI JSON, API, and report bundles.
- Reworked the desktop information architecture, problem-review explanations,
  feedback vocabulary, limited-data states, scan feedback, and production
  backend failure state so every screen distinguishes facts, leads, limits, and
  next actions.
- Made disposable Windows build versions monotonic across main and pull-request
  artifacts, and hardened in-place setup so running Difftrail processes cannot
  block the previous uninstaller.
- Added per-launch authentication for the installed desktop's loopback API.
- Remove the opt-in watcher task when the desktop application is uninstalled,
  while preserving the local journal.
- Added a security policy, architecture and roadmap documentation, structured
  issue templates, dependency auditing, CodeQL, and Dependabot configuration.
- Pinned build and workflow tooling, fixed the locked UI dependency advisory,
  and added SHA-256 checksum generation for tagged release installers.
- Added a fifth scanner-backed fixture for Windows Update transitions followed
  by an unexpected restart.
- Added offline unit coverage for Event Log reset, restart, shutdown, hang,
  and crash normalization.
- Added the v0.1.4 field-validation checklist for real Windows install,
  watcher, incident, privacy, and release-readiness checks.
- Improved investigation context, entity-aware ranking, and automatic draft
  titles while rejecting unrelated service evidence.
- Added an explicit collector JSON nesting limit and Python 3.14 CI coverage.
- Canonicalized allow-listed loopback origins before writing CORS response
  headers.
- Separated installed driver inventory from live device presence so temporary
  device transitions are not duplicated as driver uninstall/reinstall events;
  existing journals take a quiet one-time driver baseline after upgrading.
- Added a lightweight Windows notification-area companion that shows whether
  scheduled collection is enabled, actively scanning, or off; it opens the
  desktop UI on demand without keeping the WebView and local API resident.
- Made the notification-area collection status actionable: clicking it toggles
  the scheduled watcher, while the full Automation screen retains interval and
  rule controls.
- Hardened notification-area startup with a shell-ready fallback, startup
  retries, failure logging, and desktop self-healing.
- Made the background interval explicit and persistent, clarified watcher
  enable/disable results, and constrained the Automation inbox to its own
  scrollable panel.
- Reworked System health around live uptime, memory, system-drive space,
  collection health, source coverage, and an explained one-scan footprint
  measurement; fixed footprint sampling in the installed executable.

## 0.1.3 — Trust and Portability

- Added transactional, numbered SQLite migrations with legacy-journal upgrade support.
- Added stale-scan recovery and `doctor --json` journal diagnostics.
- Added portable redacted diagnostic bundle export and validation.
- Added honest investigation assessment states for weak evidence, missing changes, and limited coverage.
- Added loopback API request guards, response hardening, bundle routes, and UI export actions.
- Expanded deterministic and scanner-backed validation scenarios, release metadata checks, and Windows installer smoke validation.

## 0.1.2

See the repository history for the MVP hardening release.
