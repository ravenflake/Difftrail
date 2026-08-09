# Changelog

## Unreleased

- Added per-launch authentication for the installed desktop's loopback API.
- Remove the opt-in watcher task when the desktop application is uninstalled,
  while preserving the local journal.
- Added a security policy, architecture and roadmap documentation, structured
  issue templates, dependency review, CodeQL, and Dependabot configuration.
- Pinned build and workflow tooling, fixed the locked UI dependency advisory,
  and added SHA-256 checksum generation for tagged release installers.
- Added a fifth scanner-backed fixture for Windows Update transitions followed
  by an unexpected restart.
- Added offline unit coverage for Event Log reset, restart, shutdown, hang,
  and crash normalization.
- Added the v0.1.4 field-validation checklist for real Windows install,
  watcher, incident, privacy, and release-readiness checks.

## 0.1.3 — Trust and Portability

- Added transactional, numbered SQLite migrations with legacy-journal upgrade support.
- Added stale-scan recovery and `doctor --json` journal diagnostics.
- Added portable redacted diagnostic bundle export and validation.
- Added honest investigation assessment states for weak evidence, missing changes, and limited coverage.
- Added loopback API request guards, response hardening, bundle routes, and UI export actions.
- Expanded deterministic and scanner-backed validation scenarios, release metadata checks, and Windows installer smoke validation.

## 0.1.2

See the repository history for the MVP hardening release.
