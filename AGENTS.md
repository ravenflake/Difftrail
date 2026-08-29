# Difftrail contributor guide

## Purpose

Difftrail is a Windows-first, local-first change journal and incident investigator.
It ranks normalized SQLite evidence deterministically without AI, cloud, or remediation.

Read [README.md](README.md) for behavior, [docs/architecture.md](docs/architecture.md) for
trust boundaries, [SECURITY.md](SECURITY.md) for policy, and [CONTRIBUTING.md](CONTRIBUTING.md).
Validation gaps are in [docs/v0.1.4-field-validation.md](docs/v0.1.4-field-validation.md).

## Repository map

- `difftrail/`: dependency-free Python 3.11+ engine and CLI; the source of truth.
- `difftrail/collectors/`: read-only Windows and PowerShell collection plus normalization.
- `difftrail/db.py`: SQLite schema, migrations, snapshots, retention, and journal queries.
- `difftrail/correlation.py`, `assessment.py`, `investigation.py`: deterministic diagnosis.
- `difftrail/privacy.py`, `public_data.py`, `bundles.py`: safe public/export contracts.
- `difftrail/ui_api.py`: bounded loopback-only HTTP/JSON adapter for the UI.
- `difftrail/automation.py`, `watcher.py`: opt-in Task Scheduler collection and notifications.
- `tests/`: Python `unittest` coverage, including Windows-shaped synthetic fixtures.
- `ui/src/`: React/Vite presentation; it consumes the API and never opens SQLite.
- `ui/src-tauri/`: Rust desktop shell, backend supervision, tray companion, and NSIS config.
- `scripts/`: backend packaging, watcher installation, installer validation, and version tooling.
- `.github/workflows/ci.yml`: authoritative pull-request checks and Windows installer smoke path.

## Non-negotiable invariants

- Keep collection read-only. Difftrail observes and suggests safe diagnostic
  targets; it does not roll back, uninstall, disable, repair, or change Windows.
- Keep data local by default. Never add network upload, accounts, or cloud
  dependencies without an explicitly reviewed architecture/product change.
- Redact profile paths and sensitive text before storage, UI responses, logs,
  notifications, or exports. Never put real host data in tests or fixtures.
- Missing or malformed provider data must remain visible as partial coverage.
  Never interpret a failed/incomplete provider read as an empty clean snapshot.
- The first valid snapshot for a source is a quiet baseline. Preserve stable
  identities and noise filtering so representation churn does not create events.
- Ranking is deterministic and explainable. Scores order candidates; they are
  not probabilities or proof of causality. Preserve stable tie-breaking,
  counter-evidence, conservative confidence, and insufficient-evidence states.
- SQLite is the journal source of truth. Migrations are numbered, transactional,
  and safe to retry; journal writes stay in `Database`.
- The UI receives a reduced public representation only. Do not expose raw Event
  Log messages, absolute paths, process IDs, or provider exception text.
- The API remains loopback-only with Host/Origin validation, bounded query/body
  parsing, JSON content-type checks, and per-launch token authentication in the
  packaged app. Production must not fall back to an unauthenticated fixed port.
- Diagnostic bundles remain one-way, redacted, validated JSON. Do not add bundle
  import/merge or include the SQLite database, raw messages, usernames, or paths.
- Spawn processes with argument arrays or demonstrate safe quoting; use bounded
  timeouts and preserve windowless behavior for background Windows processes.

## Setup and development (PowerShell)

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e .
```

The engine has no third-party runtime dependency. Live collection and watcher require
Windows. Desktop work needs Node.js 20+, Rust stable, and Windows/Tauri build tools:

```powershell
Set-Location .\ui
npm ci
npm run desktop:dev
```

Set `DIFFTRAIL_PYTHON` when Tauri should not use `python`. For browser-only work, start
`python -m difftrail --db "$env:LOCALAPPDATA\Difftrail\difftrail.db" ui --port 45917`
from the root and `npm run dev` from `ui/`; see [README.md](README.md) for token setup.

## Required checks

Run Python commands from the repository root:

```powershell
python -m compileall -q difftrail tests
python scripts/check_release_metadata.py
python -m unittest discover -s tests -v
python -m difftrail validate
python -m difftrail validate-scenarios
```

Run UI/desktop checks from `ui/`:

```powershell
npm ci
npm test
npm run typecheck
npm run build
cargo test --manifest-path src-tauri/Cargo.toml --locked
```

There is no configured Python or JavaScript lint/format command. `compileall`,
TypeScript typechecking, tests, and builds are the current automated checks.

For the full Windows installer build, reproduce CI's backend-tool pin, then build:

```powershell
python -m pip install --disable-pip-version-check "pyinstaller==6.22.0"
Set-Location .\ui
npm ci
npm run desktop:build
```

The installer is written below `ui\src-tauri\target\release\bundle\nsis\`.
Run `scripts\validate-installer.ps1 -InstallerPath <absolute-exe-path>` only on
an isolated Windows user/machine with no existing Difftrail registration; it
silently installs/uninstalls. CI is the authoritative full packaging check.

## Change-specific expectations

- **Collectors/scanners:** keep provider reads independent and read-only; reject
  incomplete PowerShell output; bound parsing/timeouts; normalize stable keys;
  add collector, service, privacy, and scanner-backed fixture regression tests.
- **Storage/migrations:** use parameterized SQL and explicit transactions; test
  fresh and legacy journals, rollback/failure paths, concurrency, quiet rebase,
  redaction, and retention. Never rewrite history into false change events.
- **Correlation:** add explicit ground truth with distractors/counter-evidence;
  run both validation suites and preserve determinism and no-false-High behavior.
- **API/privacy/export:** validate every input at the boundary and return only
  allowlisted public fields. Add `test_ui_api.py`, `test_ui_http.py`, privacy,
  and bundle tests for limits, hostile shapes, redaction, and authentication.
- **UI:** update shared types and API adapters with views; keep preview data
  clearly synthetic and controls unavailable without the real API. Run UI tests,
  typecheck, production build, and relevant Rust shell tests.
- **Automation:** keep collection opt-in and observation-only; validate the exact
  scheduled executable/arguments/interval and preserve retry/idempotency behavior.
- **Packaging/Tauri:** keep the desktop responsible for token generation and
  backend lifetime. The current-user uninstaller removes processes/tasks but
  deliberately preserves the local journal. Test installer changes in isolation.
- **Releases:** keep versions synchronized in Python, npm lock/package metadata,
  Tauri config, and Cargo lock/package metadata; run the metadata checker.
- **Security-sensitive changes:** add regression tests for the crossed boundary,
  minimize exposed data/privilege, document behavior changes, and follow the
  private reporting process in [SECURITY.md](SECURITY.md).

## Windows and contribution notes

- Use PowerShell examples and Windows path semantics; quote paths and use
  `-LiteralPath` in scripts where user-controlled or space-containing paths occur.
- Synthetic validation is not real-host evidence. State clearly when live
  Windows, installer, watcher, overhead, or field validation was not performed.
- Keep changes focused and update authoritative docs when behavior or boundaries
  change. See [ROADMAP.md](ROADMAP.md), [CHANGELOG.md](CHANGELOG.md), and
  [CLA.md](CLA.md) for scope, release history, and contribution licensing.
- Do not use `codex/` or `agent/` branch-name prefixes; use conventional branch names.
