# Difftrail

Difftrail is a Windows-first, local-first change journal and incident investigator. It answers:

> My PC was fine yesterday. What changed?

The MVP focuses on one useful loop:

1. Build a quiet baseline from read-only Windows snapshots.
2. Record meaningful changes instead of raw telemetry.
3. Ingest crash, hang, reset, restart, and shutdown symptoms.
4. Let a user describe a problem and choose its onset.
5. Rank candidate changes with reproducible evidence signals.
6. Show supporting evidence, counter-evidence, a conservative next step, and a read-only Windows diagnostic target.

The core works without AI or cloud access. The local SQLite database is the app's source of truth. No screenshots, document contents, or network uploads are collected.

Normalized change history is kept locally for diagnosis. Raw Event Log message text is retained for the configured retention period (30 days by default) and then removed while the compact symptom event remains.

## Run it from a checkout

Python 3.11+ is enough for the application; there are no runtime dependencies.

For an isolated checkout environment:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e .
```

The commands below can then use either `python` from an activated environment or `.\.venv\Scripts\python.exe` explicitly.

```powershell
python -m difftrail --db .\difftrail.db seed-demo
python -m difftrail --db .\difftrail.db timeline
python -m difftrail --db .\difftrail.db investigate "My graphics started crashing after an update" --subsystem graphics
```

When `--onset` is omitted, an investigation treats the problem as happening now and includes changes from the preceding lookback window. Supply an ISO timestamp when investigating a historical incident.

The first Tkinter desktop interface has been removed for now. The local engine remains usable through the CLI while a replacement interface is designed. A partial scan prints provider warnings instead of treating missing coverage as a clean result.

For a realistic, safe driver-change test, use a new disposable database. The fixture runs the actual scanner and snapshot diff path with Windows-shaped NVIDIA records, then adds a simulated display-reset symptom; it does not call PowerShell or modify drivers:

```powershell
$simulationDb = Join-Path $env:LOCALAPPDATA "Difftrail\nvidia-switch-simulation.db"
python -m difftrail --db $simulationDb simulate nvidia-driver-switch
python -m difftrail --db $simulationDb investigate "graphics started failing" --subsystem graphics --json
```

The simulation requires an empty database so fixture evidence cannot be mixed with real host history. `seed-demo` remains useful for a quick event-only tour; this fixture is the stronger end-to-end test.

For a real Windows journal, run an initial read-only scan and then keep the watcher running:

```powershell
python -m difftrail --db "$env:LOCALAPPDATA\Difftrail\difftrail.db" scan
python -m difftrail --db "$env:LOCALAPPDATA\Difftrail\difftrail.db" watch --interval 300
```

The watcher snapshots applications, Windows updates, drivers, services, scheduled tasks, startup entries, and present devices. The first successful snapshot of each source is a quiet baseline; later durable state transitions become journal events. Normal service/task runtime state, healthy device status, and localized app/driver display text are retained as context but do not create changes by themselves. NVIDIA/AMD display-container service package-path changes are classified as graphics evidence, while the Studio/Game Ready branch is not inferred unless Windows exposes explicit branch metadata. Event Log collection covers common application crashes/hangs, display-driver resets, unexpected restarts, and unexpected shutdowns.

To start it at logon, review the script and run PowerShell as the user who should own the task:

```powershell
.\scripts\install-watcher.ps1 -PythonPath .\.venv\Scripts\python.exe -IntervalSeconds 300
```

If the package is installed into the active system Python, `-PythonPath` can be omitted. The script validates the selected interpreter before creating the scheduled task.

Remove it with .\scripts\uninstall-watcher.ps1.

## Validation

The deterministic ground-truth harness creates known-cause scenarios with nearby distractors, missing evidence, counter-evidence, no-cause cases, and post-onset changes:

```powershell
python -m difftrail validate
python -m difftrail validate --json
```

The scanner-backed fixture harness replays four safe Windows-shaped scenarios through the production collector normalizers, quiet baseline, SQLite diff, symptom ingestion, and investigation ranking. It uses disposable in-memory databases, so it cannot modify or contaminate a real journal:

```powershell
python -m difftrail validate-scenarios
python -m difftrail validate-scenarios --json
```

The scenarios cover an audio endpoint replacement, service/task/startup additions, an application update, and a graphics driver change mixed with unrelated application and persistence changes. Each run checks that the baseline is quiet, the expected transitions are captured, the expected evidence appears in the top three, no unrelated change receives High confidence, and the evidence includes a safe diagnostic target. The audio scenario validates endpoint presence changes; the current Windows collector does not claim to observe the user's default-output setting itself.

The resource validator measures the real watcher process and collector children during startup and steady state. It requires the optional psutil package only for this validation command; the application itself still has no third-party runtime dependency.

```powershell
python -m pip install psutil
python -m difftrail overhead --interval 15 --warmup 8 --duration 10 --json
```

The report separates startup CPU/disk activity from steady-state CPU/RSS/disk activity. It measures the watcher process tree, not system-wide load.

Latest local validation: 8 explicit ground-truth scenarios and 100 deterministic perturbations both reached 100% top-1 accuracy, 100% top-3 accuracy, and 100% no-false-High on the synthetic suite. A real Windows test database completed repeat scans across 7 sources with no provider errors; the follow-up fixed locale/encoding churn, runtime-state churn, stable app identity, and an NVIDIA-audio subsystem classification error. The latest 10-second steady-state watcher sample used 30.37 MB RSS, 0.000% process-tree CPU, and 0 MB disk I/O; startup peaked at 148.11 MB RSS with 1.736% CPU and 2.220 MB reads. These are host-specific measurements, not a cross-machine guarantee.

## Architecture

```
PowerShell read-only providers
        |
normalized SnapshotItem / Event models
        |
SQLite state + semantic journal
        |
deterministic correlation engine
        |
CLI / JSON
```

Important boundaries:

- difftrail/collectors/windows.py contains Windows-specific reads only.
- difftrail/db.py stores normalized state and redacted evidence locally.
- difftrail/correlation.py is deterministic and explainable. Its score orders results internally; users see High/Medium/Low plus evidence, not fake probability.
- difftrail/validation.py measures diagnosis behavior against explicit ground truth.
- difftrail/simulation.py contains safe Windows-shaped fixture replays for end-to-end validation; it does not invoke PowerShell.
- difftrail/overhead.py measures watcher resource use without changing system state.

## Test

```powershell
python -m unittest discover -s tests -v
```

Tests cover deterministic ranking, distractors, counter-evidence, missing evidence, false positives, scanner-backed fixture replays, snapshot baselines, retention, redaction, search, source status, and collector failure handling.

## Current limits and next validation

App lifecycle history is inferred from current inventory snapshots, so events that happen entirely between scans cannot be recovered yet. Windows Update and driver history currently come from state snapshots rather than a complete historical provider. The validation suite is synthetic and proves ranking behavior under known inputs; it does not yet prove real-world causal accuracy.

The safe scanner-backed scenarios now cover the first controlled MVP cases without changing Windows state. They validate capture and ranking mechanics, but remain synthetic evidence; real-world causal accuracy, longer/cross-machine overhead, install/uninstall noise, and replacement-interface usability still require validation.

## Release status

This is an early, CLI-first MVP foundation. The deterministic tests and synthetic validation suite are passing, but real-world causal accuracy, longer and cross-machine overhead, and replacement-interface usability are still open validation work. The project does not make automatic system changes. Investigation output may name a Windows diagnostic surface to open manually; Difftrail never launches it or performs rollback, uninstall, disable, or repair actions.
