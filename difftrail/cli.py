from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

from . import __version__
from .automation import run_automated_scan
from .bundles import export_bundle, read_bundle, write_bundle
from .correlation import infer_subsystem
from .db import Database
from .demo import seed_demo
from .host_validation import build_host_validation_report
from .investigation import run_investigation
from .models import IncidentRequest, iso_datetime, parse_datetime, utc_now
from .simulation import run_controlled_fixture_suite, simulate_nvidia_driver_switch


def default_database_path() -> Path:
    if os.name == "nt":
        root = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
        return root / "Difftrail" / "difftrail.db"
    return Path.home() / ".local" / "share" / "difftrail" / "difftrail.db"


def _database(args: argparse.Namespace) -> Database:
    return Database(Path(args.db) if args.db else default_database_path())


def _print_json(value: object) -> None:
    print(json.dumps(value, ensure_ascii=False, indent=2, default=str))


def _configure_output() -> None:
    """Keep human and JSON output usable in Windows consoles and pipes."""

    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            reconfigure(encoding="utf-8", errors="replace")


def _format_event(event) -> str:
    return f"{iso_datetime(event.occurred_at):19}  {event.kind:7}  {event.subsystem:14}  {event.title}"


def command_scan(args: argparse.Namespace) -> int:
    with _database(args) as database:
        result = run_automated_scan(database)
        if args.json:
            _print_json(result.as_dict())
        else:
            print(
                f"Scan {result.status}: {result.state_events} changes, "
                f"{result.symptom_events} symptoms across {result.sources} sources."
            )
            if result.errors:
                print("Warnings:")
                for error in result.errors:
                    print(f"- {error}")
    return 0


def command_seed_demo(args: argparse.Namespace) -> int:
    with _database(args) as database:
        count = seed_demo(database)
        if args.json:
            _print_json({"inserted": count, "events": database.count_events()})
        elif count:
            print(f"Seeded {count} local demo events.")
        else:
            print("Demo data was not added because this database already contains events.")
    return 0


def command_simulate(args: argparse.Namespace) -> int:
    with _database(args) as database:
        if args.scenario == "nvidia-driver-switch":
            result = simulate_nvidia_driver_switch(database)
        else:  # pragma: no cover - argparse restricts this branch
            raise ValueError(f"Unknown simulation scenario: {args.scenario}")
        if args.json:
            _print_json(result)
        else:
            print("Simulation complete: fixture data only; Windows state was not changed.")
            print(
                f"Baseline: {result['baseline']['state_events']} changes, "
                f"{result['baseline']['symptom_events']} symptoms."
            )
            print(
                f"Replay: {result['change_scan']['state_events']} changes, "
                f"{result['change_scan']['symptom_events']} symptoms."
            )
            print(f"Next: {result['next_command']}")
    return 0


def command_timeline(args: argparse.Namespace) -> int:
    with _database(args) as database:
        events = database.list_events(limit=args.limit, kind=args.kind, subsystem=args.subsystem)
        if args.json:
            _print_json([event.as_dict() for event in events])
        else:
            print("TIME (UTC)           KIND     SUBSYSTEM       EVENT")
            print("-" * 86)
            for event in events:
                print(_format_event(event))
            if not events:
                print("No events yet. Run `python -m difftrail seed-demo` or `scan` to build the journal.")
    return 0


def command_investigate(args: argparse.Namespace) -> int:
    now = utc_now()
    # A problem reported without an explicit onset is assumed to be happening
    # now. This keeps changes from the immediately preceding scan eligible;
    # users can still provide --onset when they know when the problem began.
    onset_start = parse_datetime(args.onset) if args.onset else now
    onset_end = now
    subsystem = args.subsystem or infer_subsystem(args.description)
    request = IncidentRequest(
        args.description,
        onset_start,
        onset_end,
        subsystem,
        args.lookback_days,
        affected_entity=getattr(args, "affected_entity", None),
        suspected_change=getattr(args, "suspected_change", None),
    )
    with _database(args) as database:
        run = run_investigation(database, request)
        incident = run.incident
        hypotheses = run.hypotheses
        assessment = run.assessment
        summary = run.summary
        if args.json:
            summary["incident_id"] = incident.id
            _print_json(summary)
        else:
            print(f"Investigation {incident.id}")
            print(f"Area: {subsystem} | Onset: {iso_datetime(onset_start)}")
            print(f"Assessment: {assessment.state}")
            for reason in assessment.reasons:
                print(f"- {reason}")
            print("Method: deterministic evidence signals; no AI causal inference")
            if not hypotheses:
                print("No candidate changes were found in the selected lookback window.")
            for index, hypothesis in enumerate(hypotheses, start=1):
                print(f"\n{index}. [{hypothesis.confidence}] {hypothesis.event.title}")
                for evidence in hypothesis.evidence:
                    print(f"   + {evidence.signal}: {evidence.explanation}")
                for evidence in hypothesis.counter_evidence:
                    print(f"   - {evidence.signal}: {evidence.explanation}")
                print(f"   Event ID: {hypothesis.event.event_id}")
                print(f"   Next step: {hypothesis.next_action}")
                print(
                    f"   Safe diagnostic: {hypothesis.safe_diagnostic['label']} "
                    f"({hypothesis.safe_diagnostic['target']}; open manually)"
                )
    return 0


def command_feedback(args: argparse.Namespace) -> int:
    with _database(args) as database:
        incident = database.record_incident_feedback(
            args.incident_id,
            args.outcome,
            event_id=args.event_id,
        )
        result = {
            "incident_id": incident["id"],
            "outcome": incident["feedback"]["outcome"],
            "event_id": incident["feedback"]["event_id"],
            "recorded_at": incident["feedback"]["recorded_at"],
        }
        if args.json:
            _print_json(result)
        else:
            selected = f" for event {result['event_id']}" if result["event_id"] else ""
            print(f"Feedback recorded: {result['outcome']}{selected}.")
            print(f"Incident: {result['incident_id']}")
    return 0


def command_status(args: argparse.Namespace) -> int:
    with _database(args) as database:
        status = database.status()
        if args.json:
            _print_json(status)
        else:
            print(
                f"{status['events']} events ({status['changes']} changes, {status['symptoms']} symptoms), "
                f"{status['incidents']} investigations."
            )
            if status["last_scan"]:
                print(f"Last scan: {status['last_scan']['status']} at {status['last_scan']['finished_at']}")
    return 0


def command_doctor(args: argparse.Namespace) -> int:
    with _database(args) as database:
        recovered = database.recover_stale_scans() if args.recover_stale_scans else 0
        report = database.journal_diagnostics()
        report["recovered_stale_scans"] = recovered
    if args.json:
        _print_json(report)
    else:
        schema = report["schema"]
        scans = report["scans"]
        print(
            f"Doctor: {'PASS' if report['ok'] else 'ATTENTION'} | "
            f"schema {schema['current_version']}/{schema['supported_version']} | "
            f"integrity {report['integrity']}"
        )
        print(f"Scans: {scans['running']} running, {len(scans['stale_running'])} stale")
        if recovered:
            print(f"Recovered {recovered} stale scan{'' if recovered == 1 else 's'} as interrupted.")
        print(
            f"Journal: {report['journal']['events']} events, "
            f"{report['journal']['state_items']} state items, "
            f"{report['journal']['incidents']} investigations."
        )
    return 0 if report["ok"] else 1


def command_export_bundle(args: argparse.Namespace) -> int:
    with _database(args) as database:
        bundle = export_bundle(database, days=args.days, incident_id=args.incident)
        output = write_bundle(bundle, args.output, database_path=database.path)
        result = {
            "output": str(output),
            "format": bundle["format"],
            "format_version": bundle["format_version"],
            "events": len(bundle["journal"]["events"]),
            "investigations": len(bundle["investigations"]),
        }
    if args.json:
        _print_json(result)
    else:
        print(
            f"Exported redacted bundle to {result['output']} "
            f"({result['events']} events, {result['investigations']} investigations)."
        )
    return 0


def command_validate_bundle(args: argparse.Namespace) -> int:
    _, report = read_bundle(args.bundle)
    if args.json:
        _print_json(report)
    else:
        print(f"Bundle validation: {'PASS' if report['valid'] else 'FAIL'}")
        for error in report.get("errors", []):
            print(f"- {error}")
        if report.get("valid"):
            print(f"Events: {report.get('event_count', 0)} | investigations: {report.get('investigation_count', 0)}")
    return 0 if report["valid"] else 1


def command_watch(args: argparse.Namespace) -> int:
    if args.interval < 15 or args.interval > 86_400:
        raise ValueError("The watcher interval must be between 15 and 86400 seconds")
    with _database(args) as database:
        print(f"Difftrail watcher running every {args.interval} seconds. Press Ctrl+C to stop.")
        try:
            while True:
                result = run_automated_scan(database)
                print(
                    f"Scan {result.status}: {result.state_events} changes, "
                    f"{result.symptom_events} symptoms across {result.sources} sources."
                )
                for error in result.errors:
                    print(f"Warning: {error}")
                time.sleep(args.interval)
        except KeyboardInterrupt:
            print("\nWatcher stopped.")
    return 0


def command_validate(args: argparse.Namespace) -> int:
    from .validation import run_ground_truth_suite

    report = run_ground_truth_suite()
    if args.json:
        _print_json(report)
    else:
        print(
            f"Ground-truth suite: {'PASS' if report['passed'] else 'FAIL'} | "
            f"top-1 {report['top1_accuracy']:.0%} | top-3 {report['top3_accuracy']:.0%} | "
            f"no false High {report['no_false_high_rate']:.0%} | "
            f"assessment {report['assessment_pass_rate']:.0%} | "
            f"determinism {'PASS' if report['determinism']['passed'] else 'FAIL'} | "
            f"stress top-1 {report['perturbation']['top1_accuracy']:.0%}"
        )
        for scenario in report["scenarios"]:
            print(f"{'PASS' if scenario['passed'] else 'FAIL':4} {scenario['name']} (rank={scenario['rank']})")
    return 0 if report["passed"] else 1


def command_validate_scenarios(args: argparse.Namespace) -> int:
    report = run_controlled_fixture_suite()
    if args.json:
        _print_json(report)
    else:
        checks = report["checks"]
        print(
            f"Controlled fixture suite: {'PASS' if report['passed'] else 'FAIL'} | "
            f"{report['scenario_count']} scenarios | "
            f"capture {'PASS' if checks['capture'] else 'FAIL'} | "
            f"ranking {'PASS' if checks['ranking'] else 'FAIL'} | "
            f"no false High {'PASS' if checks['no_false_high'] else 'FAIL'} | "
            f"evidence {'PASS' if checks['evidence'] else 'FAIL'}"
        )
        for scenario in report["scenarios"]:
            checks = scenario["checks"]
            print(
                f"{'PASS' if scenario['passed'] else 'FAIL':4} {scenario['name']} "
                f"({scenario['replay']['state_events']} changes, {scenario['replay']['symptom_events']} symptoms; "
                f"capture={'PASS' if checks['capture'] else 'FAIL'}, "
                f"ranking={'PASS' if checks['ranking'] else 'FAIL'})"
            )
            for expectation in scenario["expectations"]:
                print(
                    f"     {'PASS' if expectation['passed'] else 'FAIL':4} "
                    f"{expectation['source']} {expectation['title_contains'] or expectation['action']} "
                    f"(rank={expectation['rank']})"
                )
    return 0 if report["passed"] else 1


def command_overhead(args: argparse.Namespace) -> int:
    from .overhead import measure_watcher_overhead

    report = measure_watcher_overhead(
        interval_seconds=args.interval,
        warmup_seconds=args.warmup,
        sample_seconds=args.duration,
    )
    if getattr(args, "record", False):
        with _database(args) as database:
            report["recorded_measurement_id"] = database.record_overhead_measurement(report)
    _print_json(report) if args.json else print(
        f"Watcher overhead over {report['sample_seconds']}s: "
        f"CPU {report['process_tree_cpu_percent']:.3f}% | "
        f"RSS peak {report['rss_mb_peak']:.2f} MB | "
        f"disk read {report['disk_read_mb']:.3f} MB | "
        f"disk write {report['disk_write_mb']:.3f} MB"
    )
    return 0


def command_validate_host(args: argparse.Namespace) -> int:
    with _database(args) as database:
        report = build_host_validation_report(database, days=args.days)
    if args.json:
        _print_json(report)
    else:
        scans = report["scans"]
        journal = report["journal"]
        overhead = report["overhead"]
        investigations = report["investigations"]
        provider_errors = scans["provider_error_count"]
        quiet_rate = scans["quiet_rate"]
        quiet_text = "n/a" if quiet_rate is None else f"{quiet_rate:.1%}"
        print(f"Host validation report: last {args.days} days")
        print(
            f"Scans: {scans['total']} | quiet {scans['quiet']} "
            f"({quiet_text}) | "
            f"provider errors {provider_errors}."
        )
        print(
            f"Journal: {journal['changes']} changes, {journal['symptoms']} symptoms "
            f"({journal['changes_per_day']:.2f} changes/day)."
        )
        if overhead["measurements"]:
            print(
                f"Overhead samples: {overhead['measurements']} | "
                f"CPU mean/peak {overhead['cpu_percent_mean']:.3f}%/{overhead['cpu_percent_peak']:.3f}% | "
                f"RSS mean/peak {overhead['rss_mb_mean']:.2f}/{overhead['rss_mb_peak']:.2f} MB."
            )
        else:
            print("Overhead: no recorded measurements. Use `overhead --record` to add one.")
        feedback = investigations["with_feedback"]
        top3_rate = investigations["correct_cause_top3_rate"]
        top3_text = "n/a" if top3_rate is None else f"{top3_rate:.1%}"
        print(
            f"Investigations: {investigations['total']} | feedback {feedback} | "
            f"correct-cause top-3 {investigations['correct_cause_top3_hits']}/{investigations['outcomes']['correct']} ({top3_text})."
        )
        print("Privacy: aggregate local report; raw evidence and paths are omitted.")
    return 0


def command_ui(args: argparse.Namespace) -> int:
    from .ui_api import serve

    serve(Path(args.db) if args.db else default_database_path(), host=args.host, port=args.port)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="difftrail", description="Local-first Windows change journal and investigator")
    parser.add_argument("--db", help=f"SQLite path (default: {default_database_path()})")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan = subparsers.add_parser("scan", help="Collect a read-only Windows snapshot and symptom events")
    scan.add_argument("--json", action="store_true")
    scan.set_defaults(func=command_scan)

    demo = subparsers.add_parser("seed-demo", help="Add a safe synthetic incident for first-run exploration")
    demo.add_argument("--json", action="store_true")
    demo.set_defaults(func=command_seed_demo)

    simulate = subparsers.add_parser("simulate", help="Replay a safe local fixture scenario without touching Windows")
    simulate.add_argument("scenario", choices=["nvidia-driver-switch"])
    simulate.add_argument("--json", action="store_true")
    simulate.set_defaults(func=command_simulate)

    timeline = subparsers.add_parser("timeline", help="Print the normalized change journal")
    timeline.add_argument("--limit", type=int, default=50)
    timeline.add_argument("--kind", choices=["all", "change", "symptom"], default="all")
    timeline.add_argument("--subsystem", default="all")
    timeline.add_argument("--json", action="store_true")
    timeline.set_defaults(func=command_timeline)

    investigate = subparsers.add_parser("investigate", help="Rank likely changes for a reported problem")
    investigate.add_argument("description")
    investigate.add_argument(
        "--onset",
        help="ISO timestamp when the problem began (default: now), e.g. 2026-08-01T10:30:00Z",
    )
    investigate.add_argument(
        "--subsystem",
        choices=[
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
        ],
    )
    investigate.add_argument("--lookback-days", type=int, default=7)
    investigate.add_argument(
        "--affected-entity",
        help="Optional affected application, process, service, or device name",
    )
    investigate.add_argument(
        "--suspected-change",
        help="Optional recent update, install, or other change the user suspects",
    )
    investigate.add_argument("--json", action="store_true")
    investigate.set_defaults(func=command_investigate)

    feedback = subparsers.add_parser("feedback", help="Record whether an investigation's selected cause was correct")
    feedback.add_argument("incident_id")
    feedback.add_argument("--outcome", choices=["correct", "incorrect", "unknown"], required=True)
    feedback.add_argument("--event-id", help="Event ID for the cause judged correct; required for --outcome correct")
    feedback.add_argument("--json", action="store_true")
    feedback.set_defaults(func=command_feedback)

    status = subparsers.add_parser("status", help="Show local journal status")
    status.add_argument("--json", action="store_true")
    status.set_defaults(func=command_status)

    doctor = subparsers.add_parser("doctor", help="Check journal integrity, migrations, and scan recovery state")
    doctor.add_argument("--recover-stale-scans", action="store_true", help="Mark abandoned scans as interrupted")
    doctor.add_argument("--json", action="store_true")
    doctor.set_defaults(func=command_doctor)

    export = subparsers.add_parser("export-bundle", help="Export a portable redacted diagnostic bundle")
    export.add_argument("--output", required=True, help="Output JSON file")
    export.add_argument("--days", type=int, default=30, help="Journal period to include (1-3650 days)")
    export.add_argument("--incident", help="Export one saved investigation and its evidence window")
    export.add_argument("--json", action="store_true")
    export.set_defaults(func=command_export_bundle)

    validate_bundle_parser = subparsers.add_parser("validate-bundle", help="Validate a diagnostic bundle without importing it")
    validate_bundle_parser.add_argument("bundle", help="Bundle JSON file")
    validate_bundle_parser.add_argument("--json", action="store_true")
    validate_bundle_parser.set_defaults(func=command_validate_bundle)

    watch = subparsers.add_parser("watch", help="Continuously collect snapshots for a quiet background journal")
    watch.add_argument("--interval", type=int, default=300)
    watch.set_defaults(func=command_watch)

    validate = subparsers.add_parser("validate", help="Run deterministic ground-truth diagnosis scenarios")
    validate.add_argument("--json", action="store_true")
    validate.set_defaults(func=command_validate)

    validate_scenarios = subparsers.add_parser(
        "validate-scenarios",
        help="Run safe scanner-backed fixture scenarios without changing Windows",
    )
    validate_scenarios.add_argument("--json", action="store_true")
    validate_scenarios.set_defaults(func=command_validate_scenarios)

    overhead = subparsers.add_parser("overhead", help="Measure watcher CPU, memory, and process I/O")
    overhead.add_argument("--interval", type=int, default=15)
    overhead.add_argument("--warmup", type=float, default=8.0)
    overhead.add_argument("--duration", type=float, default=10.0)
    overhead.add_argument("--record", action="store_true", help="Store aggregate numeric results in the selected local database")
    overhead.add_argument("--json", action="store_true")
    overhead.set_defaults(func=command_overhead)

    validate_host = subparsers.add_parser(
        "validate-host",
        help="Build an aggregate local report from real scans, overhead samples, and labeled investigations",
    )
    validate_host.add_argument("--days", type=int, default=7)
    validate_host.add_argument("--json", action="store_true")
    validate_host.set_defaults(func=command_validate_host)

    ui = subparsers.add_parser("ui", help="Serve the local API used by the Difftrail desktop interface")
    ui.add_argument("--host", default="127.0.0.1")
    ui.add_argument("--port", type=int, default=45917)
    ui.set_defaults(func=command_ui)

    return parser


def main(argv: list[str] | None = None) -> None:
    _configure_output()
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        raise SystemExit(args.func(args))
    except (ValueError, OSError) as exc:
        parser.error(str(exc))
