from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

from . import __version__
from .correlation import infer_subsystem, investigation_summary, rank_candidates
from .db import Database
from .demo import seed_demo
from .models import IncidentRequest, iso_datetime, parse_datetime, utc_now
from .service import Scanner


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
        result = Scanner(database).scan()
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
    request = IncidentRequest(args.description, onset_start, onset_end, subsystem, args.lookback_days)
    with _database(args) as database:
        incident = database.create_incident(request)
        events = database.list_events(limit=10_000, ascending=True)
        hypotheses = rank_candidates(events, request)
        summary = investigation_summary(request, hypotheses)
        database.update_incident_results(incident.id, summary["hypotheses"])
        if args.json:
            summary["incident_id"] = incident.id
            _print_json(summary)
        else:
            print(f"Investigation {incident.id}")
            print(f"Area: {subsystem} | Onset: {iso_datetime(onset_start)}")
            print("Method: deterministic evidence signals; no AI causal inference")
            if not hypotheses:
                print("No candidate changes were found in the selected lookback window.")
            for index, hypothesis in enumerate(hypotheses, start=1):
                print(f"\n{index}. [{hypothesis.confidence}] {hypothesis.event.title}")
                for evidence in hypothesis.evidence:
                    print(f"   + {evidence.signal}: {evidence.explanation}")
                for evidence in hypothesis.counter_evidence:
                    print(f"   - {evidence.signal}: {evidence.explanation}")
                print(f"   Next step: {hypothesis.next_action}")
                print(
                    f"   Safe diagnostic: {hypothesis.safe_diagnostic['label']} "
                    f"({hypothesis.safe_diagnostic['target']}; open manually)"
                )
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


def command_watch(args: argparse.Namespace) -> int:
    with _database(args) as database:
        print(f"Difftrail watcher running every {args.interval} seconds. Press Ctrl+C to stop.")
        try:
            scanner = Scanner(database)
            while True:
                result = scanner.scan()
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
            f"stress top-1 {report['perturbation']['top1_accuracy']:.0%}"
        )
        for scenario in report["scenarios"]:
            print(f"{'PASS' if scenario['passed'] else 'FAIL':4} {scenario['name']} (rank={scenario['rank']})")
    return 0 if report["passed"] else 1


def command_overhead(args: argparse.Namespace) -> int:
    from .overhead import measure_watcher_overhead

    report = measure_watcher_overhead(
        interval_seconds=args.interval,
        warmup_seconds=args.warmup,
        sample_seconds=args.duration,
    )
    _print_json(report) if args.json else print(
        f"Watcher overhead over {report['sample_seconds']}s: "
        f"CPU {report['process_tree_cpu_percent']:.3f}% | "
        f"RSS peak {report['rss_mb_peak']:.2f} MB | "
        f"disk read {report['disk_read_mb']:.3f} MB | "
        f"disk write {report['disk_write_mb']:.3f} MB"
    )
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
    investigate.add_argument("--json", action="store_true")
    investigate.set_defaults(func=command_investigate)

    status = subparsers.add_parser("status", help="Show local journal status")
    status.add_argument("--json", action="store_true")
    status.set_defaults(func=command_status)

    watch = subparsers.add_parser("watch", help="Continuously collect snapshots for a quiet background journal")
    watch.add_argument("--interval", type=int, default=300)
    watch.set_defaults(func=command_watch)

    validate = subparsers.add_parser("validate", help="Run deterministic ground-truth diagnosis scenarios")
    validate.add_argument("--json", action="store_true")
    validate.set_defaults(func=command_validate)

    overhead = subparsers.add_parser("overhead", help="Measure watcher CPU, memory, and process I/O")
    overhead.add_argument("--interval", type=int, default=15)
    overhead.add_argument("--warmup", type=float, default=8.0)
    overhead.add_argument("--duration", type=float, default=10.0)
    overhead.add_argument("--json", action="store_true")
    overhead.set_defaults(func=command_overhead)

    return parser


def main(argv: list[str] | None = None) -> None:
    _configure_output()
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        raise SystemExit(args.func(args))
    except (ValueError, OSError) as exc:
        parser.error(str(exc))
