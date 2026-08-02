from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Iterable

from .collectors.windows import WindowsCollector
from .correlation import Hypothesis, investigation_summary, rank_candidates
from .db import Database
from .models import Event, IncidentRequest, SnapshotItem, utc_now
from .service import Scanner


class _NvidiaDriverSwitchFixture:
    """Normalized Windows-shaped records for a safe local replay.

    The fixture deliberately goes through WindowsCollector's row normalizers
    and Scanner rather than inserting finished events. It therefore exercises
    the same snapshot diff and evidence path as a real scan, without invoking
    PowerShell or changing Windows state.
    """

    def __init__(self) -> None:
        collector = WindowsCollector()
        self.phase = 0
        self.before = self._snapshots(collector, "31.0.15.5222", "06/01/2025 01:00:00", "nv_studio.inf_amd64_fixture")
        self.after = self._snapshots(collector, "32.0.16.1088", "07/22/2026 02:00:00", "nv_gameready.inf_amd64_fixture")
        self.last_errors: list[str] = []

    @staticmethod
    def _snapshots(
        collector: WindowsCollector,
        driver_version: str,
        driver_date: str,
        package_folder: str,
    ) -> dict[str, list[SnapshotItem]]:
        driver_rows: list[dict[str, Any]] = [
            {
                "DeviceID": r"PCI\VEN_10DE&DEV_2783&FIXTURE",
                "DeviceName": "NVIDIA GeForce RTX 4070 SUPER",
                "DriverVersion": driver_version,
                "DriverDate": driver_date,
                "Manufacturer": "NVIDIA",
                "Class": "{4d36e968-e325-11ce-bfc1-08002be10318}",
                "IsSigned": True,
            }
        ]
        service_rows: list[dict[str, Any]] = [
            {
                "Name": "NVDisplay.ContainerLocalSystem",
                "DisplayName": "NVIDIA Display Container LS",
                "State": "Running",
                "StartMode": "Auto",
                "StartName": "LocalSystem",
                "PathName": rf"C:\Windows\System32\DriverStore\FileRepository\{package_folder}\Display.NvContainer\NVDisplay.Container.exe",
            }
        ]
        return {
            "drivers": collector._drivers(driver_rows),
            "services": collector._services(service_rows),
        }

    def collect_snapshots(self) -> dict[str, list[SnapshotItem]]:
        return self.before if self.phase == 0 else self.after

    def collect_symptoms(self, since: datetime) -> list[Event]:
        if self.phase == 0:
            return []
        return [
            Event(
                occurred_at=utc_now(),
                kind="symptom",
                subsystem="graphics",
                action="driver_reset",
                title="Display driver reset detected",
                entity="NVIDIA GeForce RTX 4070 SUPER",
                severity="high",
                source="fixture:eventlog",
                details={"message": "Simulated display driver stopped responding and recovered."},
                event_id="fixture:nvidia-driver-reset",
            )
        ]


@dataclass(frozen=True)
class FixtureExpectation:
    """A source-level assertion for a scanner-backed scenario replay."""

    source: str
    title_contains: str = ""
    action: str | None = None
    max_rank: int = 3

    def matches(self, event: Event) -> bool:
        return (
            event.source == self.source
            and (self.action is None or event.action == self.action)
            and (not self.title_contains or self.title_contains.casefold() in event.title.casefold())
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "title_contains": self.title_contains,
            "action": self.action,
            "max_rank": self.max_rank,
        }


@dataclass(frozen=True)
class FixtureSymptom:
    subsystem: str
    action: str
    title: str
    entity: str
    event_id: str
    message: str


@dataclass(frozen=True)
class ControlledScenario:
    name: str
    description: str
    problem: str
    subsystem: str
    before: dict[str, list[SnapshotItem]]
    after: dict[str, list[SnapshotItem]]
    symptom: FixtureSymptom
    expected_changes: int
    expectations: tuple[FixtureExpectation, ...]


class _ControlledFixture:
    """Replay normalized Windows-shaped snapshots through the real Scanner."""

    def __init__(self, scenario: ControlledScenario) -> None:
        self.scenario = scenario
        self.phase = 0
        self.last_errors: list[str] = []

    def collect_snapshots(self) -> dict[str, list[SnapshotItem]]:
        return self.scenario.before if self.phase == 0 else self.scenario.after

    def collect_symptoms(self, since: datetime) -> list[Event]:
        if self.phase == 0:
            return []
        symptom = self.scenario.symptom
        return [
            Event(
                occurred_at=utc_now(),
                kind="symptom",
                subsystem=symptom.subsystem,
                action=symptom.action,
                title=symptom.title,
                entity=symptom.entity,
                severity="high",
                source=f"fixture:{self.scenario.name}",
                details={"message": symptom.message},
                event_id=symptom.event_id,
            )
        ]


def _normalized_snapshots(
    collector: WindowsCollector,
    *,
    apps: Iterable[dict[str, Any]] = (),
    drivers: Iterable[dict[str, Any]] = (),
    services: Iterable[dict[str, Any]] = (),
    tasks: Iterable[dict[str, Any]] = (),
    startup: Iterable[dict[str, Any]] = (),
    devices: Iterable[dict[str, Any]] = (),
) -> dict[str, list[SnapshotItem]]:
    """Build all seven source families using the production normalizers."""

    return {
        "apps": collector._apps(list(apps)),
        "drivers": collector._drivers(list(drivers)),
        "services": collector._services(list(services)),
        "tasks": collector._tasks(list(tasks)),
        "startup": collector._startup(list(startup)),
        "devices": collector._devices(list(devices)),
        "updates": collector._updates([]),
    }


def build_controlled_scenarios() -> tuple[ControlledScenario, ...]:
    """Return safe scenarios for validating capture and evidence ranking.

    These are deliberately Windows-shaped records, not finished events. Each
    scenario therefore exercises the collector normalizers, quiet baseline,
    snapshot diff, symptom ingestion, SQLite journal, and correlation engine.
    """

    collector = WindowsCollector()
    audio_before = _normalized_snapshots(
        collector,
        devices=[
            {
                "InstanceId": r"HDAUDIO\FUNC_01&VEN_FIXTURE&DEV_SPKR",
                "FriendlyName": "Fixture Realtek Speakers",
                "Class": "MEDIA",
                "Status": "OK",
                "Manufacturer": "Fixture Audio",
            }
        ],
    )
    audio_after = _normalized_snapshots(
        collector,
        devices=[
            {
                "InstanceId": r"USB\VID_FIXTURE&PID_HEADSET",
                "FriendlyName": "Fixture USB Audio Headset",
                "Class": "MEDIA",
                "Status": "OK",
                "Manufacturer": "Fixture Audio",
            }
        ],
    )

    startup_before = _normalized_snapshots(collector)
    startup_after = _normalized_snapshots(
        collector,
        services=[
            {
                "Name": "DifftrailFixture.Helper",
                "DisplayName": "Difftrail Fixture Helper",
                "State": "Running",
                "StartMode": "Auto",
                "StartName": "LocalSystem",
                "PathName": r"C:\Program Files\Difftrail Fixture\helper.exe",
            }
        ],
        tasks=[
            {
                "TaskName": "Difftrail Fixture Cleanup",
                "TaskPath": "\\DifftrailFixture\\",
                "State": "Ready",
                "Author": "Difftrail Fixture",
            }
        ],
        startup=[
            {
                "Name": "Difftrail Fixture Tray",
                "Command": r"C:\Program Files\Difftrail Fixture\tray.exe",
                "Location": "HKCU Run",
                "User": "FixtureUser",
            }
        ],
    )

    app_before = _normalized_snapshots(
        collector,
        apps=[
            {
                "Key": "DifftrailFixturePlayer",
                "DisplayName": "Difftrail Fixture Player",
                "DisplayVersion": "1.0.0",
                "Publisher": "Difftrail Fixture",
                "InstallDate": "20260801",
            }
        ],
    )
    app_after = _normalized_snapshots(
        collector,
        apps=[
            {
                "Key": "DifftrailFixturePlayer",
                "DisplayName": "Difftrail Fixture Player",
                "DisplayVersion": "1.1.0",
                "Publisher": "Difftrail Fixture",
                "InstallDate": "20260802",
            }
        ],
    )

    mixed_before = _normalized_snapshots(
        collector,
        drivers=[
            {
                "DeviceID": r"PCI\VEN_10DE&DEV_2783&MIXED_FIXTURE",
                "DeviceName": "NVIDIA GeForce RTX 4070 SUPER",
                "DriverVersion": "31.0.15.5222",
                "DriverDate": "06/01/2025 01:00:00",
                "Manufacturer": "NVIDIA",
                "Class": "{4d36e968-e325-11ce-bfc1-08002be10318}",
                "IsSigned": True,
            }
        ],
        apps=[
            {
                "Key": "DifftrailMixedChat",
                "DisplayName": "Difftrail Fixture Chat",
                "DisplayVersion": "1.0.0",
                "Publisher": "Difftrail Fixture",
                "InstallDate": "20260801",
            }
        ],
    )
    mixed_after = _normalized_snapshots(
        collector,
        drivers=[
            {
                "DeviceID": r"PCI\VEN_10DE&DEV_2783&MIXED_FIXTURE",
                "DeviceName": "NVIDIA GeForce RTX 4070 SUPER",
                "DriverVersion": "32.0.16.1088",
                "DriverDate": "07/22/2026 02:00:00",
                "Manufacturer": "NVIDIA",
                "Class": "{4d36e968-e325-11ce-bfc1-08002be10318}",
                "IsSigned": True,
            }
        ],
        apps=[
            {
                "Key": "DifftrailMixedChat",
                "DisplayName": "Difftrail Fixture Chat",
                "DisplayVersion": "1.1.0",
                "Publisher": "Difftrail Fixture",
                "InstallDate": "20260802",
            }
        ],
        services=[
            {
                "Name": "DifftrailFixture.Sync",
                "DisplayName": "Difftrail Fixture Sync",
                "State": "Running",
                "StartMode": "Manual",
                "StartName": "LocalSystem",
                "PathName": r"C:\Program Files\Difftrail Fixture\sync.exe",
            }
        ],
        tasks=[
            {
                "TaskName": "Difftrail Fixture Maintenance",
                "TaskPath": "\\DifftrailFixture\\",
                "State": "Ready",
                "Author": "Difftrail Fixture",
            }
        ],
        startup=[
            {
                "Name": "Difftrail Fixture Background",
                "Command": r"C:\Program Files\Difftrail Fixture\background.exe",
                "Location": "HKCU Run",
                "User": "FixtureUser",
            }
        ],
    )

    return (
        ControlledScenario(
            name="audio-device-replacement",
            description="An audio endpoint is replaced before audio becomes unavailable.",
            problem="audio output stopped working",
            subsystem="audio",
            before=audio_before,
            after=audio_after,
            symptom=FixtureSymptom(
                subsystem="audio",
                action="device_failure",
                title="Audio output unavailable",
                entity="Fixture USB Audio Headset",
                event_id="fixture:audio-device-failure",
                message="Simulated audio output failure after an endpoint replacement.",
            ),
            expected_changes=2,
            expectations=(
                FixtureExpectation("devices", "Fixture USB Audio Headset", "added", 2),
                FixtureExpectation("devices", "Devices item removed", "removed", 2),
            ),
        ),
        ControlledScenario(
            name="startup-service-task",
            description="A new service, scheduled task, and startup entry appear before login becomes slow.",
            problem="login became slow after a background change",
            subsystem="startup",
            before=startup_before,
            after=startup_after,
            symptom=FixtureSymptom(
                subsystem="startup",
                action="startup_failure",
                title="Login startup slowdown",
                entity="FixtureUser",
                event_id="fixture:startup-slowdown",
                message="Simulated login slowdown after new persistence entries appeared.",
            ),
            expected_changes=3,
            expectations=(
                FixtureExpectation("services", "Difftrail Fixture Helper", "added", 3),
                FixtureExpectation("tasks", "Difftrail Fixture Cleanup", "added", 3),
                FixtureExpectation("startup", "Difftrail Fixture Tray", "added", 3),
            ),
        ),
        ControlledScenario(
            name="application-update",
            description="An installed application updates before it begins crashing on launch.",
            problem="the fixture player started crashing",
            subsystem="application",
            before=app_before,
            after=app_after,
            symptom=FixtureSymptom(
                subsystem="application",
                action="crash",
                title="Fixture player crash",
                entity="Difftrail Fixture Player",
                event_id="fixture:application-crash",
                message="Simulated application crash after an application update.",
            ),
            expected_changes=1,
            expectations=(FixtureExpectation("apps", "Difftrail Fixture Player", "updated", 1),),
        ),
        ControlledScenario(
            name="mixed-unrelated-changes",
            description="A graphics driver changes alongside unrelated app and persistence changes.",
            problem="graphics started failing",
            subsystem="graphics",
            before=mixed_before,
            after=mixed_after,
            symptom=FixtureSymptom(
                subsystem="graphics",
                action="driver_reset",
                title="Display driver reset",
                entity="NVIDIA GeForce RTX 4070 SUPER",
                event_id="fixture:mixed-driver-reset",
                message="Simulated display driver stopped responding and recovered.",
            ),
            expected_changes=5,
            expectations=(
                FixtureExpectation(
                    "drivers",
                    "Driver for NVIDIA GeForce RTX 4070 SUPER",
                    "updated",
                    1,
                ),
            ),
        ),
    )


def _expectation_report(
    expectation: FixtureExpectation,
    hypotheses: list[Hypothesis],
) -> dict[str, Any]:
    matches = [
        (rank, hypothesis)
        for rank, hypothesis in enumerate(hypotheses, start=1)
        if expectation.matches(hypothesis.event)
    ]
    if not matches:
        return {**expectation.as_dict(), "rank": None, "confidence": None, "passed": False}
    rank, hypothesis = matches[0]
    return {
        **expectation.as_dict(),
        "rank": rank,
        "confidence": hypothesis.confidence,
        "event_id": hypothesis.event.event_id,
        "passed": rank <= expectation.max_rank,
    }


def _run_controlled_scenario(scenario: ControlledScenario) -> dict[str, Any]:
    with Database(":memory:") as database:
        fixture = _ControlledFixture(scenario)
        baseline = Scanner(database, fixture).scan()
        fixture.phase = 1
        replay = Scanner(database, fixture).scan()

        onset = utc_now()
        request = IncidentRequest(scenario.problem, onset, onset, scenario.subsystem, 7)
        incident = database.create_incident(request)
        events = database.list_events(limit=10_000, ascending=True)
        hypotheses = rank_candidates(events, request)
        summary = investigation_summary(request, hypotheses)
        database.update_incident_results(incident.id, summary["hypotheses"])

        expected = [_expectation_report(item, hypotheses) for item in scenario.expectations]
        high_hypotheses = [item for item in hypotheses if item.confidence == "High"]
        no_false_high = all(
            any(expectation.matches(item.event) for expectation in scenario.expectations)
            for item in high_hypotheses
        )
        evidence_passed = all(
            any(
                expectation.matches(hypothesis.event)
                and {evidence.signal for evidence in hypothesis.evidence}
                >= {"temporal proximity", "subsystem relevance", "baseline break"}
                and all(evidence.explanation.strip() for evidence in hypothesis.evidence)
                and "before" in hypothesis.event.details
                and "after" in hypothesis.event.details
                and bool(hypothesis.next_action.strip())
                and bool(hypothesis.safe_diagnostic.get("target"))
                for hypothesis in hypotheses
            )
            for expectation in scenario.expectations
        )
        capture_passed = (
            baseline.status == "ok"
            and baseline.state_events == 0
            and baseline.symptom_events == 0
            and replay.status == "ok"
            and replay.state_events == scenario.expected_changes
            and replay.symptom_events == 1
        )
        ranking_passed = all(item["passed"] for item in expected)
        passed = capture_passed and ranking_passed and no_false_high and evidence_passed
        return {
            "name": scenario.name,
            "description": scenario.description,
            "problem": scenario.problem,
            "subsystem": scenario.subsystem,
            "baseline": baseline.as_dict(),
            "replay": replay.as_dict(),
            "incident_id": incident.id,
            "candidate_count": len(hypotheses),
            "top": hypotheses[0].as_dict() if hypotheses else None,
            "expectations": expected,
            "checks": {
                "capture": capture_passed,
                "ranking": ranking_passed,
                "no_false_high": no_false_high,
                "evidence": evidence_passed,
            },
            "high_confidence_events": [item.event.title for item in high_hypotheses],
            "captured_change_sources": sorted({event.source for event in events if event.kind == "change"}),
            "passed": passed,
        }


def run_controlled_fixture_suite() -> dict[str, Any]:
    """Run scanner-backed fixture scenarios in disposable in-memory journals."""

    scenarios = [_run_controlled_scenario(scenario) for scenario in build_controlled_scenarios()]
    check_names = ("capture", "ranking", "no_false_high", "evidence")
    return {
        "suite": "controlled-fixture-replay",
        "description": "Safe scanner-to-investigation validation using Windows-shaped fixture snapshots.",
        "safety": "ephemeral in-memory databases; no PowerShell commands or Windows state changes",
        "scenario_count": len(scenarios),
        "passed": all(scenario["passed"] for scenario in scenarios),
        "checks": {
            name: all(scenario["checks"][name] for scenario in scenarios)
            for name in check_names
        },
        "scenarios": scenarios,
    }


def simulate_nvidia_driver_switch(database: Database) -> dict[str, Any]:
    """Replay a driver-package transition into an empty local database."""

    if not database.is_empty():
        raise ValueError("Simulation requires an empty database; choose a new --db path.")
    fixture = _NvidiaDriverSwitchFixture()
    baseline = Scanner(database, fixture).scan()
    fixture.phase = 1
    change_scan = Scanner(database, fixture).scan()
    return {
        "scenario": "nvidia-driver-switch",
        "description": "Safe fixture replay of an NVIDIA display driver package transition.",
        "safety": "fixture data only; no PowerShell commands or Windows state changes",
        "baseline": baseline.as_dict(),
        "change_scan": change_scan.as_dict(),
        "next_command": f'python -m difftrail --db "{database.path}" investigate "graphics started failing" --subsystem graphics --json',
    }
