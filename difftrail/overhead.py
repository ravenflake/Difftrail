from __future__ import annotations

import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class ProcessSample:
    cpu_seconds: float
    rss_bytes: int
    read_bytes: int
    write_bytes: int


def _sample_tree(process: Any) -> ProcessSample:
    processes = [process]
    try:
        processes.extend(process.children(recursive=True))
    except Exception:
        pass
    cpu = 0.0
    rss = 0
    read_bytes = 0
    write_bytes = 0
    for item in processes:
        try:
            times = item.cpu_times()
            memory = item.memory_info()
            io = item.io_counters()
            cpu += float(times.user) + float(times.system)
            rss += int(memory.rss)
            read_bytes += int(getattr(io, "read_bytes", 0))
            write_bytes += int(getattr(io, "write_bytes", 0))
        except Exception:
            continue
    return ProcessSample(cpu, rss, read_bytes, write_bytes)


def _watcher_command(interval_seconds: int) -> tuple[list[str], Path]:
    """Return the real watcher command for source and frozen installations."""

    if getattr(sys, "frozen", False):
        # The bundled backend is already the ``difftrail`` entry point. Passing
        # ``-m difftrail`` to it makes argparse treat ``difftrail`` as a command,
        # which is why installed footprint measurements used to fail during
        # warmup. Keep using the continuous watcher command here so the sampling
        # window measures repeated-scan idle behavior as well as startup.
        executable = Path(sys.executable).resolve()
        return (
            [
                str(executable),
                "--db",
                ":memory:",
                "watch",
                "--interval",
                str(interval_seconds),
            ],
            executable.parent,
        )

    project_root = Path(__file__).resolve().parent.parent
    return (
        [
            sys.executable,
            "-m",
            "difftrail",
            "--db",
            ":memory:",
            "watch",
            "--interval",
            str(interval_seconds),
        ],
        project_root,
    )


def measure_watcher_overhead(
    *,
    interval_seconds: int = 15,
    warmup_seconds: float = 8.0,
    sample_seconds: float = 10.0,
) -> dict[str, Any]:
    """Measure the real watcher process and its short-lived collector children.

    This is intentionally a validation command, not an application dependency:
    it uses psutil when available and never changes system state. The reported
    CPU and I/O values cover the watcher process tree during the observation
    window, while RSS is a point-in-time/peak measurement.
    """

    if interval_seconds < 15:
        raise ValueError("interval_seconds must be at least 15 seconds")
    if warmup_seconds < 1 or sample_seconds < 1:
        raise ValueError("warmup_seconds and sample_seconds must be positive")
    try:
        import psutil
    except ImportError as exc:
        raise RuntimeError("The overhead validator requires the optional psutil package") from exc

    command, working_directory = _watcher_command(interval_seconds)
    child = subprocess.Popen(
        command,
        cwd=working_directory,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
    )
    process = psutil.Process(child.pid)
    error_text = ""
    try:
        boot_sample = _sample_tree(process)
        warmup_samples = [boot_sample]
        warmup_started = time.monotonic()
        while time.monotonic() - warmup_started < warmup_seconds:
            if child.poll() is not None:
                error_text = (child.stderr.read() if child.stderr else "").strip()
                raise RuntimeError(f"watcher exited during warmup: {error_text or child.returncode}")
            time.sleep(min(0.5, warmup_seconds))
            warmup_samples.append(_sample_tree(process))
        warmup_elapsed = max(0.001, time.monotonic() - warmup_started)
        start = warmup_samples[-1]
        samples = [start]
        started = time.monotonic()
        while time.monotonic() - started < sample_seconds:
            if child.poll() is not None:
                error_text = (child.stderr.read() if child.stderr else "").strip()
                raise RuntimeError(f"watcher exited during sampling: {error_text or child.returncode}")
            time.sleep(min(1.0, sample_seconds))
            samples.append(_sample_tree(process))
        elapsed = max(0.001, time.monotonic() - started)
        end = samples[-1]
        cpu_delta = max(0.0, end.cpu_seconds - start.cpu_seconds)
        read_delta = max(0, end.read_bytes - start.read_bytes)
        write_delta = max(0, end.write_bytes - start.write_bytes)
        warmup_end = warmup_samples[-1]
        warmup_read_delta = max(0, warmup_end.read_bytes - boot_sample.read_bytes)
        warmup_write_delta = max(0, warmup_end.write_bytes - boot_sample.write_bytes)
        return {
            "status": "ok",
            "interval_seconds": interval_seconds,
            "warmup_seconds": round(warmup_seconds, 2),
            "sample_seconds": round(elapsed, 2),
            "process_id": child.pid,
            "startup_process_tree_cpu_percent": round(
                max(0.0, warmup_end.cpu_seconds - boot_sample.cpu_seconds) / warmup_elapsed * 100.0, 3
            ),
            "process_tree_cpu_percent": round(cpu_delta / elapsed * 100.0, 3),
            "startup_rss_mb_peak": round(max(sample.rss_bytes for sample in warmup_samples) / 1_048_576, 2),
            "rss_mb_mean": round(sum(sample.rss_bytes for sample in samples) / len(samples) / 1_048_576, 2),
            "rss_mb_peak": round(max(sample.rss_bytes for sample in samples) / 1_048_576, 2),
            "startup_disk_read_mb": round(warmup_read_delta / 1_048_576, 3),
            "startup_disk_write_mb": round(warmup_write_delta / 1_048_576, 3),
            "disk_read_mb": round(read_delta / 1_048_576, 3),
            "disk_write_mb": round(write_delta / 1_048_576, 3),
            "sample_count": len(samples),
            "scope": "watcher process plus collector child processes; system-wide load is not included",
        }
    finally:
        if child.poll() is None:
            child.terminate()
            try:
                child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait(timeout=5)
