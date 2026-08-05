from __future__ import annotations

import argparse
import json
import re
import sys
import tomllib
from pathlib import Path


VERSION_PATTERN = re.compile(r'(?m)^__version__\s*=\s*["\']([^"\']+)["\']\s*$')


def read_versions(root: Path) -> dict[str, str]:
    with (root / "pyproject.toml").open("rb") as handle:
        pyproject = tomllib.load(handle)
    with (root / "ui/package.json").open(encoding="utf-8") as handle:
        package = json.load(handle)
    with (root / "ui/package-lock.json").open(encoding="utf-8") as handle:
        lock = json.load(handle)
    with (root / "ui/src-tauri/tauri.conf.json").open(encoding="utf-8") as handle:
        tauri = json.load(handle)
    with (root / "ui/src-tauri/Cargo.toml").open("rb") as handle:
        cargo = tomllib.load(handle)
    with (root / "ui/src-tauri/Cargo.lock").open("rb") as handle:
        lock_packages = tomllib.load(handle)["package"]
    init_text = (root / "difftrail/__init__.py").read_text(encoding="utf-8")
    init_match = VERSION_PATTERN.search(init_text)
    if init_match is None:
        raise ValueError("difftrail/__init__.py does not define __version__")
    desktop_lock = next(
        item["version"] for item in lock_packages if item.get("name") == "difftrail-desktop"
    )
    lock_root = lock.get("packages", {}).get("")
    if not isinstance(lock_root, dict):
        raise ValueError("ui/package-lock.json is missing its root package entry")
    return {
        "difftrail/__init__.py": init_match.group(1),
        "pyproject.toml": str(pyproject["project"]["version"]),
        "ui/package.json": str(package["version"]),
        "ui/package-lock.json": str(lock.get("version")),
        "ui/package-lock.json#root": str(lock_root.get("version")),
        "ui/src-tauri/tauri.conf.json": str(tauri["version"]),
        "ui/src-tauri/Cargo.toml": str(cargo["package"]["version"]),
        "ui/src-tauri/Cargo.lock": str(desktop_lock),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check Difftrail release metadata consistency")
    parser.add_argument("--expected", help="Require this exact base version")
    args = parser.parse_args(argv)
    root = Path(__file__).resolve().parents[1]
    try:
        versions = read_versions(root)
    except (KeyError, OSError, StopIteration, TypeError, ValueError) as exc:
        print(f"Release metadata could not be read: {exc}", file=sys.stderr)
        return 1
    unique = set(versions.values())
    if len(unique) != 1:
        details = ", ".join(f"{path}={version!r}" for path, version in versions.items())
        print(f"Release metadata mismatch: {details}", file=sys.stderr)
        return 1
    version = next(iter(unique))
    if args.expected and version != args.expected:
        print(f"Release metadata is {version!r}; expected {args.expected!r}", file=sys.stderr)
        return 1
    print(f"Release metadata is consistent at {version}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
