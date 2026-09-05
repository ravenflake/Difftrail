from __future__ import annotations

import argparse
import ast
import json
import re
import sys
import tomllib
from pathlib import Path


VERSION_PATTERN = re.compile(r'(?m)^__version__\s*=\s*["\']([^"\']+)["\']\s*$')


def check_runtime_version(root: Path, expected: str, *, allow_build_stamp: bool = False) -> None:
    stamp = root / "difftrail/_build_version.py"
    if not stamp.exists():
        return
    assignments = ast.parse(stamp.read_text(encoding="utf-8")).body
    values = [ast.literal_eval(node.value) for node in assignments
              if isinstance(node, ast.Assign) and any(isinstance(target, ast.Name) and target.id == "BUILD_VERSION" for target in node.targets)]
    if len(values) != 1 or not isinstance(values[0], str):
        raise ValueError("Invalid ignored backend build stamp")
    if values[0] == expected:
        return
    if allow_build_stamp:
        config = json.loads((root / "ui/src-tauri/tauri.build.conf.json").read_text(encoding="utf-8"))
        if config.get("version") == values[0]:
            return
    raise ValueError("Ignored backend build stamp differs from release metadata. Archive stale build stamps before a release build, or explicitly build both components with the matching development configuration.")


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
    parser.add_argument("--runtime", action="store_true", help="Reject a stale ignored backend build stamp")
    parser.add_argument("--allow-build-stamp", action="store_true", help="Permit a matching generated development Tauri configuration")
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
    if args.runtime:
        try:
            check_runtime_version(root, version, allow_build_stamp=args.allow_build_stamp)
        except (OSError, SyntaxError, TypeError, ValueError) as exc:
            print(f"Runtime metadata mismatch: {exc}", file=sys.stderr)
            return 1
    if args.expected and version != args.expected:
        print(f"Release metadata is {version!r}; expected {args.expected!r}", file=sys.stderr)
        return 1
    print(f"Release metadata is consistent at {version}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
