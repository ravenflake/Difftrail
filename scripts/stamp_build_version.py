from __future__ import annotations

import argparse
import os
from pathlib import Path

if __package__:
    from .versioning import (
        artifact_name,
        development_version,
        main_artifact_name,
        main_snapshot_version,
        read_next_version,
        short_commit_sha,
        validate_build_id,
        validate_pull_request_number,
        write_build_stamp,
    )
else:  # pragma: no cover - used when executed as a script path
    from versioning import (  # type: ignore[no-redef]
        artifact_name,
        development_version,
        main_artifact_name,
        main_snapshot_version,
        read_next_version,
        short_commit_sha,
        validate_build_id,
        validate_pull_request_number,
        write_build_stamp,
    )


def _write_github_outputs(*, version: str, artifact: str, commit_sha: str) -> None:
    output_path = os.environ.get("GITHUB_OUTPUT")
    if not output_path:
        return
    with open(output_path, "a", encoding="utf-8") as output:
        output.write(f"version={version}\n")
        output.write(f"short_sha={short_commit_sha(commit_sha)}\n")
        output.write(f"artifact_name={artifact}\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Stamp ignored development-build metadata")
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    build = parser.add_mutually_exclusive_group(required=True)
    build.add_argument("--pr-number")
    build.add_argument("--channel", choices=("main",))
    parser.add_argument("--build-id", required=True)
    parser.add_argument("--commit-sha", required=True)
    args = parser.parse_args(argv)

    root = args.root.resolve()
    next_version = read_next_version(root)
    build_id = validate_build_id(args.build_id)
    if args.pr_number is not None:
        pr_number = validate_pull_request_number(args.pr_number)
        version = development_version(next_version, pr_number, build_id, args.commit_sha)
        artifact = artifact_name(pr_number, args.commit_sha)
        build_label = f"pull-request #{pr_number}"
    else:
        version = main_snapshot_version(next_version, build_id, args.commit_sha)
        artifact = main_artifact_name(args.commit_sha)
        build_label = "main snapshot"
    write_build_stamp(root, version)
    _write_github_outputs(version=version, artifact=artifact, commit_sha=args.commit_sha)
    print(f"Stamped disposable {build_label} build version {version}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
