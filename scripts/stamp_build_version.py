from __future__ import annotations

import argparse
import os
from pathlib import Path

if __package__:
    from .versioning import (
        artifact_name,
        development_version,
        read_next_version,
        short_commit_sha,
        validate_pull_request_number,
        write_build_stamp,
    )
else:  # pragma: no cover - used when executed as a script path
    from versioning import (  # type: ignore[no-redef]
        artifact_name,
        development_version,
        read_next_version,
        short_commit_sha,
        validate_pull_request_number,
        write_build_stamp,
    )


def _write_github_outputs(*, version: str, pr_number: str, commit_sha: str) -> None:
    output_path = os.environ.get("GITHUB_OUTPUT")
    if not output_path:
        return
    with open(output_path, "a", encoding="utf-8") as output:
        output.write(f"version={version}\n")
        output.write(f"short_sha={short_commit_sha(commit_sha)}\n")
        output.write(f"artifact_name={artifact_name(pr_number, commit_sha)}\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Stamp ignored pull-request build metadata")
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--pr-number", required=True)
    parser.add_argument("--commit-sha", required=True)
    args = parser.parse_args(argv)

    root = args.root.resolve()
    pr_number = validate_pull_request_number(args.pr_number)
    version = development_version(read_next_version(root), pr_number, args.commit_sha)
    write_build_stamp(root, version)
    _write_github_outputs(version=version, pr_number=pr_number, commit_sha=args.commit_sha)
    print(f"Stamped disposable pull-request build version {version}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
