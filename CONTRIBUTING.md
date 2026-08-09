# Contributing to Difftrail

Thanks for your interest in improving Difftrail.

Difftrail is open source under `GPL-3.0-only`, and external contributions are welcome. To preserve the project's ability to offer alternative commercial licensing in the future, contributed code and other copyrightable material are accepted under the Difftrail Contributor License Agreement in [`CLA.md`](CLA.md).

## Start here

- Use the structured issue templates for reproducible bugs and focused feature
  requests.
- Read [`SECURITY.md`](SECURITY.md) and report suspected vulnerabilities
  privately.
- Read [`docs/architecture.md`](docs/architecture.md) before changing storage,
  collectors, privacy, automation, the loopback API, or installer behavior.
- Check [`ROADMAP.md`](ROADMAP.md) for the evidence and reliability work that is
  currently in scope.

Small fixes, deterministic tests, privacy improvements, documentation repairs,
and safe Windows validation reports are useful contributions. Please discuss a
new collector or substantial product-direction change in an issue before doing
large implementation work.

## Development setup

The Python engine supports Python 3.11+ and has no third-party runtime
dependencies:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e .
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
.\.venv\Scripts\python.exe -m difftrail validate
.\.venv\Scripts\python.exe -m difftrail validate-scenarios
```

UI work additionally needs Node.js 20+, Rust stable, and the Windows build tools
required by Tauri:

```powershell
Set-Location .\ui
npm ci
npm test
npm run typecheck
npm run build
```

The full `npm run desktop:build` path is Windows-specific and builds the bundled
Python backend plus NSIS installer. Pull-request CI runs that path and silently
installs/uninstalls the artifact. A contributor without Windows should say so
clearly rather than presenting the installer as locally validated.

## Before opening a pull request

1. Read [`CLA.md`](CLA.md).
2. Make sure you have the right to submit the contribution, including any permission required by an employer or other copyright holder.
3. Clearly identify third-party code, assets, generated material, or dependencies and their licenses.
4. Keep changes focused and include tests where the behavior can reasonably be tested.
5. Run the relevant validation and test commands above and in the README before requesting review.
6. Update user-facing documentation when behavior, boundaries, or release
   instructions change.
7. Keep Windows-only field results explicit; do not replace missing host evidence
   with synthetic claims.

## Contributor License Agreement

You retain copyright in your contribution. The CLA grants the Difftrail Project Maintainer a broad, non-exclusive license that includes sublicensing and relicensing rights. This is intended to let the public project remain GPL-licensed while preserving the option to offer commercial or other alternative licenses later.

External pull requests containing copyrightable contributions must include the checked visible CLA acknowledgement from the pull request template. The automated check recognizes only that exact visible template acknowledgement.

Repository-owner-authored pull requests containing only work owned by the Project Maintainer must include the checked ownership declaration from the pull request template. If an owner-authored pull request includes third-party copyrightable material, the owner must use the CLA acknowledgement or identify the material and record the necessary permission before merging.

If you are contributing on behalf of a company or other legal entity, only agree to the CLA if you are authorized to bind that entity or otherwise have permission to grant the required rights.

## Contributions that usually do not require a CLA grant

Pure bug reports, feature requests, issue discussion, and other material that does not contain a copyrightable contribution can generally be submitted without a CLA acknowledgement. If an issue or comment includes a substantial patch, implementation, documentation text, design asset, or other material intended for inclusion in Difftrail, the maintainer may ask for CLA acknowledgement before using it.

## Licensing of accepted contributions

Accepted contributions included in the public Difftrail repository are distributed as part of Difftrail under `GPL-3.0-only`, unless a file clearly states otherwise. The CLA is an additional inbound grant to the Project Maintainer; it does not remove the GPL rights received by users of public releases.

## Security and privacy

Difftrail handles diagnostic information from Windows systems. Contributions should preserve its local-first and read-only safety boundaries unless a change is explicitly designed, reviewed, and documented otherwise. Do not include real user event logs, private paths, credentials, tokens, personal data, or other sensitive host data in tests, fixtures, issues, or pull requests.

New or changed inputs need bounded validation at the boundary. Process spawning
must use argument arrays or otherwise demonstrate safe quoting. UI responses and
diagnostic bundles must expose only the minimum normalized data needed. A
provider failure must remain visible as partial coverage instead of becoming a
false clean result.

## Pull-request expectations

- Explain the problem, root cause, user/developer impact, and why the chosen
  change is within scope.
- Keep the diff coherent. Separate privacy migrations or security-sensitive
  behavior when independent review is safer.
- Add regression coverage for behavioral fixes and explicit ground truth for
  deterministic ranking changes.
- List the exact checks run. Distinguish local checks from GitHub Actions and
  from unavailable Windows field validation.
- Address legitimate review findings and leave no known regression at merge.

## Review

Maintainers may request changes for correctness, privacy, security, performance, maintainability, scope, or product-direction reasons. Acceptance of a CLA does not guarantee that a contribution will be merged.
