# Security policy

Difftrail reads Windows diagnostic metadata, keeps a local SQLite journal, and
exposes a loopback API to its desktop interface. Security and privacy reports
are welcome and should be handled privately.

## Supported versions

| Version | Security fixes |
| --- | --- |
| `main` | Yes; development branch, not a release |
| Latest tagged release | Yes, on a best-effort basis while Difftrail is pre-1.0 |
| Older releases | No; upgrade to the latest release before reporting |

## Report a vulnerability

Use GitHub's private
[vulnerability reporting form](https://github.com/ravenflake/Difftrail/security/advisories/new).
Do not open a public issue for a suspected vulnerability.

Include only the minimum information needed to reproduce the problem:

- affected Difftrail version and installation method;
- Windows version and whether the desktop installer or source checkout is used;
- impact and the trust boundary that is crossed;
- minimal reproduction steps or a small synthetic test case; and
- any proposed mitigation.

Do **not** attach a real Difftrail database, exported Event Log, diagnostic
bundle containing unexpected private data, username, private path, credential,
token, or process dump. Describe the sensitive field and its location instead.
If a file is essential, wait for the maintainer to agree on a private transfer
method.

The maintainer aims to acknowledge a complete report within seven days, confirm
whether it is reproducible, and coordinate a fix and disclosure timeline based
on severity. Please allow a reasonable remediation window before public
disclosure.

## Security and privacy boundaries

- Windows collectors are intended to be read-only. Difftrail does not
  automatically roll back drivers, uninstall software, disable services, or
  apply repairs.
- The journal is stored under the current user's local application data by
  default. It contains normalized system-change metadata and may retain
  redacted raw Event Log message text for the configured retention period.
- The installed Tauri desktop launches the Python API on a dynamically selected
  loopback port and authenticates requests with a random per-launch token. Host
  and Origin checks remain defense-in-depth. The standalone browser-development
  server can run without a token unless `DIFFTRAIL_API_TOKEN` and
  `VITE_DIFFTRAIL_API_TOKEN` are configured.
- Enabling the watcher creates a current-user Task Scheduler entry. Windows may
  request elevation if Task Scheduler denies the initial registration. The
  desktop uninstaller removes the task but preserves the journal.
- Diagnostic bundles are one-way, redacted JSON exports. Validation checks for
  forbidden fields and absolute paths, but a bundle still contains normalized
  software, hardware, timing, and investigation metadata. Inspect it before
  sharing.
- Release installers are built by GitHub Actions. Tagged releases publish a
  `SHA256SUMS.txt` file for artifact verification. The installer is not
  currently code-signed.

Difftrail does not claim to protect its local database or running process from
malware or an administrator already executing as the same Windows user. Reports
that show an unexpected escalation beyond those local privileges are still in
scope.

