# Roadmap

Difftrail is an early Windows-first MVP. The roadmap prioritizes evidence and
reliability over collector count or speculative features.

## Now: v0.1.4 field validation

- Validate clean install, v0.1.3 upgrade, launch, watcher enable/disable, and
  uninstall on a real Windows user profile.
- Confirm legacy journal privacy migration preserves useful context.
- Observe the watcher for at least 48 hours, including reboot and sleep/wake.
- Review naturally occurring incidents, including one with incomplete provider
  coverage, without treating correlation as proof.
- Inspect a real redacted bundle before sharing it.

The complete evidence gate is in
[`docs/v0.1.4-field-validation.md`](docs/v0.1.4-field-validation.md). Items remain
pending until the recorded Windows checks actually happen.

## Next: reliability and diagnostic evidence

- Fix false changes, missed transitions, retention problems, and installer or
  watcher failures found during field use.
- Measure ranking usefulness from explicitly labeled real incidents rather than
  synthetic-suite percentages alone.
- Improve accessibility and the installed first-run path where real user
  observation identifies friction.
- Expand collector history only where a documented incident shows a concrete
  evidence gap and the provider can remain read-only and privacy-conscious.

## Later: broader contributor and ecosystem value

- Publish repeatable, privacy-safe field-validation summaries once there is
  enough real evidence to interpret them honestly.
- Stabilize extension seams for new collectors and diagnostic targets after the
  existing interfaces have survived real contributions.
- Revisit platform breadth only after the Windows product is reliable enough to
  justify it.

## Non-goals

- Requiring AI, an online account, or cloud upload for evidence review.
- Automatic remediation, rollback, uninstall, disable, or repair actions.
- Presenting timestamp correlation as proof of causality.
- Maximizing event volume at the expense of a quiet, understandable journal.
- Claiming broad platform support before it is implemented and validated.

