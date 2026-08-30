from __future__ import annotations

"""Shared investigation assessment states.

Keeping these values in a dependency-neutral module prevents the correlation
engine and persistence layer from drifting apart when a state is added.
"""

ASSESSMENT_STATES = frozenset(
    {"candidate_found", "insufficient_evidence", "no_recent_changes", "limited_coverage"}
)

# A newly created or otherwise unassessed investigation must never imply that
# a supported lead was found. This is intentionally one of the public
# assessment states so old journals can be read without a separate sentinel.
NEUTRAL_ASSESSMENT = "insufficient_evidence"
