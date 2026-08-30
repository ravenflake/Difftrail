from __future__ import annotations

"""Dependency-neutral serializers for data that may cross the UI boundary."""

import re
from typing import Any

from .privacy import extract_safe_application_name, redact_public_text


SAFE_CHANGE_FIELDS = frozenset(
    {
        "class",
        "description",
        "display_name",
        "driver_date",
        "install_date",
        "installed_on",
        "location",
        "manufacturer",
        "publisher",
        "service_type",
        "signed",
        "start_mode",
        "state",
        "status",
        "version",
    }
)
SAFE_EVENT_FIELDS = frozenset({"event_id", "log_name", "provider", "record_id", "application_name"})

PUBLIC_FEEDBACK_OUTCOMES = frozenset({"helpful", "not_helpful", "unsure"})
_STORED_TO_PUBLIC_FEEDBACK = {
    "correct": "helpful",
    "incorrect": "not_helpful",
    "unknown": "unsure",
}
_PUBLIC_TO_STORED_FEEDBACK = {value: key for key, value in _STORED_TO_PUBLIC_FEEDBACK.items()}


def public_review_text(value: Any) -> str:
    """Redact and conservatively rephrase generated text from older journals."""

    text = redact_public_text(str(value))
    text = re.sub(
        r"^This change occurred (.+) before the selected onset\.$",
        r"This change was recorded \1 before the selected onset. Timing determines rank but does not establish a connection.",
        text,
    )
    text = re.sub(
        r"^(\d+) related symptom event(s?) appeared after this change and before the investigation window ended\.$",
        lambda match: (
            f"{match.group(1)} compatible symptom record"
            f"{'' if match.group(2) == '' else 's'} appeared after this change was recorded and before the problem window ended. "
            "This sequence does not prove causality."
        ),
        text,
    )
    text = re.sub(
        r"^(\d+) related symptom event(s?) existed before this change, so it may not be the original cause\.$",
        lambda match: (
            f"{match.group(1)} compatible symptom record"
            f"{'' if match.group(2) == '' else 's'} "
            f"{'predates' if match.group(2) == '' else 'predate'} this detected change. "
            "That weakens it as an explanation for when the problem began."
        ),
        text,
    )
    exact_replacements = {
        "No related symptom event was recorded after this change in the selected window.": (
            "No compatible symptom record was captured near the reported onset. "
            "This lead is ranked from change timing and category only."
        ),
        "The strongest candidate has only weak supporting evidence.": (
            "The top-ranked change has only weak or non-specific support; review it as timeline context, not an answer."
        ),
        "The strongest candidate has material counter-evidence that limits causal support.": (
            "The top-ranked change has counter-signals that weaken it."
        ),
        "A bulk Windows per-user service refresh was excluded from causal ranking because its suffixed instances changed together.": (
            "A bulk Windows per-user service refresh was excluded from ranked leads because its suffixed instances changed together."
        ),
        "No journaled changes occurred during the selected lookback window before onset.": (
            "No journaled changes were recorded during the selected lookback window before onset."
        ),
    }
    text = exact_replacements.get(text, text)
    text = re.sub(
        r"^The strongest candidates are tied at the same score \((\d+) candidates\), so no single change is uniquely supported\.$",
        r"\1 changes are tied by the fixed ranking rules, so no single lead is uniquely supported.",
        text,
    )
    text = re.sub(
        r"^(\d+) changes have similarly strong ranking scores, so no single lead is uniquely supported\.$",
        r"\1 changes are tied by the fixed ranking rules, so no single lead is uniquely supported.",
        text,
    )
    return text


def public_next_action(event: Any) -> str:
    """Generate a read-only verification step independent of legacy stored copy."""

    raw = event if isinstance(event, dict) else {}
    source = str(raw.get("source", ""))
    subsystem = str(raw.get("subsystem", ""))
    if subsystem in {"graphics", "audio", "network", "bluetooth", "driver"} or source == "drivers":
        return "In Device Manager, compare the current device status, driver provider, version, and date with this journaled change. Do not roll back a driver based on rank alone."
    if subsystem == "windows-update" or source == "updates":
        return "In Windows Update history, confirm the install time and update identifier, then compare them with the problem onset. Do not uninstall an update based on timing alone."
    if source == "services":
        return "In Services, compare the service status, startup type, and executable path with the journaled before/after values. Do not change it based on rank alone."
    if source == "tasks":
        return "In Task Scheduler, inspect the task's author, trigger, action, and last-run result, then compare them with the journaled change."
    if source == "startup" or subsystem == "startup":
        return "In Startup apps, inspect the entry's publisher and current state, then compare them with the journaled change."
    if subsystem == "application" or source == "apps":
        return "Confirm the application's current version and update time, then reproduce the problem once while noting whether the same symptom returns."
    if subsystem == "device":
        return "In Device Manager, compare the device status and associated driver with the journaled change before taking action."
    return "Open the relevant Windows management surface and compare its current state with this journaled change before taking action."


def safe_detail_value(value: Any) -> str | int | float | bool | None:
    if isinstance(value, str):
        return redact_public_text(value)
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    return None


def public_feedback_outcome(value: Any) -> str | None:
    """Translate the legacy stored feedback vocabulary into a non-causal label."""

    if not isinstance(value, str):
        return None
    if value in PUBLIC_FEEDBACK_OUTCOMES:
        return value
    return _STORED_TO_PUBLIC_FEEDBACK.get(value)


def stored_feedback_outcome(value: Any) -> str:
    """Accept the public vocabulary while preserving the existing journal schema."""

    if not isinstance(value, str):
        raise ValueError("outcome must be helpful, not_helpful, or unsure")
    if value in _STORED_TO_PUBLIC_FEEDBACK:
        return value
    stored = _PUBLIC_TO_STORED_FEEDBACK.get(value)
    if stored is None:
        raise ValueError("outcome must be helpful, not_helpful, or unsure")
    return stored


def _public_location(value: Any) -> str | None:
    """Describe a startup scope without exposing a registry key, SID, or path."""

    if not isinstance(value, str) or not value.strip():
        return None
    normalized = value.casefold()
    if "startup" in normalized:
        return "Startup folder"
    if (
        "hkcu" in normalized
        or "hku" in normalized
        or "current user" in normalized
        or "\\users\\<user>" in normalized
        or "/users/<user>" in normalized
    ):
        return "Per-user"
    if "hklm" in normalized or "all users" in normalized or "common" in normalized:
        return "Machine-wide"
    return "Other startup location"


def public_detail_summary(event: dict[str, Any]) -> dict[str, Any] | None:
    """Expose parsed, non-sensitive event context without raw messages/paths."""

    details = event.get("details")
    if not isinstance(details, dict):
        return None
    summary: dict[str, Any] = {}
    before = details.get("before") if isinstance(details.get("before"), dict) else None
    after = details.get("after") if isinstance(details.get("after"), dict) else None
    if before is not None or after is not None:
        old = before or {}
        new = after or {}
        changed_fields = sorted(
            key for key in set(old) | set(new) if key in SAFE_CHANGE_FIELDS and old.get(key) != new.get(key)
        )
        if changed_fields:
            summary["changed_fields"] = changed_fields
        for label, values in (("before", old), ("after", new)):
            selected: dict[str, Any] = {}
            for key, value in values.items():
                if key not in SAFE_CHANGE_FIELDS:
                    continue
                safe_value = _public_location(value) if key == "location" else safe_detail_value(value)
                if safe_value is not None:
                    selected[key] = safe_value
            if selected:
                summary[label] = selected
    for key in SAFE_EVENT_FIELDS:
        value = safe_detail_value(details.get(key))
        if value is not None:
            summary[key] = value
    if "application_name" not in summary and details.get("message"):
        application_name = extract_safe_application_name(str(details["message"]))
        if application_name:
            summary["application_name"] = application_name
    if "message" in details:
        summary["raw_message_retained"] = bool(details.get("message"))
    elif details.get("raw_message_retained") is False:
        summary["raw_message_retained"] = False
    return summary or None
