from __future__ import annotations

"""Dependency-neutral serializers for data that may cross the UI boundary."""

from typing import Any

from .privacy import extract_safe_application_name


SAFE_CHANGE_FIELDS = frozenset(
    {"display_name", "state", "start_mode", "version", "driver_date", "manufacturer", "class", "status"}
)
SAFE_EVENT_FIELDS = frozenset({"event_id", "log_name", "provider", "record_id", "application_name"})


def safe_detail_value(value: Any) -> str | int | float | bool | None:
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return None


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
            selected = {
                key: safe_value
                for key, value in values.items()
                if key in SAFE_CHANGE_FIELDS
                and (safe_value := safe_detail_value(value)) is not None
            }
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
