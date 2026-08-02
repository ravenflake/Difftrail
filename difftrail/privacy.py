from __future__ import annotations

import re
from typing import Any


# Keep normalized evidence useful while preventing common personal paths from
# leaking into logs, exports, or the UI. The local database still contains only
# the normalized/redacted representation; no document contents are collected.
_USER_PATH = re.compile(r"(?i)([a-z]:\\Users\\)[^\\\s\"']+(?:\\[^\\\s\"']+)*")
_PROFILE_PATH = re.compile(r"(?i)([a-z]:\\Documents and Settings\\)[^\\\s\"']+(?:\\[^\\\s\"']+)*")
_UNC_USER_PATH = re.compile(r"(?i)(\\\\[^\\\s\\]+\\Users\\)[^\\\s\"']+(?:\\[^\\\s\"']+)*")
_LONG_WHITESPACE = re.compile(r"[ \t]{2,}")


def redact_text(value: str) -> str:
    """Redact common user-profile paths without hiding diagnostic labels."""

    value = _USER_PATH.sub(r"\1<user>", value)
    value = _PROFILE_PATH.sub(r"\1<user>", value)
    value = _UNC_USER_PATH.sub(r"\\\\<machine>\\Users\\<user>", value)
    return _LONG_WHITESPACE.sub(" ", value).strip()


def redact_value(value: Any) -> Any:
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, dict):
        return {str(key): redact_value(item) for key, item in value.items()}
    if isinstance(value, list):
        return [redact_value(item) for item in value]
    if isinstance(value, tuple):
        return [redact_value(item) for item in value]
    return value
