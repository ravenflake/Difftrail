from __future__ import annotations

import re
from typing import Any


KNOWN_ERROR_BUCKETS = frozenset(
    {
        "updates",
        "apps",
        "drivers",
        "services",
        "tasks",
        "startup",
        "devices",
        "snapshots",
        "symptoms",
        "collector",
    }
)


# Keep normalized evidence useful while preventing common personal paths from
# leaking into logs, exports, or the UI. The local database still contains only
# the normalized/redacted representation; no document contents are collected.
_PATH_CHARACTER = r"[^\\/:*?\"<>|\r\n]"
_EXECUTABLE_EXTENSION = r"(?:exe|dll|sys|com|bat|cmd|ps1|vbs|js|msi|msix|appx)"
_EXECUTABLE_PATH_SUFFIX = (
    rf"(?:{_PATH_CHARACTER}+\\)*"
    rf"{_PATH_CHARACTER}*\.{_EXECUTABLE_EXTENSION}"
    r"(?=$|[\s,;:)\]}.\"'!?])"
)
_USER_EXECUTABLE_PATH = re.compile(rf"(?i)([a-z]:\\Users\\){_EXECUTABLE_PATH_SUFFIX}")
_PROFILE_EXECUTABLE_PATH = re.compile(rf"(?i)([a-z]:\\Documents and Settings\\){_EXECUTABLE_PATH_SUFFIX}")
_UNC_USER_EXECUTABLE_PATH = re.compile(rf"(?i)(\\\\[^\\\s\\]+\\Users\\){_EXECUTABLE_PATH_SUFFIX}")
_USER_PATH = re.compile(r"(?i)([a-z]:\\Users\\)[^\"'<>\r\n]+")
_PROFILE_PATH = re.compile(r"(?i)([a-z]:\\Documents and Settings\\)[^\"'<>\r\n]+")
_UNC_USER_PATH = re.compile(r"(?i)(\\\\[^\\\s\\]+\\Users\\)[^\"'<>\r\n]+")
# v0.1.3 stopped at whitespace while replacing a profile name. These patterns
# repair the remaining suffix (for example, "<user> Doe\Games\App.exe")
# before the normal current-path rules run.
_LEGACY_PARTIAL_EXECUTABLE_SUFFIX = (
    rf"(?:[ \t]{_PATH_CHARACTER}+\\){_EXECUTABLE_PATH_SUFFIX}"
)
_LEGACY_PARTIAL_PATH_BOUNDARY = r"(?=$|[\s,;:)\]}\"'!?]|\.(?![A-Za-z0-9]))"
_LEGACY_PARTIAL_PATH_TERMINATOR = r"(?=$|[,;:)\]}\"'!?]|\.(?![A-Za-z0-9]))"
_LEGACY_PARTIAL_TERMINATED_PATH_CHARACTER = r"[^\\/:*?\"<>|,;:)\]}\r\n]"
_LEGACY_PARTIAL_PATH_SUFFIX = (
    rf"(?:"
    # A file extension gives an unambiguous end when the filename has spaces.
    rf"(?:[ \t]{_PATH_CHARACTER}+\\)(?:{_PATH_CHARACTER}+\\)*?"
    rf"{_PATH_CHARACTER}*?\.[A-Za-z0-9]{{1,16}}{_LEGACY_PARTIAL_PATH_BOUNDARY}"
    rf"|"
    # A trailing separator also unambiguously ends a directory path.
    rf"(?:[ \t]{_PATH_CHARACTER}+\\)(?:{_PATH_CHARACTER}+\\)+{_LEGACY_PARTIAL_PATH_BOUNDARY}"
    rf"|"
    # Without an extension, whitespace can belong to the last path component.
    # Only repair it when a real path terminator follows, not a whitespace gap.
    rf"(?:[ \t]{_PATH_CHARACTER}+\\)(?:{_PATH_CHARACTER}+\\)*?"
    rf"{_LEGACY_PARTIAL_TERMINATED_PATH_CHARACTER}+?{_LEGACY_PARTIAL_PATH_TERMINATOR}"
    rf")"
)
_LEGACY_PARTIAL_USER_EXECUTABLE_PATH = re.compile(
    rf"(?i)([a-z]:\\Users\\)<user>{_LEGACY_PARTIAL_EXECUTABLE_SUFFIX}"
)
_LEGACY_PARTIAL_USER_PATH = re.compile(rf"(?i)([a-z]:\\Users\\)<user>{_LEGACY_PARTIAL_PATH_SUFFIX}")
_LEGACY_PARTIAL_PROFILE_EXECUTABLE_PATH = re.compile(
    rf"(?i)([a-z]:\\Documents and Settings\\)<user>{_LEGACY_PARTIAL_EXECUTABLE_SUFFIX}"
)
_LEGACY_PARTIAL_PROFILE_PATH = re.compile(
    rf"(?i)([a-z]:\\Documents and Settings\\)<user>{_LEGACY_PARTIAL_PATH_SUFFIX}"
)
_LEGACY_PARTIAL_UNC_USER_EXECUTABLE_PATH = re.compile(
    rf"(?i)(\\\\<machine>\\Users\\)<user>{_LEGACY_PARTIAL_EXECUTABLE_SUFFIX}"
)
_LEGACY_PARTIAL_UNC_USER_PATH = re.compile(
    rf"(?i)(\\\\<machine>\\Users\\)<user>{_LEGACY_PARTIAL_PATH_SUFFIX}"
)
_LONG_WHITESPACE = re.compile(r"[ \t]{2,}")
_FAULTING_APPLICATION = re.compile(r"(?im)faulting application name:\s*([^,\r\n]+)")
_HANGING_APPLICATION = re.compile(
    rf"(?im)the program\s+(.+?\.{_EXECUTABLE_EXTENSION})"
    r"(?=(?:[\s,;:)\]}.\"'!?])*(?:version\s+\S|stopped\s+interacting\b))"
)


def redact_text(value: str) -> str:
    """Redact common user-profile paths without hiding diagnostic labels."""

    value = _USER_EXECUTABLE_PATH.sub(r"\1<user>", value)
    value = _PROFILE_EXECUTABLE_PATH.sub(r"\1<user>", value)
    value = _UNC_USER_EXECUTABLE_PATH.sub(r"\\\\<machine>\\Users\\<user>", value)
    value = _USER_PATH.sub(r"\1<user>", value)
    value = _PROFILE_PATH.sub(r"\1<user>", value)
    value = _UNC_USER_PATH.sub(r"\\\\<machine>\\Users\\<user>", value)
    return _LONG_WHITESPACE.sub(" ", value).strip()


def redact_legacy_text(value: str) -> str:
    """Repair the partial profile-path redaction emitted by v0.1.3."""

    value = _LEGACY_PARTIAL_USER_EXECUTABLE_PATH.sub(r"\1<user>", value)
    value = _LEGACY_PARTIAL_PROFILE_EXECUTABLE_PATH.sub(r"\1<user>", value)
    value = _LEGACY_PARTIAL_UNC_USER_EXECUTABLE_PATH.sub(r"\\\\<machine>\\Users\\<user>", value)
    value = _LEGACY_PARTIAL_USER_PATH.sub(r"\1<user>", value)
    value = _LEGACY_PARTIAL_PROFILE_PATH.sub(r"\1<user>", value)
    value = _LEGACY_PARTIAL_UNC_USER_PATH.sub(r"\\\\<machine>\\Users\\<user>", value)
    return redact_text(value)


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


def redact_legacy_value(value: Any) -> Any:
    """Recursively repair v0.1.3 redaction before storing an upgraded journal."""

    if isinstance(value, str):
        return redact_legacy_text(value)
    if isinstance(value, dict):
        return {str(key): redact_legacy_value(item) for key, item in value.items()}
    if isinstance(value, list):
        return [redact_legacy_value(item) for item in value]
    if isinstance(value, tuple):
        return [redact_legacy_value(item) for item in value]
    return value


def error_bucket(error: object) -> str:
    """Return a stable, non-sensitive provider-error category."""

    prefix = str(error).split(":", 1)[0].strip()
    return prefix if prefix in KNOWN_ERROR_BUCKETS else "other"


def extract_safe_application_name(message: str) -> str | None:
    """Extract only an executable basename from a Windows event message."""

    if not message:
        return None
    candidate = None
    for pattern in (_FAULTING_APPLICATION, _HANGING_APPLICATION):
        match = pattern.search(message)
        if match:
            candidate = match.group(1).strip().strip("\"'")
            break
    if not candidate:
        return None
    candidate = re.split(r"[\\/]", candidate)[-1].strip().rstrip(".,;:!?)]}")
    candidate = re.sub(r"[^A-Za-z0-9._() +\-]", "", candidate)
    candidate = candidate[:128].strip()
    return candidate or None
