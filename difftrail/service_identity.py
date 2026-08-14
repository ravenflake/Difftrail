from __future__ import annotations

"""Helpers for recognizing Windows per-user service instances."""

import re
from typing import Any


_PER_USER_SERVICE_NAME = re.compile(r"^(?P<base>.+)_(?P<suffix>[0-9a-f]{4,})$", re.IGNORECASE)


def split_per_user_service_name(name: str) -> tuple[str, str] | None:
    """Return the base name and LUID suffix for a per-user-shaped service name."""

    match = _PER_USER_SERVICE_NAME.fullmatch(str(name).strip())
    if not match:
        return None
    return match.group("base"), match.group("suffix")


def per_user_service_identity(
    name: str,
    *,
    path: str = "",
    service_type: str = "",
) -> tuple[str, str] | None:
    """Recognize a suffixed service when it is hosted as a Windows user service.

    The suffix alone is not enough because third-party services can contain a
    hexadecimal-looking token in their names. The Windows per-user service
    collector also reports these instances as shared ``svchost.exe`` services.
    """

    parts = split_per_user_service_name(name)
    if parts is None:
        return None
    host_path = str(path).casefold()
    kind = str(service_type).casefold()
    if "svchost.exe" not in host_path and "share process" not in kind:
        return None
    return parts


def is_per_user_service_payload(payload: Any) -> bool:
    """Return whether a stored service payload represents a user service."""

    if not isinstance(payload, dict):
        return False
    if payload.get("per_user_service") is True:
        return True
    return per_user_service_identity(
        str(payload.get("name", "")),
        path=str(payload.get("path", "")),
        service_type=str(payload.get("service_type", "")),
    ) is not None


def service_base_name(name: str) -> str:
    """Return the stable logical service name for state matching."""

    parts = split_per_user_service_name(name)
    return parts[0] if parts else str(name)
