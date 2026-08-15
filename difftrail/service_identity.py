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


def service_base_name(
    name: str,
    *,
    path: str = "",
    service_type: str = "",
    trusted: bool = False,
) -> str:
    """Return a base name only when the service has per-user evidence.

    A hexadecimal-looking suffix is not sufficient evidence by itself because
    unrelated services can use the same naming shape.
    """

    parts = split_per_user_service_name(name)
    if parts is None:
        return str(name)
    if not trusted and per_user_service_identity(name, path=path, service_type=service_type) is None:
        return str(name)
    return parts[0]
