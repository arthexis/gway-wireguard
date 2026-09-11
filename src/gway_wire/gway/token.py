"""Enrollment-token commands exposed through GWAY."""

from __future__ import annotations

from gway_wireguard.admin_ops import create_enrollment_token


def create(device: str | None = None, ttl: int = 3600) -> dict[str, object]:
    """Create a one-time enrollment token, optionally scoped to one device."""
    return create_enrollment_token(device=device, ttl=ttl)
