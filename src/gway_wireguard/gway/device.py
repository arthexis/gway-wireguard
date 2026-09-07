"""Device-registry commands exposed through GWAY."""

from __future__ import annotations

import builtins

from gway_wireguard.admin_ops import list_devices, revoke_device


def list() -> builtins.list[dict[str, object]]:
    """List enrolled devices from the server registry."""
    return list_devices()


def revoke(device: str) -> dict[str, object]:
    """Revoke one enrolled device and remove its managed WireGuard access."""
    return revoke_device(device)
