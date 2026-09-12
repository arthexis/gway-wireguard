"""Server-side DNS administration commands on the canonical Wire surface."""

from __future__ import annotations

from gway_wire.admin_ops import (
    delete_device_dns,
    dns_status,
    ensure_device_dns,
    sync_dns,
)
from gway_wire.gway.protocols import DEFAULT_PROTOCOL, require_protocol


def status(protocol: str = DEFAULT_PROTOCOL) -> dict[str, object]:
    """Show non-secret DNS automation configuration status."""
    require_protocol(protocol)
    return dns_status()


def sync(protocol: str = DEFAULT_PROTOCOL) -> dict[str, object]:
    """Reconcile operational and registry-owned public DNS records."""
    require_protocol(protocol)
    return sync_dns()


def ensure(device: str, protocol: str = DEFAULT_PROTOCOL) -> dict[str, object]:
    """Ensure one enabled device public hostname points to the gateway."""
    require_protocol(protocol)
    return ensure_device_dns(device)


def delete(device: str, protocol: str = DEFAULT_PROTOCOL) -> dict[str, object]:
    """Delete one registry device's explicit public DNS record."""
    require_protocol(protocol)
    return delete_device_dns(device)
