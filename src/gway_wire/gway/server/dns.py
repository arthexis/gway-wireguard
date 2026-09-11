"""Server-side public DNS administration commands exposed through GWAY."""

from __future__ import annotations

from gway_wire.admin_ops import (
    delete_device_dns,
    dns_status,
    ensure_device_dns,
    sync_dns,
)


def status() -> dict[str, object]:
    """Show non-secret DNS automation configuration status."""
    return dns_status()


def sync() -> dict[str, object]:
    """Reconcile operational and registry-owned public DNS records."""
    return sync_dns()


def ensure(device: str) -> dict[str, object]:
    """Ensure one enabled device public hostname points to the gateway."""
    return ensure_device_dns(device)


def delete(device: str) -> dict[str, object]:
    """Delete one registry device's explicit public DNS record."""
    return delete_device_dns(device)
