"""Private-hostname commands exposed through GWAY."""

from __future__ import annotations

from gway_wire.admin_ops import sync_hosts


def sync() -> dict[str, object]:
    """Synchronize private short hostnames from the enrolled-device registry."""
    return sync_hosts()
