"""Server-side private-hostname commands exposed through GWAY."""

from __future__ import annotations

from gway_wire.admin_ops import sync_hosts
from gway_wire.gway.protocols import DEFAULT_PROTOCOL, require_protocol


def sync(protocol: str = DEFAULT_PROTOCOL) -> dict[str, object]:
    """Synchronize private short hostnames from the enrolled-device registry."""
    require_protocol(protocol)
    return sync_hosts()
