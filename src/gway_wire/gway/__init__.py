"""Public GWAY command namespace for gway-wire.

Role-specific operations live under ``client`` and ``server``. Top-level
``status`` and ``sync`` operate across all configured relationships.
"""

from __future__ import annotations

from pathlib import Path

from . import topology
from .protocols import DEFAULT_PROTOCOL, require_protocol


def status(
    server: bool = False,
    client: bool = False,
    debug: bool = False,
    root: Path = topology._STATE_ROOT,
    protocol: str = DEFAULT_PROTOCOL,
) -> dict[str, dict[str, dict[str, object]]]:
    """Return topology-wide configured status, optionally filtered by role."""
    require_protocol(protocol)
    return topology.status(
        server=server,
        client=client,
        debug=debug,
        root=root,
        protocol=protocol,
    )


def sync(
    domain: str | None = None,
    root: Path = topology._STATE_ROOT,
    protocol: str = DEFAULT_PROTOCOL,
) -> dict[str, dict[str, dict[str, object]]]:
    """Reconcile all configured relationships, optionally for one domain."""
    require_protocol(protocol)
    return topology.sync(domain=domain, root=root, protocol=protocol)


__all__ = ["status", "sync"]
