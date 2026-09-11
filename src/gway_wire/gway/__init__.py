"""Public GWAY command namespace for gway-wire.

Role-specific operations live under ``client`` and ``server``. Top-level
``status``, ``check``, and ``sync`` cover the common topology surface.
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


def check(
    domain: str,
    source: bool = False,
    config: bool = False,
    dns_check: bool = False,
    peers: bool = False,
    require_dns: bool = True,
    dns: bool | None = None,
    root: Path = topology._STATE_ROOT,
    protocol: str = DEFAULT_PROTOCOL,
) -> dict[str, object]:
    """Validate a server domain without requiring the explicit server prefix."""
    require_protocol(protocol)
    return topology.check(
        domain,
        source=source,
        config=config,
        dns_check=dns_check,
        peers=peers,
        require_dns=require_dns,
        dns=dns,
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


__all__ = ["status", "check", "sync"]
