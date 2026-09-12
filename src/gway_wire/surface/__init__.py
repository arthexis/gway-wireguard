"""Canonical GWAY command surface for gway-wire."""

from __future__ import annotations

from pathlib import Path

from gway_wire.gway import topology
from gway_wire.gway.protocols import DEFAULT_PROTOCOL, require_protocol

from . import server


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
    *name: str,
    fqdn: str | None = None,
    domain: str | None = None,
    source: bool = False,
    config: bool = False,
    wireguard: bool = False,
    listener: bool = False,
    enrollment: bool = False,
    web: bool = False,
    dns_provider: bool = False,
    provider: bool = False,
    tls: bool = False,
    public: bool = False,
    peers: bool = False,
    require_dns: bool = True,
    dns: bool | None = None,
    public_address: str | None = None,
    timeout: float = 5.0,
    protocol: str = DEFAULT_PROTOCOL,
) -> dict[str, object]:
    """Run server readiness checks without requiring the explicit server prefix."""
    require_protocol(protocol)
    return server.check(
        *name,
        fqdn=fqdn,
        domain=domain,
        source=source,
        config=config,
        wireguard=wireguard,
        listener=listener,
        enrollment=enrollment,
        web=web,
        dns_provider=dns_provider,
        provider=provider,
        tls=tls,
        public=public,
        peers=peers,
        require_dns=require_dns,
        dns=dns,
        public_address=public_address,
        timeout=timeout,
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
