"""Public GWAY command namespace for gway-wire.

Role-specific operations live under ``client`` and ``server``. Top-level
``status`` and ``sync`` operate across all configured relationships.
"""

from __future__ import annotations

from pathlib import Path

from . import topology


def status(
    server: bool = False,
    client: bool = False,
    debug: bool = False,
    root: Path = topology._STATE_ROOT,
) -> dict[str, dict[str, dict[str, object]]]:
    """Return topology-wide configured status, optionally filtered by role."""
    return topology.status(server=server, client=client, debug=debug, root=root)


def sync(
    domain: str | None = None,
    root: Path = topology._STATE_ROOT,
) -> dict[str, dict[str, dict[str, object]]]:
    """Reconcile all configured relationships, optionally for one domain."""
    return topology.sync(domain=domain, root=root)


__all__ = ["status", "sync"]
