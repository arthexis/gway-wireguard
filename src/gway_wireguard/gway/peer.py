"""Read-only peer inspection commands for GWAY."""

from __future__ import annotations

from pathlib import Path

from gway_wireguard.peer_manager import PeerManager


def managed(
    config_path: Path = Path("/etc/wireguard/gway.conf"),
) -> list[dict[str, str]]:
    """List peers managed by gway-wireguard in the persistent config."""
    return PeerManager(config_path, apply_runtime=False).managed_peers()
