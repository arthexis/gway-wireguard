"""Shared administrative operations used by GWAY and legacy server entrypoints."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from .hosts_manager import HostsManager, HostsManagerError
from .peer_manager import PeerManager
from .registry import Registry, RegistryError, validate_device_id


@dataclass(frozen=True)
class AdminSettings:
    db_path: Path = Path("/var/lib/gway-wireguard/registry.sqlite3")
    wg_config: Path = Path("/etc/wireguard/gway.conf")
    wg_interface: str = "gway"
    wg_bin: str = "wg"
    wg_network: str = "10.90.0.0/24"
    gateway_address: str = "10.90.0.1"
    hosts_path: Path = Path("/etc/hosts")
    apply_runtime: bool = True

    @classmethod
    def from_env(cls) -> "AdminSettings":
        return cls(
            db_path=Path(
                os.environ.get(
                    "GWAY_REGISTRY_DB",
                    "/var/lib/gway-wireguard/registry.sqlite3",
                )
            ),
            wg_config=Path(
                os.environ.get(
                    "GWAY_WG_CONFIG",
                    "/etc/wireguard/gway.conf",
                )
            ),
            wg_interface=os.environ.get("GWAY_WG_INTERFACE", "gway"),
            wg_bin=os.environ.get("GWAY_WG_BIN", "wg"),
            wg_network=os.environ.get("GWAY_WG_NETWORK", "10.90.0.0/24"),
            gateway_address=os.environ.get("GWAY_GATEWAY_ADDRESS", "10.90.0.1"),
            hosts_path=Path(os.environ.get("GWAY_HOSTS_FILE", "/etc/hosts")),
            apply_runtime=os.environ.get("GWAY_APPLY_RUNTIME", "1") != "0",
        )


def _registry(settings: AdminSettings) -> Registry:
    return Registry(
        settings.db_path,
        network=settings.wg_network,
        gateway_address=settings.gateway_address,
    )


def _peers(settings: AdminSettings) -> PeerManager:
    return PeerManager(
        settings.wg_config,
        interface=settings.wg_interface,
        wg_bin=settings.wg_bin,
        apply_runtime=settings.apply_runtime,
    )


def create_enrollment_token(
    *,
    device: str | None = None,
    ttl: int = 3600,
    settings: AdminSettings | None = None,
) -> dict[str, object]:
    """Create one expiring enrollment token and return its one-time plaintext value."""
    active = settings or AdminSettings.from_env()
    token, expires = _registry(active).create_token(device_id=device, ttl_seconds=ttl)
    return {
        "token": token,
        "device": device,
        "expires": expires.isoformat(timespec="seconds"),
    }


def list_devices(*, settings: AdminSettings | None = None) -> list[dict[str, object]]:
    """Return all registry device rows in deterministic device order."""
    active = settings or AdminSettings.from_env()
    return _registry(active).list_devices()


def sync_hosts(*, settings: AdminSettings | None = None) -> dict[str, object]:
    """Reconcile private short hostnames from enabled registry devices."""
    active = settings or AdminSettings.from_env()
    changed = HostsManager(active.hosts_path).sync(_registry(active).list_devices())
    return {"changed": changed, "path": str(active.hosts_path)}


def revoke_device(
    device: str,
    *,
    settings: AdminSettings | None = None,
) -> dict[str, object]:
    """Revoke one device, remove its WireGuard peer, and reconcile short hostnames."""
    device_id = validate_device_id(device)
    active = settings or AdminSettings.from_env()
    registry = _registry(active)
    record = registry.get_device(device_id)
    if record is None:
        raise RegistryError(f"unknown device: {device_id}")
    if not record["enabled"]:
        return {"device": device_id, "revoked": True, "already_revoked": True}

    peers = _peers(active)
    public_key = str(record["wireguard_public_key"])
    try:
        peers.remove_peer(device_id, public_key)
        registry.revoke(device_id)
    except Exception:
        try:
            peers.ensure_peer(device_id, public_key, str(record["vpn_address"]))
        except Exception:
            pass
        raise

    warning: str | None = None
    try:
        HostsManager(active.hosts_path).sync(registry.list_devices())
    except HostsManagerError as exc:
        warning = str(exc)

    result: dict[str, object] = {
        "device": device_id,
        "revoked": True,
        "already_revoked": False,
    }
    if warning is not None:
        result["hosts_warning"] = warning
    return result
