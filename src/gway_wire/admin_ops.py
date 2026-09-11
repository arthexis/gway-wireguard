"""Shared administrative operations used by GWAY and legacy server entrypoints."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .config import server_environment
from .dns import DNSConfigurationError, DNSManager, DNSProviderError, DNSSettings
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
        values = server_environment()
        return cls(
            db_path=Path(
                values.get(
                    "GWAY_REGISTRY_DB",
                    "/var/lib/gway-wireguard/registry.sqlite3",
                )
            ),
            wg_config=Path(
                values.get(
                    "GWAY_WG_CONFIG",
                    "/etc/wireguard/gway.conf",
                )
            ),
            wg_interface=values.get("GWAY_WG_INTERFACE", "gway"),
            wg_bin=values.get("GWAY_WG_BIN", "wg"),
            wg_network=values.get("GWAY_WG_NETWORK", "10.90.0.0/24"),
            gateway_address=values.get("GWAY_GATEWAY_ADDRESS", "10.90.0.1"),
            hosts_path=Path(values.get("GWAY_HOSTS_FILE", "/etc/hosts")),
            apply_runtime=values.get("GWAY_APPLY_RUNTIME", "1") != "0",
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


def dns_status() -> dict[str, object]:
    """Return non-secret Phase 4 DNS configuration state."""
    settings = DNSSettings.from_env()
    result: dict[str, object] = {
        "enabled": settings.enabled,
        "provider": settings.provider,
        "base_domain": settings.base_domain,
        "public_gateway_ip": settings.public_gateway_ip,
        "ttl": settings.ttl,
        "vpn_hostname": settings.vpn_hostname,
        "register_hostname": settings.register_hostname,
        "credentials_configured": bool(settings.godaddy_key and settings.godaddy_secret)
        if settings.provider == "godaddy"
        else None,
    }
    try:
        settings.validate()
    except DNSConfigurationError as exc:
        result["valid"] = False
        result["error"] = str(exc)
    else:
        result["valid"] = True
    return result


def sync_dns(
    *,
    settings: AdminSettings | None = None,
    dns: DNSManager | None = None,
) -> dict[str, object]:
    """Reconcile operational and registry-owned public DNS records."""
    active = settings or AdminSettings.from_env()
    manager = dns or DNSManager(DNSSettings.from_env())
    return manager.sync_devices(_registry(active).list_devices())


def ensure_device_dns(
    device: str,
    *,
    settings: AdminSettings | None = None,
    dns: DNSManager | None = None,
) -> dict[str, object]:
    """Ensure one enabled device hostname points to the public gateway."""
    device_id = validate_device_id(device)
    active = settings or AdminSettings.from_env()
    record = _registry(active).get_device(device_id)
    if record is None:
        raise RegistryError(f"unknown device: {device_id}")
    if not record["enabled"]:
        raise RegistryError(f"device is revoked: {device_id}")
    manager = dns or DNSManager(DNSSettings.from_env())
    hostname = str(record["hostname"])
    manager.settings.validate_device_hostname(hostname)
    mutation = manager.ensure_record(
        hostname,
        "A",
        manager.settings.public_gateway_ip,
    )
    return {
        "device": device_id,
        "hostname": hostname,
        "changed": mutation.changed,
        "provider": manager.settings.provider,
    }


def delete_device_dns(
    device: str,
    *,
    settings: AdminSettings | None = None,
    dns: DNSManager | None = None,
) -> dict[str, object]:
    """Delete the explicit public DNS record owned by one registry device."""
    device_id = validate_device_id(device)
    active = settings or AdminSettings.from_env()
    record = _registry(active).get_device(device_id)
    if record is None:
        raise RegistryError(f"unknown device: {device_id}")
    manager = dns or DNSManager(DNSSettings.from_env())
    hostname = str(record["hostname"])
    manager.settings.validate_device_hostname(hostname)
    mutation = manager.delete_record(hostname)
    return {
        "device": device_id,
        "hostname": hostname,
        "changed": mutation.changed,
        "provider": manager.settings.provider,
    }


def _cleanup_dns_after_revoke(
    record: dict[str, object],
    *,
    dns: DNSManager | None,
) -> tuple[bool | None, str | None]:
    """Best-effort DNS cleanup; never restore revoked network access on failure."""
    try:
        manager = dns
        if manager is None:
            dns_settings = DNSSettings.from_env()
            if not dns_settings.enabled:
                return None, None
            manager = DNSManager(dns_settings)
        hostname = str(record["hostname"])
        manager.settings.validate_device_hostname(hostname)
        mutation = manager.delete_record(hostname)
        return mutation.changed, None
    except (DNSConfigurationError, DNSProviderError, OSError, ValueError) as exc:
        return None, str(exc)


def revoke_device(
    device: str,
    *,
    settings: AdminSettings | None = None,
    dns: DNSManager | None = None,
) -> dict[str, object]:
    """Revoke one device and remove WireGuard, private-host, and public-DNS access."""
    device_id = validate_device_id(device)
    active = settings or AdminSettings.from_env()
    registry = _registry(active)
    record = registry.get_device(device_id)
    if record is None:
        raise RegistryError(f"unknown device: {device_id}")

    already_revoked = not bool(record["enabled"])
    if not already_revoked:
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
        record = registry.get_device(device_id) or record

    hosts_warning: str | None = None
    try:
        HostsManager(active.hosts_path).sync(registry.list_devices())
    except HostsManagerError as exc:
        hosts_warning = str(exc)

    dns_changed, dns_warning = _cleanup_dns_after_revoke(record, dns=dns)

    result: dict[str, object] = {
        "device": device_id,
        "revoked": True,
        "already_revoked": already_revoked,
    }
    if hosts_warning is not None:
        result["hosts_warning"] = hosts_warning
    if dns_changed is not None:
        result["dns_changed"] = dns_changed
    if dns_warning is not None:
        result["dns_warning"] = dns_warning
    return result
