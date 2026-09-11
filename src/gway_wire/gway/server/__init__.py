"""Server-side GWAY commands for the gway-wire gateway."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

from gway_wire.admin_ops import (
    create_enrollment_token,
    dns_status,
    list_devices,
    revoke_device,
)
from gway_wire.config import read_environment_file
from gway_wire.peer_manager import PeerManager

_DEFAULT_ENV_FILE = Path("/etc/gway-wireguard/server.env")
_SUPPORTED_DNS_PROVIDERS = {"none", "disabled", "godaddy"}


def _server_installer() -> Path:
    """Locate the checkout's server installer without depending on caller cwd."""
    for parent in Path(__file__).resolve().parents:
        candidate = parent / "server" / "install.sh"
        if candidate.is_file() and (parent / "gway.toml").is_file():
            return candidate
    raise RuntimeError("could not locate gway-wire server installer")


def _run_installer(*arguments: str) -> dict[str, object]:
    """Run the server installer with the supplied mode arguments."""
    installer = _server_installer()
    result = subprocess.run(
        ["bash", str(installer), *arguments],
        check=False,
        capture_output=True,
        text=True,
    )
    return {
        "success": result.returncode == 0,
        "exit_code": result.returncode,
        "output": result.stdout.strip(),
        "error": result.stderr.strip(),
    }


def _readiness(
    domain: str | None = None,
    require_dns: bool = True,
    env_file: Path = _DEFAULT_ENV_FILE,
) -> dict[str, object]:
    """Validate deployed configuration readiness without mutating server state."""
    issues: list[str] = []
    if not env_file.is_file():
        return {"ready": False, "issues": [f"missing deployed environment: {env_file}"]}

    try:
        values = read_environment_file(env_file)
    except ValueError as exc:
        return {"ready": False, "issues": [f"invalid deployed environment: {exc}"]}
    except OSError as exc:
        return {"ready": False, "issues": [f"cannot read deployed environment: {exc}"]}

    configured_domain = values.get("GWAY_BASE_DOMAIN", "").strip().lower()
    provider = values.get("GWAY_DNS_PROVIDER", "none").strip().lower() or "none"
    registry = Path(
        values.get("GWAY_REGISTRY_DB", "/var/lib/gway-wireguard/registry.sqlite3")
    )
    vpn_hostname = values.get("GWAY_VPN_HOSTNAME", "").strip().lower()
    register_hostname = values.get("GWAY_REGISTER_HOSTNAME", "").strip().lower()

    if not configured_domain:
        issues.append("GWAY_BASE_DOMAIN is not configured")
    if domain is not None and configured_domain != domain.strip().lower():
        issues.append(
            "base domain mismatch: "
            f"configured={configured_domain or '<unset>'} expected={domain}"
        )
    if not registry.is_file():
        issues.append(f"registry does not exist: {registry}")
    if provider not in _SUPPORTED_DNS_PROVIDERS:
        issues.append(f"unsupported DNS provider: {provider}")
    elif require_dns and provider in {"none", "disabled"}:
        issues.append("DNS provider is disabled")
    if configured_domain:
        if vpn_hostname != f"vpn.{configured_domain}":
            issues.append(
                "VPN hostname mismatch: "
                f"configured={vpn_hostname or '<unset>'} expected=vpn.{configured_domain}"
            )
        if register_hostname != f"register.{configured_domain}":
            issues.append(
                "register hostname mismatch: "
                f"configured={register_hostname or '<unset>'} expected=register.{configured_domain}"
            )

    if provider == "godaddy":
        credentials = (
            ("GWAY_GODADDY_KEY", "GWAY_GODADDY_KEY_FILE", "godaddy.key"),
            ("GWAY_GODADDY_SECRET", "GWAY_GODADDY_SECRET_FILE", "godaddy.secret"),
        )
        for direct_name, file_name, default_name in credentials:
            if values.get(direct_name, "").strip():
                continue
            configured_path = values.get(file_name, "").strip()
            credential = (
                Path(configured_path)
                if configured_path
                else env_file.parent / default_name
            )
            try:
                if not credential.is_file() or credential.stat().st_size == 0:
                    issues.append(f"credential file missing or empty: {credential}")
            except OSError as exc:
                issues.append(f"cannot inspect credential file {credential}: {exc}")

    return {
        "ready": not issues,
        "domain": configured_domain or None,
        "dns_provider": provider,
        "registry": str(registry),
        "issues": issues,
    }


def _snapshot(
    env_file: Path = _DEFAULT_ENV_FILE,
    debug: bool = False,
) -> dict[str, object]:
    """Read configured server state without performing validation or mutation."""
    values = read_environment_file(env_file)
    if not values:
        return {"configured": False, "env_file": str(env_file)}

    registry = Path(
        values.get("GWAY_REGISTRY_DB", "/var/lib/gway-wireguard/registry.sqlite3")
    )
    wg_config = Path(values.get("GWAY_WG_CONFIG", "/etc/wireguard/gway.conf"))
    result: dict[str, object] = {
        "configured": True,
        "domain": values.get("GWAY_BASE_DOMAIN") or None,
        "interface": values.get("GWAY_WG_INTERFACE", "gway"),
        "network": values.get("GWAY_WG_NETWORK") or None,
        "gateway_address": values.get("GWAY_GATEWAY_ADDRESS") or None,
        "endpoint": values.get("GWAY_GATEWAY_ENDPOINT") or None,
        "enrollment_bind": values.get("GWAY_ENROLL_BIND") or None,
        "enrollment_port": values.get("GWAY_ENROLL_PORT") or None,
        "dns_provider": values.get("GWAY_DNS_PROVIDER", "none"),
        "vpn_hostname": values.get("GWAY_VPN_HOSTNAME") or None,
        "register_hostname": values.get("GWAY_REGISTER_HOSTNAME") or None,
        "registry": str(registry),
        "registry_exists": registry.is_file(),
        "wireguard_config": str(wg_config),
        "wireguard_config_exists": wg_config.is_file(),
        "env_file": str(env_file),
    }
    if debug and wg_config.is_file():
        result["managed_peers"] = PeerManager(
            wg_config,
            apply_runtime=False,
        ).managed_peers()
    return result


def _dns_status_for(env_file: Path) -> dict[str, object]:
    """Read DNS status using the selected deployment environment file."""
    previous = os.environ.get("GWAY_SERVER_ENV_FILE")
    os.environ["GWAY_SERVER_ENV_FILE"] = str(env_file)
    try:
        return dns_status()
    finally:
        if previous is None:
            os.environ.pop("GWAY_SERVER_ENV_FILE", None)
        else:
            os.environ["GWAY_SERVER_ENV_FILE"] = previous


def deploy(
    domain: str | None = None,
    require_dns: bool = True,
    env_file: Path = _DEFAULT_ENV_FILE,
) -> dict[str, object]:
    """Deploy the current checkout, then optionally validate a production domain."""
    result = _run_installer()
    if not result["success"] or domain is None:
        return result
    readiness = _readiness(domain=domain, require_dns=require_dns, env_file=env_file)
    return {**result, **readiness, "success": bool(readiness["ready"])}


def status(
    env_file: Path = _DEFAULT_ENV_FILE,
    debug: bool = False,
) -> dict[str, object]:
    """Return the configured server snapshot; optionally include debug detail."""
    return _snapshot(env_file=env_file, debug=debug)


def check(
    source: bool = False,
    config: bool = False,
    dns: bool = False,
    peers: bool = False,
    env_file: Path = _DEFAULT_ENV_FILE,
) -> dict[str, object]:
    """Run selected server checks, or all checks when none are selected."""
    selected = {"source": source, "config": config, "dns": dns, "peers": peers}
    if not any(selected.values()):
        selected = {name: True for name in selected}

    results: dict[str, object] = {}
    if selected["source"]:
        results["source"] = _run_installer("--check")
    if selected["config"]:
        results["config"] = _readiness(require_dns=False, env_file=env_file)
    if selected["dns"]:
        results["dns"] = _dns_status_for(env_file)
    if selected["peers"]:
        snapshot = _snapshot(env_file=env_file)
        config_path = Path(
            str(snapshot.get("wireguard_config", "/etc/wireguard/gway.conf"))
        )
        managed = (
            PeerManager(config_path, apply_runtime=False).managed_peers()
            if config_path.is_file()
            else []
        )
        results["peers"] = {
            "config": str(config_path),
            "managed": managed,
            "count": len(managed),
        }
    return results


def token(device: str | None = None, ttl: int = 3600) -> dict[str, object]:
    """Create a one-time token on the server; then run `gway wire client enroll` on the client.

    The token is intended to cross the server/client boundary. Do not run the
    client enrollment command on this same device with a token created here.
    """
    return create_enrollment_token(device=device, ttl=ttl)


def devices() -> list[dict[str, object]]:
    """List enrolled devices from the server registry."""
    return list_devices()


def revoke(device: str) -> dict[str, object]:
    """Revoke one enrolled device and remove its managed WireGuard access."""
    return revoke_device(device)
