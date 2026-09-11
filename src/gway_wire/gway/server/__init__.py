"""Server-side GWAY commands for the gway-wire gateway."""

from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path

from gway_wire.admin_ops import (
    create_enrollment_token,
    dns_status,
    list_devices,
    revoke_device,
)
from gway_wire.config import read_environment_file
from gway_wire.gway.protocols import DEFAULT_PROTOCOL, require_protocol
from gway_wire.peer_manager import PeerManager

_DEFAULT_ENV_FILE = Path("/etc/gway-wireguard/server.env")
_SUPPORTED_DNS_PROVIDERS = {"none", "disabled", "godaddy"}
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$"
)


def _server_installer() -> Path:
    """Locate the checkout's server installer without depending on caller cwd."""
    for parent in Path(__file__).resolve().parents:
        candidate = parent / "server" / "install.sh"
        if candidate.is_file() and (parent / "gway.toml").is_file():
            return candidate
    raise RuntimeError("could not locate gway-wire server installer")


def _run_installer(
    *arguments: str,
    env: dict[str, str] | None = None,
) -> dict[str, object]:
    """Run the server installer with the supplied mode arguments."""
    installer = _server_installer()
    result = subprocess.run(
        ["bash", str(installer), *arguments],
        check=False,
        capture_output=True,
        text=True,
        env=env,
    )
    return {
        "success": result.returncode == 0,
        "exit_code": result.returncode,
        "output": result.stdout.strip(),
        "error": result.stderr.strip(),
    }


def _normalize_domain(domain: str) -> str:
    """Normalize and validate a deployment domain."""
    value = domain.strip().lower().rstrip(".")
    if not _DOMAIN_RE.fullmatch(value):
        raise ValueError(f"invalid domain: {domain!r}")
    return value


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
    try:
        values = read_environment_file(env_file)
    except OSError:
        return {"configured": False, "env_file": str(env_file)}
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


def _domain_preflight(
    domain: str,
    env_file: Path,
    require_dns: bool,
) -> dict[str, object]:
    """Inspect whether a domain is configured or can be deployed without mutation."""
    target = _normalize_domain(domain)
    if env_file.is_file():
        snapshot = _snapshot(env_file=env_file)
        configured_domain = str(snapshot.get("domain") or "").strip().lower()
        if configured_domain == target:
            readiness = _readiness(
                domain=target,
                require_dns=require_dns,
                env_file=env_file,
            )
            return {
                "domain": target,
                "configured": True,
                "already_configured": True,
                "deployable": bool(readiness["ready"]),
                **readiness,
            }
        return {
            "domain": target,
            "configured": False,
            "already_configured": False,
            "deployable": False,
            "ready": False,
            "configured_domain": configured_domain or None,
            "issues": [
                f"server is already configured for {configured_domain or '<unknown>'}"
            ],
        }

    source = _run_installer("--check")
    return {
        "domain": target,
        "configured": False,
        "already_configured": False,
        "deployable": bool(source["success"]),
        "ready": False,
        "preflight": {"source": source},
        "issues": [] if source["success"] else ["server source/configuration preflight failed"],
    }


def deploy(
    domain: str,
    require_dns: bool = True,
    env_file: Path = _DEFAULT_ENV_FILE,
    protocol: str = DEFAULT_PROTOCOL,
) -> dict[str, object]:
    """Mutate this server into a deployment for DOMAIN, then validate readiness."""
    require_protocol(protocol)
    target = _normalize_domain(domain)
    environment = os.environ.copy()
    environment["BASE_DOMAIN"] = target
    environment["VPN_HOSTNAME"] = f"vpn.{target}"
    environment["REGISTER_HOSTNAME"] = f"register.{target}"
    result = _run_installer(env=environment)
    if not result["success"]:
        return {**result, "domain": target}
    readiness = _readiness(domain=target, require_dns=require_dns, env_file=env_file)
    return {**result, **readiness, "success": bool(readiness["ready"])}


def status(
    env_file: Path = _DEFAULT_ENV_FILE,
    debug: bool = False,
    protocol: str = DEFAULT_PROTOCOL,
) -> dict[str, object]:
    """Return the configured server snapshot; optionally include debug detail."""
    require_protocol(protocol)
    return _snapshot(env_file=env_file, debug=debug)


def check(
    domain: str,
    source: bool = False,
    config: bool = False,
    dns: bool = False,
    peers: bool = False,
    require_dns: bool = True,
    env_file: Path = _DEFAULT_ENV_FILE,
    protocol: str = DEFAULT_PROTOCOL,
) -> dict[str, object]:
    """Validate DOMAIN non-mutatively, with selectable active checks."""
    require_protocol(protocol)
    target = _normalize_domain(domain)
    selected = {"source": source, "config": config, "dns": dns, "peers": peers}
    if not any(selected.values()):
        return _domain_preflight(target, env_file, require_dns)

    results: dict[str, object] = {"domain": target}
    if selected["source"]:
        results["source"] = _run_installer("--check")
    if selected["config"]:
        results["config"] = _domain_preflight(target, env_file, require_dns=False)
    if selected["dns"]:
        if env_file.is_file():
            results["dns"] = _dns_status_for(env_file)
        else:
            results["dns"] = {"available": False, "configured": False}
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


def validate(
    domain: str,
    source: bool = False,
    config: bool = False,
    dns: bool = False,
    peers: bool = False,
    require_dns: bool = True,
    env_file: Path = _DEFAULT_ENV_FILE,
    protocol: str = DEFAULT_PROTOCOL,
) -> dict[str, object]:
    """Alias for check."""
    return check(
        domain,
        source=source,
        config=config,
        dns=dns,
        peers=peers,
        require_dns=require_dns,
        env_file=env_file,
        protocol=protocol,
    )


def token(
    device: str | None = None,
    ttl: int = 3600,
    protocol: str = DEFAULT_PROTOCOL,
) -> dict[str, object]:
    """Create a one-time token on the server; then run `gway wire client enroll` on the client.

    The token is intended to cross the server/client boundary. Do not run the
    client enrollment command on this same device with a token created here.
    """
    require_protocol(protocol)
    return create_enrollment_token(device=device, ttl=ttl)


def devices(protocol: str = DEFAULT_PROTOCOL) -> list[dict[str, object]]:
    """List enrolled devices from the server registry."""
    require_protocol(protocol)
    return list_devices()


def revoke(device: str, protocol: str = DEFAULT_PROTOCOL) -> dict[str, object]:
    """Revoke one enrolled device and remove its managed protocol access."""
    require_protocol(protocol)
    return revoke_device(device)
