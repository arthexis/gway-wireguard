"""GWAY lifecycle commands for the gway-wire gateway service."""

from __future__ import annotations

import subprocess
from pathlib import Path

from gway_wire.config import read_environment_file

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
    domain: str,
    require_dns: bool = True,
    env_file: Path = _DEFAULT_ENV_FILE,
) -> dict[str, object]:
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
    registry = Path(values.get("GWAY_REGISTRY_DB", "/var/lib/gway-wireguard/registry.sqlite3"))
    vpn_hostname = values.get("GWAY_VPN_HOSTNAME", "").strip().lower()
    register_hostname = values.get("GWAY_REGISTER_HOSTNAME", "").strip().lower()

    if not configured_domain:
        issues.append("GWAY_BASE_DOMAIN is not configured")
    if configured_domain != domain.strip().lower():
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
            credential = Path(configured_path) if configured_path else env_file.parent / default_name
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


def deploy(
    domain: str | None = None,
    require_dns: bool = True,
    env_file: Path = _DEFAULT_ENV_FILE,
) -> dict[str, object]:
    """Deploy the current checkout and optionally validate its production domain."""
    result = _run_installer()
    if not result["success"] or domain is None:
        return result
    readiness = _readiness(domain=domain, require_dns=require_dns, env_file=env_file)
    return {**result, **readiness, "success": bool(readiness["ready"])}


def status() -> dict[str, object]:
    """Show deployed gateway, registry, enrollment, and DNS status."""
    return _run_installer("--status")


def check() -> dict[str, object]:
    """Validate server source and configuration defaults without changing the host."""
    return _run_installer("--check")
