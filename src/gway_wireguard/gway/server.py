"""GWAY lifecycle commands for the gway-wireguard gateway service."""

from __future__ import annotations

import subprocess
from pathlib import Path

_DEFAULT_ENV_FILE = Path("/etc/gway-wireguard/server.env")


def _server_installer() -> Path:
    """Locate the checkout's server installer without depending on caller cwd."""
    for parent in Path(__file__).resolve().parents:
        candidate = parent / "server" / "install.sh"
        if candidate.is_file() and (parent / "gway.toml").is_file():
            return candidate
    raise RuntimeError("could not locate gway-wireguard server installer")


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


def _read_env(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip()
    return values


def deploy() -> dict[str, object]:
    """Deploy the current managed checkout to the gateway and restart services."""
    return _run_installer()


def status() -> dict[str, object]:
    """Show deployed gateway, registry, enrollment, and DNS status."""
    return _run_installer("--status")


def check() -> dict[str, object]:
    """Validate server source and configuration defaults without changing the host."""
    return _run_installer("--check")


def ready(
    expected_domain: str | None = None,
    require_dns: bool = True,
    env_file: Path = _DEFAULT_ENV_FILE,
) -> dict[str, object]:
    """Validate deployed configuration before Phase 5 production routing."""
    issues: list[str] = []
    if not env_file.is_file():
        return {
            "ready": False,
            "issues": [f"missing deployed environment: {env_file}"],
        }

    try:
        values = _read_env(env_file)
    except OSError as exc:
        return {
            "ready": False,
            "issues": [f"cannot read deployed environment: {exc}"],
        }

    domain = values.get("GWAY_BASE_DOMAIN", "").strip().lower()
    provider = values.get("GWAY_DNS_PROVIDER", "none").strip().lower() or "none"
    registry = Path(
        values.get("GWAY_REGISTRY_DB", "/var/lib/gway-wireguard/registry.sqlite3")
    )
    vpn_hostname = values.get("GWAY_VPN_HOSTNAME", "").strip().lower()
    register_hostname = values.get("GWAY_REGISTER_HOSTNAME", "").strip().lower()

    if not domain:
        issues.append("GWAY_BASE_DOMAIN is not configured")
    if expected_domain is not None and domain != expected_domain.strip().lower():
        issues.append(
            f"base domain mismatch: configured={domain or '<unset>'} expected={expected_domain}"
        )
    if not registry.is_file():
        issues.append(f"registry does not exist: {registry}")
    if require_dns and provider in {"", "none", "disabled"}:
        issues.append("DNS provider is disabled")
    if domain:
        if vpn_hostname != f"vpn.{domain}":
            issues.append(
                f"VPN hostname mismatch: configured={vpn_hostname or '<unset>'} expected=vpn.{domain}"
            )
        if register_hostname != f"register.{domain}":
            issues.append(
                "register hostname mismatch: "
                f"configured={register_hostname or '<unset>'} expected=register.{domain}"
            )

    if provider == "godaddy":
        for key in ("GWAY_GODADDY_KEY_FILE", "GWAY_GODADDY_SECRET_FILE"):
            value = values.get(key, "").strip()
            if not value:
                issues.append(f"{key} is not configured")
                continue
            credential = Path(value)
            try:
                if not credential.is_file() or credential.stat().st_size == 0:
                    issues.append(f"credential file missing or empty: {credential}")
            except OSError as exc:
                issues.append(f"cannot inspect credential file {credential}: {exc}")

    return {
        "ready": not issues,
        "domain": domain or None,
        "dns_provider": provider,
        "registry": str(registry),
        "issues": issues,
    }
