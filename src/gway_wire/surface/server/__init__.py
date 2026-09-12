"""Server command surface with exact-FQDN public enrollment readiness."""

from __future__ import annotations

import os
import shutil
import socket
import subprocess
from contextlib import contextmanager
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from gway_web import exposure_check, exposure_ensure

from gway_wire.admin_ops import create_enrollment_token, list_devices, revoke_device
from gway_wire.config import read_environment_file
from gway_wire.gway import server as legacy
from gway_wire.gway.protocols import DEFAULT_PROTOCOL, require_protocol
from gway_wire.peer_manager import PeerManager

_DEFAULT_ENV_FILE = Path("/etc/gway-wireguard/server.env")


def _one_fqdn(
    names: tuple[str, ...], *, fqdn: str | None = None, domain: str | None = None
) -> str:
    if len(names) > 1:
        raise ValueError("expected at most one FQDN")
    supplied = [value for value in (*names, fqdn, domain) if value]
    if not supplied:
        raise ValueError("--fqdn is required")
    normalized = [legacy._normalize_domain(value) for value in supplied]
    if len(set(normalized)) != 1:
        raise ValueError("positional FQDN, --fqdn, and --domain must agree")
    return normalized[0]


def _values(env_file: Path) -> dict[str, str]:
    try:
        return read_environment_file(env_file)
    except OSError:
        return {}


def _replace_env_values(env_file: Path, changes: dict[str, str]) -> str | None:
    """Patch an existing server.env and return its original text for rollback."""
    if not env_file.is_file():
        return None
    original = env_file.read_text(encoding="utf-8")
    pending = dict(changes)
    lines: list[str] = []
    for line in original.splitlines():
        key = line.partition("=")[0]
        if key in pending:
            lines.append(f"{key}={pending.pop(key)}")
        else:
            lines.append(line)
    lines.extend(f"{key}={value}" for key, value in pending.items())
    env_file.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return original


def _selected_provider(
    values: dict[str, str], dns_provider: str | None, provider: str | None
) -> str | None:
    explicit = legacy._resolve_deploy_provider(dns_provider, provider)
    if explicit is not None:
        return explicit
    configured = values.get("GWAY_DNS_PROVIDER", "none").strip().lower()
    return None if configured in {"", "none", "disabled"} else configured


def _public_address(values: dict[str, str], explicit: str | None) -> str | None:
    if explicit and explicit.strip():
        return explicit.strip()
    configured = values.get("GWAY_PUBLIC_GATEWAY_IP", "").strip()
    if configured:
        return configured
    endpoint = values.get("GWAY_GATEWAY_ENDPOINT", "").strip()
    host = endpoint.rsplit(":", 1)[0] if ":" in endpoint else endpoint
    try:
        socket.inet_aton(host)
    except OSError:
        return None
    return host


@contextmanager
def _web_environment(values: dict[str, str]):
    """Expose existing Wire provider configuration to Web for one operation."""
    names = (
        "GWAY_GODADDY_KEY",
        "GWAY_GODADDY_SECRET",
        "GWAY_GODADDY_KEY_FILE",
        "GWAY_GODADDY_SECRET_FILE",
    )
    before = {name: os.environ.get(name) for name in (*names, "GWAY_GODADDY_DOMAIN")}
    try:
        for name in names:
            value = values.get(name, "").strip()
            if value:
                os.environ[name] = value
        zone = values.get("GWAY_BASE_DOMAIN", "").strip()
        if zone:
            os.environ["GWAY_GODADDY_DOMAIN"] = zone
        yield
    finally:
        for name, value in before.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value


def _local_config(fqdn: str, env_file: Path, require_dns: bool) -> dict[str, object]:
    base = legacy._readiness(domain=None, require_dns=require_dns, env_file=env_file)
    values = _values(env_file)
    issues = list(base.get("issues", []))
    configured = values.get("GWAY_REGISTER_HOSTNAME", "").strip().lower()
    if configured != fqdn:
        issues.append(
            f"public enrollment FQDN mismatch: configured={configured or '<unset>'} expected={fqdn}"
        )
    return {
        **base,
        "fqdn": fqdn,
        "ready": not issues,
        "issues": issues,
    }


def _wireguard(values: dict[str, str]) -> dict[str, object]:
    executable = shutil.which("wg")
    interface = values.get("GWAY_WG_INTERFACE", "gway")
    if executable is None:
        return {"ok": False, "detail": "wg executable not found", "interface": interface}
    result = subprocess.run(
        [executable, "show", interface], check=False, capture_output=True, text=True
    )
    return {
        "ok": result.returncode == 0,
        "interface": interface,
        "detail": result.stderr.strip() or result.stdout.strip(),
    }


def _listener(values: dict[str, str]) -> dict[str, object]:
    port = values.get("GWAY_WG_PORT", "51820").strip() or "51820"
    executable = shutil.which("ss")
    if executable is None:
        return {"ok": False, "detail": "ss executable not found", "port": int(port)}
    result = subprocess.run(
        [executable, "-lun"], check=False, capture_output=True, text=True
    )
    found = result.returncode == 0 and any(
        line.rstrip().endswith(f":{port}") or f":{port} " in line
        for line in result.stdout.splitlines()
    )
    return {"ok": found, "port": int(port), "protocol": "udp"}


def _enrollment(values: dict[str, str], timeout: float) -> dict[str, object]:
    host = values.get("GWAY_ENROLL_BIND", "127.0.0.1")
    port = int(values.get("GWAY_ENROLL_PORT", "8787"))
    url = f"http://{host}:{port}/health"
    try:
        with urlopen(Request(url, method="GET"), timeout=timeout) as response:  # noqa: S310
            status = response.getcode()
            return {"ok": 200 <= status < 400, "url": url, "status": status}
    except HTTPError as exc:
        return {"ok": False, "url": url, "status": exc.code, "detail": str(exc)}
    except (URLError, OSError) as exc:
        return {"ok": False, "url": url, "status": None, "detail": str(exc)}


def _peers(values: dict[str, str]) -> dict[str, object]:
    config_path = Path(values.get("GWAY_WG_CONFIG", "/etc/wireguard/gway.conf"))
    managed = (
        PeerManager(config_path, apply_runtime=False).managed_peers()
        if config_path.is_file()
        else []
    )
    return {
        "ok": config_path.is_file(),
        "config": str(config_path),
        "managed": managed,
        "count": len(managed),
    }


def _web(
    fqdn: str,
    values: dict[str, str],
    *,
    provider: str | None,
    public_address: str | None,
    timeout: float,
) -> dict[str, object]:
    try:
        with _web_environment(values):
            return exposure_check(
                fqdn=fqdn,
                dns_provider=provider,
                dns_zone=values.get("GWAY_BASE_DOMAIN") or None,
                public_address=public_address,
                timeout=timeout,
            )
    except Exception as exc:
        return {"fqdn": fqdn, "ok": False, "checks": [], "error": str(exc)}


def _web_subset(result: dict[str, object], kinds: set[str]) -> dict[str, object]:
    checks = [
        item
        for item in result.get("checks", [])
        if isinstance(item, dict) and str(item.get("check")) in kinds
    ]
    return {
        "fqdn": result.get("fqdn"),
        "ok": bool(checks) and all(bool(item.get("ok")) for item in checks),
        "checks": checks,
        **({"error": result["error"]} if "error" in result else {}),
    }


def deploy(
    *name: str,
    fqdn: str | None = None,
    domain: str | None = None,
    require_dns: bool = True,
    dns: bool | None = None,
    dns_provider: str | None = None,
    provider: str | None = None,
    public_address: str | None = None,
    cert_email: str | None = None,
    env_file: Path = _DEFAULT_ENV_FILE,
    protocol: str = DEFAULT_PROTOCOL,
) -> dict[str, object]:
    """Deploy Wire and expose its enrollment service at one exact public FQDN."""
    require_protocol(protocol)
    target = _one_fqdn(name, fqdn=fqdn, domain=domain)
    before_values = _values(env_file)
    selected_provider = _selected_provider(before_values, dns_provider, provider)
    dns_required = legacy._effective_require_dns(require_dns, dns)

    changes = {"GWAY_REGISTER_HOSTNAME": target}
    if selected_provider is not None:
        changes["GWAY_DNS_PROVIDER"] = selected_provider
    original_env = _replace_env_values(env_file, changes)

    environment = os.environ.copy()
    environment["REGISTER_HOSTNAME"] = target
    if selected_provider is not None:
        environment["DNS_PROVIDER"] = selected_provider
    installer = legacy._run_installer(env=environment)
    if not installer["success"]:
        if original_env is not None:
            env_file.write_text(original_env, encoding="utf-8")
        return {**installer, "fqdn": target, "success": False}

    values = _values(env_file)
    selected_provider = _selected_provider(values, dns_provider, provider)
    address = _public_address(values, public_address)
    bind = values.get("GWAY_ENROLL_BIND", "127.0.0.1")
    port = int(values.get("GWAY_ENROLL_PORT", "8787"))
    upstream = f"http://{bind}:{port}"
    email = cert_email or values.get("GWAY_CERTBOT_EMAIL") or os.environ.get("GWAY_CERTBOT_EMAIL")

    try:
        with _web_environment(values):
            web_result = exposure_ensure(
                fqdn=target,
                upstream=upstream,
                health_path="/health",
                certbot=True,
                dns_provider=selected_provider if dns_required else None,
                dns_zone=values.get("GWAY_BASE_DOMAIN") or None,
                public_address=address,
                email=email,
                agree_tos=True,
            )
    except Exception as exc:
        if original_env is not None:
            env_file.write_text(original_env, encoding="utf-8")
        return {
            **installer,
            "fqdn": target,
            "success": False,
            "web": {"success": False, "error": str(exc)},
        }

    readiness = check(
        fqdn=target,
        require_dns=dns_required,
        env_file=env_file,
        protocol=protocol,
    )
    return {
        **installer,
        "fqdn": target,
        "dns_provider": selected_provider,
        "web": web_result,
        "readiness": readiness,
        "success": bool(readiness["ok"]),
    }


def status(
    env_file: Path = _DEFAULT_ENV_FILE,
    debug: bool = False,
    protocol: str = DEFAULT_PROTOCOL,
) -> dict[str, object]:
    """Return static server state, including the exact enrollment FQDN."""
    require_protocol(protocol)
    result = legacy._snapshot(env_file=env_file, debug=debug)
    if result.get("configured"):
        result["fqdn"] = result.get("register_hostname")
    return result


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
    env_file: Path = _DEFAULT_ENV_FILE,
    protocol: str = DEFAULT_PROTOCOL,
) -> dict[str, object]:
    """Run read-only end-to-end readiness checks for one exact public FQDN."""
    require_protocol(protocol)
    target = _one_fqdn(name, fqdn=fqdn, domain=domain)
    dns_required = legacy._effective_require_dns(require_dns, dns)
    values = _values(env_file)
    selected_provider = _selected_provider(values, None, None)
    address = _public_address(values, public_address)

    selected = {
        "source": source,
        "config": config,
        "wireguard": wireguard,
        "listener": listener,
        "enrollment": enrollment,
        "web": web,
        "dns": dns_provider or provider,
        "tls": tls,
        "public": public,
        "peers": peers,
    }
    if not any(selected.values()):
        for key in selected:
            selected[key] = True

    checks: dict[str, object] = {}
    if selected["source"]:
        result = legacy._run_installer("--check")
        checks["source"] = {"ok": bool(result.get("success")), **result}
    if selected["config"]:
        checks["config"] = _local_config(target, env_file, dns_required)
        checks["config"]["ok"] = bool(checks["config"].get("ready"))  # type: ignore[index]
    if selected["wireguard"]:
        checks["wireguard"] = _wireguard(values)
    if selected["listener"]:
        checks["listener"] = _listener(values)
    if selected["enrollment"]:
        checks["enrollment"] = _enrollment(values, timeout)

    if any(selected[key] for key in ("web", "dns", "tls", "public")):
        observed = _web(
            target,
            values,
            provider=selected_provider if dns_required else None,
            public_address=address,
            timeout=timeout,
        )
        if selected["web"]:
            checks["web"] = observed
        if selected["dns"]:
            checks["dns"] = _web_subset(observed, {"dns"})
        if selected["tls"]:
            checks["tls"] = _web_subset(observed, {"certificate"})
        if selected["public"]:
            checks["public"] = _web_subset(
                observed, {"reachability", "public", "public_health"}
            )
    if selected["peers"]:
        checks["peers"] = _peers(values)

    def passed(value: object) -> bool:
        return isinstance(value, dict) and bool(value.get("ok"))

    return {
        "fqdn": target,
        "ok": bool(checks) and all(passed(value) for value in checks.values()),
        "checks": checks,
    }


def validate(
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
    env_file: Path = _DEFAULT_ENV_FILE,
    protocol: str = DEFAULT_PROTOCOL,
) -> dict[str, object]:
    """Alias for check."""
    return check(
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
        env_file=env_file,
        protocol=protocol,
    )


def token(
    device: str | None = None,
    ttl: int = 3600,
    protocol: str = DEFAULT_PROTOCOL,
) -> dict[str, object]:
    """Create a one-time enrollment token."""
    require_protocol(protocol)
    return create_enrollment_token(device=device, ttl=ttl)


def devices(protocol: str = DEFAULT_PROTOCOL) -> list[dict[str, object]]:
    """List enrolled devices."""
    require_protocol(protocol)
    return list_devices()


def revoke(device: str, protocol: str = DEFAULT_PROTOCOL) -> dict[str, object]:
    """Revoke one enrolled device."""
    require_protocol(protocol)
    return revoke_device(device)
