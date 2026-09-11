"""Topology-wide GWAY commands spanning configured client and server roles."""

from __future__ import annotations

import os
from contextlib import contextmanager
from pathlib import Path

from gway_wire.admin_ops import sync_dns, sync_hosts
from gway_wire.config import read_environment_file
from gway_wire.gway import client as client_commands
from gway_wire.gway import server as server_commands
from gway_wire.gway.protocols import DEFAULT_PROTOCOL, require_protocol

_STATE_ROOT = Path("/etc/gway-wireguard")


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8").strip()
    except OSError:
        return ""


def _client_domain(state_dir: Path) -> str | None:
    explicit = _read_text(state_dir / "domain")
    if explicit:
        return explicit.lower()
    hostname = _read_text(state_dir / "hostname").lower()
    if "." in hostname:
        return hostname.split(".", 1)[1]
    return None


def discover_servers(root: Path = _STATE_ROOT) -> dict[str, Path]:
    """Return configured server environments keyed by domain."""
    found: dict[str, Path] = {}
    candidates: list[Path] = []
    legacy = root / "server.env"
    if legacy.is_file():
        candidates.append(legacy)
    scoped = root / "servers"
    if scoped.is_dir():
        candidates.extend(sorted(scoped.glob("*.env")))
    for path in candidates:
        values = read_environment_file(path)
        domain = values.get("GWAY_BASE_DOMAIN", "").strip().lower() or path.stem.lower()
        if domain:
            found[domain] = path
    return found


def discover_clients(root: Path = _STATE_ROOT) -> dict[str, Path]:
    """Return configured client state directories keyed by domain."""
    found: dict[str, Path] = {}
    if (root / "client-address").is_file() or (root / "server-endpoint").is_file():
        domain = _client_domain(root)
        if domain:
            found[domain] = root
    scoped = root / "clients"
    if scoped.is_dir():
        for state_dir in sorted(path for path in scoped.iterdir() if path.is_dir()):
            domain = _client_domain(state_dir) or state_dir.name.lower()
            found[domain] = state_dir
    return found


def _client_interface(state_dir: Path) -> str:
    return _read_text(state_dir / "interface") or "gway"


@contextmanager
def _server_environment(path: Path):
    values = read_environment_file(path)
    previous = os.environ.copy()
    os.environ.update(values)
    os.environ["GWAY_SERVER_ENV_FILE"] = str(path)
    try:
        yield
    finally:
        os.environ.clear()
        os.environ.update(previous)


def status(
    server: bool = False,
    client: bool = False,
    debug: bool = False,
    root: Path = _STATE_ROOT,
    protocol: str = DEFAULT_PROTOCOL,
) -> dict[str, dict[str, dict[str, object]]]:
    """Return configured topology snapshots, optionally including debug detail."""
    protocol = require_protocol(protocol)
    include_servers = server or not (server or client)
    include_clients = client or not (server or client)
    result: dict[str, dict[str, dict[str, object]]] = {}

    if include_servers:
        result["servers"] = {
            domain: server_commands.status(
                env_file=env_file,
                debug=debug,
                protocol=protocol,
            )
            for domain, env_file in discover_servers(root).items()
        }

    if include_clients:
        result["clients"] = {
            domain: client_commands.status(
                state_dir=state_dir,
                interface=_client_interface(state_dir),
                debug=debug,
                protocol=protocol,
            )
            for domain, state_dir in discover_clients(root).items()
        }

    return result


def check(
    domain: str,
    source: bool = False,
    config: bool = False,
    dns_provider: bool = False,
    provider: bool = False,
    peers: bool = False,
    require_dns: bool = True,
    dns: bool | None = None,
    root: Path = _STATE_ROOT,
    protocol: str = DEFAULT_PROTOCOL,
) -> dict[str, object]:
    """Run the server-domain check without requiring the explicit server prefix."""
    protocol = require_protocol(protocol)
    wanted = domain.strip().lower().rstrip(".")
    env_file = discover_servers(root).get(wanted, root / "server.env")
    return server_commands.check(
        domain,
        source=source,
        config=config,
        dns_provider=dns_provider,
        provider=provider,
        peers=peers,
        require_dns=require_dns,
        dns=dns,
        env_file=env_file,
        protocol=protocol,
    )


def sync(
    domain: str | None = None,
    root: Path = _STATE_ROOT,
    protocol: str = DEFAULT_PROTOCOL,
) -> dict[str, dict[str, dict[str, object]]]:
    """Reconcile every configured role, optionally restricted to one domain."""
    protocol = require_protocol(protocol)
    wanted = domain.strip().lower() if domain else None
    result: dict[str, dict[str, dict[str, object]]] = {"servers": {}, "clients": {}}

    for name, env_file in discover_servers(root).items():
        if wanted is not None and name != wanted:
            continue
        with _server_environment(env_file):
            result["servers"][name] = {
                "hosts": sync_hosts(),
                "dns": sync_dns(),
            }

    for name, state_dir in discover_clients(root).items():
        if wanted is not None and name != wanted:
            continue
        result["clients"][name] = client_commands.sync(
            state_dir=state_dir,
            interface=_client_interface(state_dir),
            protocol=protocol,
        )

    return result
