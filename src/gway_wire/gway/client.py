"""Client-side GWAY commands for gway-wire devices."""

from __future__ import annotations

import hashlib
import os
import sqlite3
import subprocess
from pathlib import Path

from gway_wire.config import read_environment_file
from gway_wire.gway.protocols import DEFAULT_PROTOCOL, require_protocol

_DEFAULT_ENROLL_URL = "https://register.arthexis.com/v1/enroll"
_DEFAULT_STATE_DIR = Path("/etc/gway-wireguard")
_DEFAULT_SERVER_ENV_FILE = Path("/etc/gway-wireguard/server.env")


class LocalTokenValidationError(RuntimeError):
    """Raised when configured local server state cannot validate a token."""


def _client_installer() -> Path:
    """Locate the checkout's client installer without depending on caller cwd."""
    for parent in Path(__file__).resolve().parents:
        candidate = parent / "install.sh"
        if candidate.is_file() and (parent / "gway.toml").is_file():
            return candidate
    raise RuntimeError("could not locate gway-wire client installer")


def _read_state(state_dir: Path, name: str) -> str | None:
    """Read one persisted client state value, returning None when absent."""
    try:
        value = (state_dir / name).read_text(encoding="utf-8").strip()
    except OSError:
        return None
    return value or None


def _enrollment_token_value(token: str | None, token_file: Path | None) -> str | None:
    """Return the supplied enrollment token without persisting or logging it."""
    if token is not None:
        return token.strip()
    if token_file is not None:
        try:
            return token_file.read_text(encoding="utf-8").strip() or None
        except OSError:
            return None
    return os.environ.get("GWAY_ENROLL_TOKEN", "").strip() or None


def _token_was_issued_locally(
    token: str,
    env_file: Path | None = None,
) -> bool:
    """Return whether this host's configured server registry contains the token."""
    active_env = env_file or _DEFAULT_SERVER_ENV_FILE
    if not active_env.is_file():
        return False
    try:
        values = read_environment_file(active_env)
    except (OSError, ValueError) as exc:
        raise LocalTokenValidationError(
            "local server configuration is unreadable"
        ) from exc
    registry = Path(
        values.get("GWAY_REGISTRY_DB", "/var/lib/gway-wireguard/registry.sqlite3")
    )
    if not registry.is_file():
        raise LocalTokenValidationError(
            "configured local server registry is unavailable"
        )
    digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
    try:
        with sqlite3.connect(registry) as connection:
            row = connection.execute(
                "SELECT 1 FROM enrollment_tokens WHERE token_hash = ? LIMIT 1",
                (digest,),
            ).fetchone()
    except (OSError, sqlite3.Error) as exc:
        raise LocalTokenValidationError(
            "configured local server registry cannot be read"
        ) from exc
    return row is not None


def enroll(
    device: str | None = None,
    token_file: Path | None = None,
    token: str | None = None,
    enroll_url: str = _DEFAULT_ENROLL_URL,
    protocol: str = DEFAULT_PROTOCOL,
) -> dict[str, object]:
    """Enroll this client using a token created first with `gway wire server token` on the server.

    Run the token command on the server device, then run this command on the
    separate client device. A token found in this device's own server registry
    is rejected so a server cannot consume a token it created locally.
    """
    require_protocol(protocol)
    supplied_token = _enrollment_token_value(token, token_file)
    if supplied_token:
        try:
            issued_locally = _token_was_issued_locally(supplied_token)
        except LocalTokenValidationError as exc:
            return {
                "success": False,
                "exit_code": 2,
                "output": "",
                "error": f"cannot validate enrollment token against local server state: {exc}",
            }
        if issued_locally:
            return {
                "success": False,
                "exit_code": 2,
                "output": "",
                "error": (
                    "refusing enrollment with a token created on this device; "
                    "create the token on the server and run enroll on the client"
                ),
            }

    command = ["bash", str(_client_installer())]
    if device:
        command.extend(["--device", device])
    if token_file is not None:
        command.extend(["--token-file", str(token_file)])
    if token is not None:
        command.extend(["--token", token])
    command.extend(["--enroll-url", enroll_url])

    result = subprocess.run(
        command,
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


def sync(
    state_dir: Path = _DEFAULT_STATE_DIR,
    interface: str = "gway",
    protocol: str = DEFAULT_PROTOCOL,
) -> dict[str, object]:
    """Reconcile a persisted client configuration with the live protocol state."""
    require_protocol(protocol)
    env = os.environ.copy()
    env["STATE_DIR"] = str(state_dir)
    env["WG_INTERFACE"] = interface
    result = subprocess.run(
        ["bash", str(_client_installer())],
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
        "interface": interface,
        "state_dir": str(state_dir),
        "protocol": protocol,
    }


def status(
    state_dir: Path = _DEFAULT_STATE_DIR,
    interface: str = "gway",
    debug: bool = False,
    wg_bin: str = "wg",
    protocol: str = DEFAULT_PROTOCOL,
) -> dict[str, object]:
    """Return persisted client configuration; optionally include live debug detail."""
    protocol = require_protocol(protocol)
    configured = (state_dir / "client-address").is_file() or (
        state_dir / "server-endpoint"
    ).is_file()
    result: dict[str, object] = {
        "configured": configured,
        "device": _read_state(state_dir, "device-id"),
        "domain": _read_state(state_dir, "domain"),
        "hostname": _read_state(state_dir, "hostname"),
        "vpn_address": _read_state(state_dir, "client-address"),
        "server_endpoint": _read_state(state_dir, "server-endpoint"),
        "server_tunnel_ip": _read_state(state_dir, "server-tunnel-ip"),
        "interface": interface,
        "state_dir": str(state_dir),
        "protocol": protocol,
    }
    if not debug:
        return result

    try:
        live = subprocess.run(
            [wg_bin, "show", interface],
            check=False,
            capture_output=True,
            text=True,
        )
    except OSError as exc:
        result["debug"] = {"available": False, "detail": str(exc)}
        return result

    result["debug"] = {
        "available": live.returncode == 0,
        "output": live.stdout.strip() if live.returncode == 0 else "",
        "detail": live.stderr.strip() if live.returncode != 0 else "",
    }
    return result
