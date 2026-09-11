"""Client-side GWAY commands for gway-wire devices."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

_DEFAULT_ENROLL_URL = "https://register.arthexis.com/v1/enroll"
_DEFAULT_STATE_DIR = Path("/etc/gway-wireguard")


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


def enroll(
    device: str | None = None,
    token_file: Path | None = None,
    token: str | None = None,
    enroll_url: str = _DEFAULT_ENROLL_URL,
) -> dict[str, object]:
    """Enroll this device with the WireGuard gateway without changing directories."""
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
) -> dict[str, object]:
    """Reconcile a persisted client configuration with the live WireGuard state."""
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
    }


def status(
    state_dir: Path = _DEFAULT_STATE_DIR,
    interface: str = "gway",
    debug: bool = False,
    wg_bin: str = "wg",
) -> dict[str, object]:
    """Return persisted client configuration; optionally include live debug detail."""
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
