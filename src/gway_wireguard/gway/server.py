"""GWAY lifecycle commands for the gway-wireguard gateway service."""

from __future__ import annotations

import subprocess
from pathlib import Path


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


def deploy() -> dict[str, object]:
    """Deploy the current managed checkout to the gateway and restart services."""
    return _run_installer()


def status() -> dict[str, object]:
    """Show deployed gateway, registry, enrollment, and DNS status."""
    return _run_installer("--status")


def check() -> dict[str, object]:
    """Validate server source and configuration defaults without changing the host."""
    return _run_installer("--check")
