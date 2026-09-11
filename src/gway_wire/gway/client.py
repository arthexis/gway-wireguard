"""Client-side GWAY commands for gway-wire devices."""

from __future__ import annotations

import subprocess
from pathlib import Path

_DEFAULT_ENROLL_URL = "https://register.arthexis.com/v1/enroll"


def _client_installer() -> Path:
    """Locate the checkout's client installer without depending on caller cwd."""
    for parent in Path(__file__).resolve().parents:
        candidate = parent / "install.sh"
        if candidate.is_file() and (parent / "gway.toml").is_file():
            return candidate
    raise RuntimeError("could not locate gway-wire client installer")


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


def status(interface: str = "gway", wg_bin: str = "wg") -> dict[str, object]:
    """Show live client WireGuard status without exposing private key material."""
    try:
        result = subprocess.run(
            [wg_bin, "show", interface],
            check=False,
            capture_output=True,
            text=True,
        )
    except OSError as exc:
        return {
            "interface": interface,
            "available": False,
            "detail": str(exc),
        }

    if result.returncode != 0:
        detail = result.stderr.strip() or f"{wg_bin} exited with status {result.returncode}"
        return {
            "interface": interface,
            "available": False,
            "detail": detail,
        }

    return {
        "interface": interface,
        "available": True,
        "output": result.stdout.strip(),
    }
