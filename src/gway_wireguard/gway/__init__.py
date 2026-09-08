"""Public GWAY command namespace for gway-wireguard."""

from __future__ import annotations

import getpass
import os
import subprocess
from pathlib import Path

_DEFAULT_ENROLL_URL = "https://register.arthexis.com/v1/enroll"


def _client_installer() -> Path:
    """Locate the checkout's client installer without depending on the caller cwd."""
    for parent in Path(__file__).resolve().parents:
        candidate = parent / "install.sh"
        if candidate.is_file() and (parent / "gway.toml").is_file():
            return candidate
    raise RuntimeError("could not locate gway-wireguard client installer")


def enroll(
    device: str | None = None,
    token_file: Path | None = None,
    token: str | None = None,
    enroll_url: str = _DEFAULT_ENROLL_URL,
) -> dict[str, object]:
    """Enroll this device, prompting securely when no token source is supplied."""
    prompted_token = False
    if token_file is None and token is None:
        try:
            token = getpass.getpass("Enrollment token: ").strip()
        except EOFError:
            token = ""
        if not token:
            return {
                "success": False,
                "exit_code": 2,
                "output": "",
                "error": "no enrollment token provided",
            }
        prompted_token = True

    command = ["bash", str(_client_installer())]
    if device:
        command.extend(["--device", device])
    if token_file is not None:
        command.extend(["--token-file", str(token_file)])
    if token is not None and not prompted_token:
        command.extend(["--token", token])
    command.extend(["--enroll-url", enroll_url])

    run_kwargs: dict[str, object] = {
        "check": False,
        "capture_output": True,
        "text": True,
    }
    if prompted_token:
        environment = os.environ.copy()
        environment["GWAY_ENROLL_TOKEN"] = token
        run_kwargs["env"] = environment

    result = subprocess.run(command, **run_kwargs)
    return {
        "success": result.returncode == 0,
        "exit_code": result.returncode,
        "output": result.stdout.strip(),
        "error": result.stderr.strip(),
    }


def status(interface: str = "gway", wg_bin: str = "wg") -> dict[str, object]:
    """Show live WireGuard status without exposing private key material."""
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
        detail = (
            result.stderr.strip() or f"{wg_bin} exited with status {result.returncode}"
        )
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
