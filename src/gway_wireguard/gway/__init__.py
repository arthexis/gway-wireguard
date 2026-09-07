"""Public GWAY command namespace for gway-wireguard."""

from __future__ import annotations

import subprocess


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
