"""Shared server configuration loading for service and generated GWAY commands."""

from __future__ import annotations

import os
from pathlib import Path

DEFAULT_SERVER_ENV = Path("/etc/gway-wireguard/server.env")


def _unquote(value: str) -> str:
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        return value[1:-1]
    return value


def read_environment_file(path: str | Path) -> dict[str, str]:
    """Read the simple KEY=VALUE subset written by the server installer."""
    source = Path(path)
    try:
        text = source.read_text(encoding="utf-8")
    except FileNotFoundError:
        return {}
    except PermissionError:
        # Non-privileged diagnostics may still use process environment/defaults.
        return {}

    values: dict[str, str] = {}
    for number, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            raise ValueError(f"invalid server environment line {number}: {source}")
        key, value = line.split("=", 1)
        key = key.strip()
        if not key or not key.replace("_", "A").isalnum() or not key[0].isalpha():
            raise ValueError(
                f"invalid server environment key on line {number}: {source}"
            )
        values[key] = _unquote(value.strip())
    return values


def server_environment() -> dict[str, str]:
    """Return installed server values overlaid by the current process environment."""
    path = Path(os.environ.get("GWAY_SERVER_ENV_FILE", str(DEFAULT_SERVER_ENV)))
    values = read_environment_file(path)
    values.update(os.environ)
    return values
