"""Read-only peer inspection commands for GWAY."""

from __future__ import annotations

from pathlib import Path

_BEGIN_PREFIX = "# BEGIN gway-wireguard managed peer: "


def managed(config_path: Path = Path("/etc/wireguard/gway.conf")) -> list[dict[str, str]]:
    """List peers managed by gway-wireguard in the persistent config."""
    text = config_path.read_text(encoding="utf-8")
    peers: list[dict[str, str]] = []
    current: dict[str, str] | None = None

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if line.startswith(_BEGIN_PREFIX):
            current = {"device": line.removeprefix(_BEGIN_PREFIX)}
            continue
        if current is None:
            continue
        if line.startswith("PublicKey") and "=" in line:
            current["public_key"] = line.split("=", 1)[1].strip()
        elif line.startswith("AllowedIPs") and "=" in line:
            current["allowed_ips"] = line.split("=", 1)[1].strip()
        elif line.startswith("# END gway-wireguard managed peer: "):
            peers.append(current)
            current = None

    return peers
