"""Protocol selection shared by the public GWAY command surface."""

from __future__ import annotations

DEFAULT_PROTOCOL = "wireguard"
SUPPORTED_PROTOCOLS = frozenset({DEFAULT_PROTOCOL})


def require_protocol(protocol: str = DEFAULT_PROTOCOL) -> str:
    """Return a normalized supported protocol or raise for an unknown backend."""
    normalized = protocol.strip().lower()
    if normalized not in SUPPORTED_PROTOCOLS:
        supported = ", ".join(sorted(SUPPORTED_PROTOCOLS))
        raise ValueError(f"unsupported protocol {protocol!r}; supported: {supported}")
    return normalized
