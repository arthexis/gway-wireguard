#!/usr/bin/env python3
"""Compatibility imports for the packaged peer manager."""

from gway_wireguard.peer_manager import (
    BEGIN_PREFIX,
    END_PREFIX,
    PeerManager,
    PeerManagerError,
    _validate_address,
)

__all__ = [
    "BEGIN_PREFIX",
    "END_PREFIX",
    "PeerManager",
    "PeerManagerError",
    "_validate_address",
]
