#!/usr/bin/env python3
"""Compatibility imports for the packaged hosts manager."""

from gway_wireguard.hosts_manager import (
    BEGIN_MARKER,
    END_MARKER,
    HostsManager,
    HostsManagerError,
)

__all__ = [
    "BEGIN_MARKER",
    "END_MARKER",
    "HostsManager",
    "HostsManagerError",
]
