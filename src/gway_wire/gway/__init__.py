"""Public GWAY command namespace for gway-wire.

Role-specific operations live under ``client`` and ``server``. Top-level
``status`` and ``sync`` operate across the configured topology.
"""

from __future__ import annotations

from .topology import status, sync

__all__ = ["status", "sync"]
