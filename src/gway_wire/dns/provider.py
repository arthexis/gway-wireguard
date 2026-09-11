"""Provider-neutral DNS record contract for gway-wireguard."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol


class DNSProviderError(RuntimeError):
    """A DNS provider operation failed."""


class DNSConfigurationError(ValueError):
    """DNS automation configuration is missing or invalid."""


@dataclass(frozen=True)
class DNSRecord:
    """One DNS record value managed by the provider adapter."""

    data: str
    ttl: int = 600


class DNSProvider(Protocol):
    """Small provider boundary used by the shared DNS manager."""

    def get_records(self, name: str, record_type: str) -> list[DNSRecord]: ...

    def replace_records(
        self,
        name: str,
        record_type: str,
        records: list[DNSRecord],
    ) -> None: ...

    def delete_records(self, name: str, record_type: str) -> None: ...
