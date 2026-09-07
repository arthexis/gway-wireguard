"""GoDaddy DNS provider adapter.

The adapter intentionally contains only provider-specific HTTP behavior. Desired
state, idempotency, device ownership, and rollback live in ``dns.service``.
"""

from __future__ import annotations

import json
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

from .provider import DNSProviderError, DNSRecord


class GoDaddyProvider:
    """Manage one GoDaddy DNS zone through the v1 REST API."""

    def __init__(
        self,
        *,
        domain: str,
        key: str,
        secret: str,
        api_base: str = "https://api.godaddy.com/v1",
        timeout: float = 10.0,
    ) -> None:
        if not domain or not key or not secret:
            raise ValueError("GoDaddy domain, key, and secret are required")
        self.domain = domain
        self.key = key
        self.secret = secret
        self.api_base = api_base.rstrip("/")
        self.timeout = timeout

    def _url(self, name: str, record_type: str) -> str:
        return (
            f"{self.api_base}/domains/{quote(self.domain, safe='')}/records/"
            f"{quote(record_type.upper(), safe='')}/{quote(name, safe='')}"
        )

    def _request(
        self,
        method: str,
        name: str,
        record_type: str,
        *,
        payload: object | None = None,
    ) -> object | None:
        data = None
        if payload is not None:
            data = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        request = Request(
            self._url(name, record_type),
            data=data,
            method=method,
            headers={
                "Accept": "application/json",
                "Content-Type": "application/json",
                "Authorization": f"sso-key {self.key}:{self.secret}",
                "User-Agent": "gway-wireguard/0.3",
            },
        )
        try:
            with urlopen(request, timeout=self.timeout) as response:  # noqa: S310
                raw = response.read()
        except HTTPError as exc:
            raise DNSProviderError(
                f"GoDaddy DNS request failed with HTTP {exc.code}"
            ) from exc
        except (URLError, OSError) as exc:
            raise DNSProviderError("GoDaddy DNS request failed") from exc

        if not raw:
            return None
        try:
            return json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise DNSProviderError("GoDaddy DNS returned invalid JSON") from exc

    def get_records(self, name: str, record_type: str) -> list[DNSRecord]:
        payload = self._request("GET", name, record_type)
        if payload is None:
            return []
        if not isinstance(payload, list):
            raise DNSProviderError("GoDaddy DNS returned an invalid record list")

        records: list[DNSRecord] = []
        for item in payload:
            if not isinstance(item, dict):
                raise DNSProviderError("GoDaddy DNS returned an invalid record")
            data = item.get("data")
            ttl = item.get("ttl")
            if not isinstance(data, str) or not isinstance(ttl, int):
                raise DNSProviderError("GoDaddy DNS returned an invalid record")
            records.append(DNSRecord(data=data, ttl=ttl))
        return records

    def replace_records(
        self,
        name: str,
        record_type: str,
        records: list[DNSRecord],
    ) -> None:
        payload = [{"data": record.data, "ttl": record.ttl} for record in records]
        self._request("PUT", name, record_type, payload=payload)

    def delete_records(self, name: str, record_type: str) -> None:
        self._request("DELETE", name, record_type)
