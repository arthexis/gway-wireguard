"""Shared desired-state DNS management for public gway-wireguard names."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Mapping

from gway_wire.config import server_environment

from .godaddy import GoDaddyProvider
from .provider import DNSConfigurationError, DNSProvider, DNSRecord

_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$"
)


def _read_optional_secret(
    values: Mapping[str, str],
    env_name: str,
    path_name: str,
    default_path: str,
) -> str | None:
    direct = values.get(env_name)
    if direct:
        return direct
    path = Path(values.get(path_name, default_path))
    try:
        if not path.exists():
            return None
    except PermissionError:
        # A non-root diagnostic must not fail merely because the credential
        # directory is intentionally inaccessible.
        return None
    try:
        value = path.read_text(encoding="utf-8").strip()
    except PermissionError:
        # Non-privileged status can still report that credentials are not readable.
        return None
    except OSError as exc:
        raise DNSConfigurationError(f"cannot read DNS credential file: {path}") from exc
    return value or None


@dataclass(frozen=True)
class DNSSettings:
    """Server-side DNS automation settings; credentials never leave the gateway."""

    provider: str = "none"
    base_domain: str = "arthexis.com"
    public_gateway_ip: str = "54.161.177.151"
    ttl: int = 600
    vpn_hostname: str = "vpn.arthexis.com"
    register_hostname: str = "register.arthexis.com"
    godaddy_key: str | None = None
    godaddy_secret: str | None = None
    godaddy_api_base: str = "https://api.godaddy.com/v1"

    @classmethod
    def from_env(cls) -> "DNSSettings":
        values = server_environment()
        base_domain = values.get("GWAY_BASE_DOMAIN", "arthexis.com")
        provider = values.get("GWAY_DNS_PROVIDER", "none").strip().lower()

        # Disabled or unsupported providers do not need credential discovery.
        # This keeps non-root checks independent of intentionally root-only
        # credential directories. Unsupported providers are rejected by validate().
        godaddy_key: str | None = None
        godaddy_secret: str | None = None
        if provider == "godaddy":
            godaddy_key = _read_optional_secret(
                values,
                "GWAY_GODADDY_KEY",
                "GWAY_GODADDY_KEY_FILE",
                "/etc/gway-wireguard/godaddy.key",
            )
            godaddy_secret = _read_optional_secret(
                values,
                "GWAY_GODADDY_SECRET",
                "GWAY_GODADDY_SECRET_FILE",
                "/etc/gway-wireguard/godaddy.secret",
            )

        return cls(
            provider=provider,
            base_domain=base_domain,
            public_gateway_ip=values.get("GWAY_PUBLIC_GATEWAY_IP", "54.161.177.151"),
            ttl=int(values.get("GWAY_DNS_TTL", "600")),
            vpn_hostname=values.get("GWAY_VPN_HOSTNAME", f"vpn.{base_domain}"),
            register_hostname=values.get(
                "GWAY_REGISTER_HOSTNAME", f"register.{base_domain}"
            ),
            godaddy_key=godaddy_key,
            godaddy_secret=godaddy_secret,
            godaddy_api_base=values.get(
                "GWAY_GODADDY_API_BASE", "https://api.godaddy.com/v1"
            ),
        )

    @property
    def enabled(self) -> bool:
        return self.provider not in {"", "none", "disabled"}

    def validate(self) -> None:
        if self.provider not in {"none", "disabled", "godaddy"}:
            raise DNSConfigurationError(f"unsupported DNS provider: {self.provider}")
        if not _DOMAIN_RE.fullmatch(self.base_domain):
            raise DNSConfigurationError("invalid DNS base domain")
        try:
            public_ip = ipaddress.ip_address(self.public_gateway_ip)
        except ValueError as exc:
            raise DNSConfigurationError("invalid public gateway IP") from exc
        if public_ip.version != 4:
            raise DNSConfigurationError("public gateway IP must be IPv4")
        if self.ttl < 600 or self.ttl > 86400:
            raise DNSConfigurationError("DNS TTL must be between 600 and 86400 seconds")
        for hostname in (self.vpn_hostname, self.register_hostname):
            self.relative_name(hostname)
        if self.vpn_hostname == self.register_hostname:
            raise DNSConfigurationError(
                "VPN and registration hostnames must be distinct"
            )
        if self.provider == "godaddy" and (
            not self.godaddy_key or not self.godaddy_secret
        ):
            raise DNSConfigurationError(
                "GoDaddy DNS credentials are not configured or not readable"
            )

    def relative_name(self, hostname: str) -> str:
        suffix = f".{self.base_domain}"
        if not hostname.endswith(suffix):
            raise DNSConfigurationError(
                f"hostname is outside managed domain {self.base_domain}: {hostname}"
            )
        name = hostname[: -len(suffix)]
        if not name or any(
            not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,62}", label)
            for label in name.split(".")
        ):
            raise DNSConfigurationError(f"invalid managed hostname: {hostname}")
        return name

    def validate_device_hostname(self, hostname: str) -> str:
        """Validate a registry device name and reject operational-name collisions."""
        name = self.relative_name(hostname)
        if hostname in {self.vpn_hostname, self.register_hostname}:
            raise DNSConfigurationError(
                f"device hostname conflicts with an operational DNS name: {hostname}"
            )
        return name


@dataclass(frozen=True)
class DNSMutation:
    """Enough information to restore provider state after a failed transaction."""

    hostname: str
    record_type: str
    previous: tuple[DNSRecord, ...]
    changed: bool


class DNSManager:
    """Own desired DNS state independently of any concrete DNS provider."""

    def __init__(
        self,
        settings: DNSSettings | None = None,
        *,
        provider: DNSProvider | None = None,
    ) -> None:
        self.settings = settings or DNSSettings.from_env()
        self.settings.validate()
        if provider is not None:
            self.provider = provider
        elif self.settings.provider == "godaddy":
            assert self.settings.godaddy_key is not None
            assert self.settings.godaddy_secret is not None
            self.provider = GoDaddyProvider(
                domain=self.settings.base_domain,
                key=self.settings.godaddy_key,
                secret=self.settings.godaddy_secret,
                api_base=self.settings.godaddy_api_base,
            )
        else:
            self.provider = None

    @property
    def enabled(self) -> bool:
        return self.settings.enabled

    def status(self) -> dict[str, object]:
        """Return non-secret DNS configuration status."""
        return {
            "enabled": self.enabled,
            "provider": self.settings.provider,
            "base_domain": self.settings.base_domain,
            "public_gateway_ip": self.settings.public_gateway_ip,
            "ttl": self.settings.ttl,
            "vpn_hostname": self.settings.vpn_hostname,
            "register_hostname": self.settings.register_hostname,
            "credentials_configured": bool(
                self.settings.godaddy_key and self.settings.godaddy_secret
            )
            if self.settings.provider == "godaddy"
            else None,
        }

    def _require_provider(self) -> DNSProvider:
        if self.provider is None:
            raise DNSConfigurationError("DNS automation is disabled")
        return self.provider

    def _restore_provider_state(
        self,
        name: str,
        record_type: str,
        previous: tuple[DNSRecord, ...],
    ) -> None:
        provider = self._require_provider()
        if previous:
            provider.replace_records(name, record_type, list(previous))
        else:
            provider.delete_records(name, record_type)

    def ensure_record(
        self,
        hostname: str,
        record_type: str,
        value: str,
    ) -> DNSMutation:
        """Ensure one explicit record and return reversible mutation metadata."""
        provider = self._require_provider()
        if record_type.upper() != "A":
            raise DNSConfigurationError("Phase 4 manages A records only")
        try:
            address = ipaddress.ip_address(value)
        except ValueError as exc:
            raise DNSConfigurationError("A record value must be an IP address") from exc
        if address.version != 4:
            raise DNSConfigurationError("A record value must be IPv4")
        name = self.settings.relative_name(hostname)
        previous = tuple(provider.get_records(name, "A"))
        desired = (DNSRecord(data=str(address), ttl=self.settings.ttl),)
        changed = previous != desired
        if changed:
            try:
                provider.replace_records(name, "A", list(desired))
            except Exception:
                try:
                    self._restore_provider_state(name, "A", previous)
                except Exception:
                    pass
                raise
        return DNSMutation(hostname, "A", previous, changed)

    def delete_record(self, hostname: str, record_type: str = "A") -> DNSMutation:
        """Delete one explicit managed record and return reversible mutation metadata."""
        provider = self._require_provider()
        if record_type.upper() != "A":
            raise DNSConfigurationError("Phase 4 manages A records only")
        name = self.settings.relative_name(hostname)
        previous = tuple(provider.get_records(name, "A"))
        changed = bool(previous)
        if changed:
            try:
                provider.delete_records(name, "A")
            except Exception:
                try:
                    self._restore_provider_state(name, "A", previous)
                except Exception:
                    pass
                raise
        return DNSMutation(hostname, "A", previous, changed)

    def restore(self, mutation: DNSMutation) -> None:
        """Restore provider state captured by a prior mutation."""
        if not mutation.changed:
            return
        name = self.settings.relative_name(mutation.hostname)
        self._restore_provider_state(name, mutation.record_type, mutation.previous)

    def sync_devices(
        self,
        devices: Iterable[Mapping[str, object]],
        *,
        include_operational: bool = True,
    ) -> dict[str, object]:
        """Reconcile operational names and registry-owned device records atomically."""
        self._require_provider()
        device_rows = list(devices)
        for record in device_rows:
            self.settings.validate_device_hostname(str(record["hostname"]))

        mutations: list[DNSMutation] = []
        ensured: list[str] = []
        deleted: list[str] = []
        try:
            if include_operational:
                for hostname in (
                    self.settings.vpn_hostname,
                    self.settings.register_hostname,
                ):
                    mutation = self.ensure_record(
                        hostname,
                        "A",
                        self.settings.public_gateway_ip,
                    )
                    mutations.append(mutation)
                    ensured.append(hostname)

            for record in device_rows:
                hostname = str(record["hostname"])
                if record.get("enabled"):
                    mutation = self.ensure_record(
                        hostname,
                        "A",
                        self.settings.public_gateway_ip,
                    )
                    ensured.append(hostname)
                else:
                    mutation = self.delete_record(hostname)
                    deleted.append(hostname)
                mutations.append(mutation)
        except Exception:
            for mutation in reversed(mutations):
                try:
                    self.restore(mutation)
                except Exception:
                    pass
            raise

        return {
            "changed": any(mutation.changed for mutation in mutations),
            "ensured": ensured,
            "deleted": deleted,
            "provider": self.settings.provider,
        }


def manager_from_env() -> DNSManager:
    """Construct the configured DNS manager from installed server state."""
    return DNSManager(DNSSettings.from_env())
