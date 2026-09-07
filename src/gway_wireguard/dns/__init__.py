"""Public DNS automation API for gway-wireguard."""

from .provider import DNSConfigurationError, DNSProvider, DNSProviderError, DNSRecord
from .service import DNSManager, DNSMutation, DNSSettings, manager_from_env

__all__ = [
    "DNSConfigurationError",
    "DNSManager",
    "DNSMutation",
    "DNSProvider",
    "DNSProviderError",
    "DNSRecord",
    "DNSSettings",
    "manager_from_env",
]
