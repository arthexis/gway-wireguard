#!/usr/bin/env python3
"""Compatibility imports for the packaged registry implementation."""

from gway_wireguard.registry import (
    AddressPoolExhausted,
    EnrollmentRejected,
    Registry,
    RegistryError,
    isoformat,
    token_hash,
    utc_now,
    validate_device_id,
    validate_public_key,
)

__all__ = [
    "AddressPoolExhausted",
    "EnrollmentRejected",
    "Registry",
    "RegistryError",
    "isoformat",
    "token_hash",
    "utc_now",
    "validate_device_id",
    "validate_public_key",
]
