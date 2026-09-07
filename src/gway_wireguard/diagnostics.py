"""Structured, secret-safe diagnostics for gateway enrollment operations."""

from __future__ import annotations

import json
import os
import sys
import uuid
from collections.abc import Mapping
from typing import Any

_SECRET_ENV_KEYS = (
    "GWAY_GODADDY_KEY",
    "GWAY_GODADDY_SECRET",
)


def new_request_id() -> str:
    """Return an opaque identifier used only to correlate enrollment logs."""
    return uuid.uuid4().hex


def _redact(message: str, payload: Mapping[str, Any] | None = None) -> str:
    secrets: list[str] = []
    if payload is not None:
        token = payload.get("token")
        if isinstance(token, str) and token:
            secrets.append(token)
    for key in _SECRET_ENV_KEYS:
        value = os.environ.get(key)
        if value:
            secrets.append(value)

    redacted = message
    for secret in secrets:
        redacted = redacted.replace(secret, "<redacted>")
    return redacted


def log_enrollment_event(
    event: str,
    *,
    request_id: str,
    device_id: str,
    stage: str,
    error: BaseException | None = None,
    payload: Mapping[str, Any] | None = None,
) -> None:
    """Write one structured event to stderr without logging enrollment secrets."""
    entry: dict[str, object] = {
        "event": event,
        "request_id": request_id,
        "device_id": device_id,
        "stage": stage,
    }
    if error is not None:
        entry["exception"] = type(error).__name__
        entry["message"] = _redact(str(error), payload)

    sys.stderr.write(json.dumps(entry, sort_keys=True, separators=(",", ":")) + "\n")
    sys.stderr.flush()
