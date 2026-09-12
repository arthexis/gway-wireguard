"""Client commands exposed by the canonical Wire surface."""

from __future__ import annotations

from pathlib import Path

from gway_wire.gway import client as legacy
from gway_wire.gway.protocols import DEFAULT_PROTOCOL


def enroll(
    device: str | None = None,
    token_file: Path | None = None,
    token: str | None = None,
    enroll_url: str = legacy._DEFAULT_ENROLL_URL,
    url: str | None = None,
    protocol: str = DEFAULT_PROTOCOL,
) -> dict[str, object]:
    """Enroll this client using a server-issued token and enrollment URL."""
    return legacy.enroll(
        device=device,
        token_file=token_file,
        token=token,
        enroll_url=enroll_url,
        url=url,
        protocol=protocol,
    )


def sync(
    state_dir: Path = legacy._DEFAULT_STATE_DIR,
    interface: str = "gway",
    protocol: str = DEFAULT_PROTOCOL,
) -> dict[str, object]:
    """Reconcile persisted client state with the live protocol state."""
    return legacy.sync(state_dir=state_dir, interface=interface, protocol=protocol)


def status(
    state_dir: Path = legacy._DEFAULT_STATE_DIR,
    interface: str = "gway",
    debug: bool = False,
    wg_bin: str = "wg",
    protocol: str = DEFAULT_PROTOCOL,
) -> dict[str, object]:
    """Return persisted client configuration and optional live detail."""
    return legacy.status(
        state_dir=state_dir,
        interface=interface,
        debug=debug,
        wg_bin=wg_bin,
        protocol=protocol,
    )
