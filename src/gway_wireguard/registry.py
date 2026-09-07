"""SQLite registry and one-time enrollment tokens for gway-wireguard."""

from __future__ import annotations

import contextlib
import datetime as dt
import hashlib
import ipaddress
import re
import secrets
import sqlite3
from pathlib import Path
from typing import Iterable, Iterator

DEVICE_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$")
PUBLIC_KEY_RE = re.compile(r"^[A-Za-z0-9+/]{43}=$")
DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$"
)


class RegistryError(Exception):
    """Base error for registry operations."""


class EnrollmentRejected(RegistryError):
    """Enrollment request was invalid or unauthorized."""

    def __init__(self, message: str, *, code: str = "enrollment_rejected", status: int = 400):
        super().__init__(message)
        self.code = code
        self.status = status


class AddressPoolExhausted(RegistryError):
    pass


def utc_now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def isoformat(value: dt.datetime) -> str:
    return value.astimezone(dt.timezone.utc).isoformat(timespec="seconds")


def validate_device_id(device_id: str) -> str:
    if not DEVICE_RE.fullmatch(device_id):
        raise EnrollmentRejected(
            "invalid device_id",
            code="invalid_device_id",
            status=400,
        )
    return device_id


def validate_public_key(public_key: str) -> str:
    if not PUBLIC_KEY_RE.fullmatch(public_key):
        raise EnrollmentRejected(
            "invalid WireGuard public key",
            code="invalid_public_key",
            status=400,
        )
    return public_key


def token_hash(token: str) -> str:
    if not token:
        raise EnrollmentRejected(
            "invalid enrollment token",
            code="invalid_enrollment_token",
            status=403,
        )
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


class Registry:
    def __init__(
        self,
        db_path: str | Path,
        *,
        network: str = "10.90.0.0/24",
        gateway_address: str = "10.90.0.1",
    ) -> None:
        self.db_path = Path(db_path)
        parsed_network = ipaddress.ip_network(network, strict=True)
        if parsed_network.version != 4:
            raise ValueError("WG network must be IPv4")
        parsed_gateway = ipaddress.ip_address(gateway_address)
        if parsed_gateway not in parsed_network:
            raise ValueError("gateway address must be inside WG network")
        self.network = parsed_network
        self.gateway_address = parsed_gateway

    def connect(self) -> sqlite3.Connection:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(self.db_path, timeout=30)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA busy_timeout = 30000")
        return conn

    def initialize(self) -> None:
        with contextlib.closing(self.connect()) as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS devices (
                    device_id TEXT PRIMARY KEY,
                    hostname TEXT NOT NULL UNIQUE,
                    wireguard_public_key TEXT NOT NULL UNIQUE,
                    vpn_address TEXT NOT NULL UNIQUE,
                    enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    revoked_at TEXT
                );

                CREATE TABLE IF NOT EXISTS enrollment_tokens (
                    token_hash TEXT PRIMARY KEY,
                    device_id TEXT,
                    created_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    consumed_at TEXT
                );

                CREATE INDEX IF NOT EXISTS idx_devices_enabled
                    ON devices(enabled);
                CREATE INDEX IF NOT EXISTS idx_tokens_device
                    ON enrollment_tokens(device_id);
                """
            )

    @contextlib.contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        conn = self.connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def create_token(
        self,
        *,
        device_id: str | None = None,
        ttl_seconds: int = 3600,
        token: str | None = None,
        now: dt.datetime | None = None,
    ) -> tuple[str, dt.datetime]:
        if device_id is not None:
            validate_device_id(device_id)
        if ttl_seconds < 1 or ttl_seconds > 7 * 24 * 3600:
            raise ValueError("ttl_seconds must be between 1 and 604800")
        token = token or secrets.token_urlsafe(32)
        if len(token) < 20:
            raise ValueError("enrollment token must contain at least 20 characters")
        now = now or utc_now()
        expires = now + dt.timedelta(seconds=ttl_seconds)
        self.initialize()
        with contextlib.closing(self.connect()) as conn:
            conn.execute(
                """
                INSERT INTO enrollment_tokens
                    (token_hash, device_id, created_at, expires_at, consumed_at)
                VALUES (?, ?, ?, ?, NULL)
                """,
                (token_hash(token), device_id, isoformat(now), isoformat(expires)),
            )
            conn.commit()
        return token, expires

    def _reserved_networks(
        self,
        conn: sqlite3.Connection,
        external: Iterable[str],
    ) -> list[ipaddress.IPv4Network]:
        reserved: list[ipaddress.IPv4Network] = [
            ipaddress.ip_network(f"{self.network.network_address}/32"),
            ipaddress.ip_network(f"{self.network.broadcast_address}/32"),
            ipaddress.ip_network(f"{self.gateway_address}/32"),
        ]
        for row in conn.execute("SELECT vpn_address FROM devices"):
            reserved.append(ipaddress.ip_network(row["vpn_address"], strict=False))
        for value in external:
            try:
                parsed = ipaddress.ip_network(value, strict=False)
            except ValueError:
                continue
            if parsed.version == 4:
                reserved.append(parsed)
        return reserved

    def allocate_address(
        self,
        conn: sqlite3.Connection,
        *,
        externally_reserved: Iterable[str] = (),
    ) -> str:
        reserved = self._reserved_networks(conn, externally_reserved)
        for candidate in self.network.hosts():
            if candidate == self.gateway_address:
                continue
            if any(candidate in item for item in reserved):
                continue
            return f"{candidate}/32"
        raise AddressPoolExhausted(f"no addresses remain in {self.network}")

    def prepare_enrollment(
        self,
        conn: sqlite3.Connection,
        *,
        device_id: str,
        public_key: str,
        token: str,
        base_domain: str,
        externally_reserved: Iterable[str] = (),
        now: dt.datetime | None = None,
    ) -> tuple[dict[str, object], str, bool]:
        device_id = validate_device_id(device_id)
        public_key = validate_public_key(public_key)
        if not DOMAIN_RE.fullmatch(base_domain):
            raise ValueError("base_domain is invalid")
        now = now or utc_now()
        digest = token_hash(token)

        token_row = conn.execute(
            "SELECT * FROM enrollment_tokens WHERE token_hash = ?",
            (digest,),
        ).fetchone()
        if token_row is None or token_row["consumed_at"] is not None:
            raise EnrollmentRejected(
                "invalid or already-used enrollment token",
                code="invalid_enrollment_token",
                status=403,
            )

        try:
            expires_at = dt.datetime.fromisoformat(token_row["expires_at"])
        except ValueError as exc:
            raise RegistryError("stored enrollment token expiry is invalid") from exc
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=dt.timezone.utc)
        if now >= expires_at:
            raise EnrollmentRejected(
                "enrollment token expired",
                code="expired_enrollment_token",
                status=403,
            )
        if token_row["device_id"] is not None and token_row["device_id"] != device_id:
            raise EnrollmentRejected(
                "enrollment token is not valid for this device",
                code="invalid_enrollment_token",
                status=403,
            )

        existing = conn.execute(
            "SELECT * FROM devices WHERE device_id = ?",
            (device_id,),
        ).fetchone()
        created = False
        if existing is not None:
            if not existing["enabled"]:
                raise EnrollmentRejected(
                    "device is revoked",
                    code="device_revoked",
                    status=409,
                )
            if existing["wireguard_public_key"] != public_key:
                raise EnrollmentRejected(
                    "device identity is already enrolled with another key",
                    code="device_key_conflict",
                    status=409,
                )
            record = dict(existing)
        else:
            key_owner = conn.execute(
                "SELECT device_id FROM devices WHERE wireguard_public_key = ?",
                (public_key,),
            ).fetchone()
            if key_owner is not None:
                raise EnrollmentRejected(
                    "WireGuard public key is already assigned to another device",
                    code="public_key_conflict",
                    status=409,
                )
            address = self.allocate_address(
                conn,
                externally_reserved=externally_reserved,
            )
            hostname = f"{device_id}.{base_domain}"
            stamp = isoformat(now)
            conn.execute(
                """
                INSERT INTO devices
                    (device_id, hostname, wireguard_public_key, vpn_address,
                     enabled, created_at, updated_at, revoked_at)
                VALUES (?, ?, ?, ?, 1, ?, ?, NULL)
                """,
                (device_id, hostname, public_key, address, stamp, stamp),
            )
            record = dict(
                conn.execute(
                    "SELECT * FROM devices WHERE device_id = ?",
                    (device_id,),
                ).fetchone()
            )
            created = True
        return record, digest, created

    def consume_token(
        self,
        conn: sqlite3.Connection,
        digest: str,
        *,
        now: dt.datetime | None = None,
    ) -> None:
        now = now or utc_now()
        cursor = conn.execute(
            """
            UPDATE enrollment_tokens
               SET consumed_at = ?
             WHERE token_hash = ? AND consumed_at IS NULL
            """,
            (isoformat(now), digest),
        )
        if cursor.rowcount != 1:
            raise EnrollmentRejected(
                "invalid or already-used enrollment token",
                code="invalid_enrollment_token",
                status=403,
            )

    def get_device(self, device_id: str) -> dict[str, object] | None:
        validate_device_id(device_id)
        self.initialize()
        with contextlib.closing(self.connect()) as conn:
            row = conn.execute(
                "SELECT * FROM devices WHERE device_id = ?",
                (device_id,),
            ).fetchone()
        return dict(row) if row else None

    def revoke(self, device_id: str, *, now: dt.datetime | None = None) -> dict[str, object]:
        validate_device_id(device_id)
        now = now or utc_now()
        self.initialize()
        with self.transaction() as conn:
            row = conn.execute(
                "SELECT * FROM devices WHERE device_id = ?",
                (device_id,),
            ).fetchone()
            if row is None:
                raise RegistryError(f"unknown device: {device_id}")
            stamp = isoformat(now)
            conn.execute(
                """
                UPDATE devices
                   SET enabled = 0, updated_at = ?, revoked_at = ?
                 WHERE device_id = ?
                """,
                (stamp, stamp, device_id),
            )
            updated = conn.execute(
                "SELECT * FROM devices WHERE device_id = ?",
                (device_id,),
            ).fetchone()
        return dict(updated)

    def list_devices(self) -> list[dict[str, object]]:
        self.initialize()
        with contextlib.closing(self.connect()) as conn:
            rows = conn.execute("SELECT * FROM devices ORDER BY device_id").fetchall()
        return [dict(row) for row in rows]
