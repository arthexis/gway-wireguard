#!/usr/bin/env python3
"""Authenticated enrollment API for gway-wireguard.

The service binds to loopback by default and is intended to sit behind an HTTPS
reverse proxy. It refuses to serve cleartext HTTP on a non-loopback address.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import ssl
import sys
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from gway_wireguard.dns import (
    DNSConfigurationError,
    DNSManager,
    DNSMutation,
    DNSProviderError,
    DNSSettings,
)
from hosts_manager import HostsManager, HostsManagerError
from peer_manager import PeerManager, PeerManagerError
from registry import (
    AddressPoolExhausted,
    EnrollmentRejected,
    Registry,
    RegistryError,
    validate_public_key,
)

MAX_REQUEST_BYTES = 16 * 1024
DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$"
)
ENDPOINT_RE = re.compile(r"^[A-Za-z0-9.-]+:[0-9]{1,5}$")


@dataclass(frozen=True)
class ServerConfig:
    db_path: Path
    wg_config: Path
    wg_interface: str
    wg_bin: str
    wg_network: str
    gateway_address: str
    gateway_endpoint: str
    gateway_public_key_path: Path
    base_domain: str
    hosts_path: Path
    bind_host: str
    bind_port: int
    tls_cert: Path | None = None
    tls_key: Path | None = None
    apply_runtime: bool = True

    @classmethod
    def from_env(cls) -> "ServerConfig":
        cert = os.environ.get("GWAY_TLS_CERT", "")
        key = os.environ.get("GWAY_TLS_KEY", "")
        return cls(
            db_path=Path(
                os.environ.get(
                    "GWAY_REGISTRY_DB",
                    "/var/lib/gway-wireguard/registry.sqlite3",
                )
            ),
            wg_config=Path(
                os.environ.get(
                    "GWAY_WG_CONFIG",
                    "/etc/wireguard/gway.conf",
                )
            ),
            wg_interface=os.environ.get("GWAY_WG_INTERFACE", "gway"),
            wg_bin=os.environ.get("GWAY_WG_BIN", "wg"),
            wg_network=os.environ.get("GWAY_WG_NETWORK", "10.90.0.0/24"),
            gateway_address=os.environ.get("GWAY_GATEWAY_ADDRESS", "10.90.0.1"),
            gateway_endpoint=os.environ.get(
                "GWAY_GATEWAY_ENDPOINT",
                "54.161.177.151:51820",
            ),
            gateway_public_key_path=Path(
                os.environ.get(
                    "GWAY_GATEWAY_PUBLIC_KEY",
                    "/etc/gway-wireguard/server.pub",
                )
            ),
            base_domain=os.environ.get("GWAY_BASE_DOMAIN", "arthexis.com"),
            hosts_path=Path(os.environ.get("GWAY_HOSTS_FILE", "/etc/hosts")),
            bind_host=os.environ.get("GWAY_ENROLL_BIND", "127.0.0.1"),
            bind_port=int(os.environ.get("GWAY_ENROLL_PORT", "8787")),
            tls_cert=Path(cert) if cert else None,
            tls_key=Path(key) if key else None,
            apply_runtime=os.environ.get("GWAY_APPLY_RUNTIME", "1") != "0",
        )

    def validate(self) -> None:
        network = ipaddress.ip_network(self.wg_network, strict=True)
        gateway = ipaddress.ip_address(self.gateway_address)
        if network.version != 4 or gateway.version != 4 or gateway not in network:
            raise ValueError("invalid WireGuard network/gateway address")
        if not DOMAIN_RE.fullmatch(self.base_domain):
            raise ValueError("invalid GWAY_BASE_DOMAIN")
        if not ENDPOINT_RE.fullmatch(self.gateway_endpoint):
            raise ValueError("invalid GWAY_GATEWAY_ENDPOINT")
        port = int(self.gateway_endpoint.rsplit(":", 1)[1])
        if port < 1 or port > 65535:
            raise ValueError("invalid WireGuard endpoint port")
        if not self.hosts_path.is_absolute():
            raise ValueError("GWAY_HOSTS_FILE must be an absolute path")
        if self.bind_port < 1 or self.bind_port > 65535:
            raise ValueError("invalid enrollment bind port")
        if bool(self.tls_cert) != bool(self.tls_key):
            raise ValueError("GWAY_TLS_CERT and GWAY_TLS_KEY must be set together")


class EnrollmentService:
    def __init__(
        self,
        config: ServerConfig,
        *,
        dns_manager: DNSManager | None = None,
    ) -> None:
        config.validate()
        self.config = config
        self.registry = Registry(
            config.db_path,
            network=config.wg_network,
            gateway_address=config.gateway_address,
        )
        self.registry.initialize()
        self.peers = PeerManager(
            config.wg_config,
            interface=config.wg_interface,
            wg_bin=config.wg_bin,
            apply_runtime=config.apply_runtime,
        )
        self.hosts = HostsManager(config.hosts_path)

        if dns_manager is not None:
            self.dns = dns_manager
        else:
            dns_settings = DNSSettings.from_env()
            self.dns = DNSManager(dns_settings) if dns_settings.enabled else None
        if self.dns is not None and self.dns.settings.base_domain != config.base_domain:
            raise DNSConfigurationError(
                "DNS base domain must match enrollment GWAY_BASE_DOMAIN"
            )

    def _gateway_public_key(self) -> str:
        try:
            key = self.config.gateway_public_key_path.read_text(
                encoding="utf-8"
            ).strip()
        except OSError as exc:
            raise RegistryError("gateway public key is unavailable") from exc
        try:
            return validate_public_key(key)
        except EnrollmentRejected as exc:
            raise RegistryError("gateway public key is invalid") from exc

    def enroll(self, payload: dict[str, Any]) -> dict[str, Any]:
        allowed_fields = {"device_id", "public_key", "token"}
        if not isinstance(payload, dict) or set(payload) - allowed_fields:
            raise EnrollmentRejected(
                "request contains unsupported fields",
                code="invalid_request",
                status=400,
            )
        for required in allowed_fields:
            if not isinstance(payload.get(required), str) or not payload[required]:
                raise EnrollmentRejected(
                    f"missing {required}",
                    code="invalid_request",
                    status=400,
                )

        gateway_public_key = self._gateway_public_key()
        gateway_ip = str(ipaddress.ip_address(self.config.gateway_address))
        gateway_allowed = f"{gateway_ip}/32"
        externally_reserved = self.peers.reserved_networks()

        created = False
        record: dict[str, Any] | None = None
        dns_mutation: DNSMutation | None = None
        try:
            with self.registry.transaction() as conn:
                record, digest, created = self.registry.prepare_enrollment(
                    conn,
                    device_id=payload["device_id"],
                    public_key=payload["public_key"],
                    token=payload["token"],
                    base_domain=self.config.base_domain,
                    externally_reserved=externally_reserved,
                )
                self.peers.ensure_peer(
                    str(record["device_id"]),
                    str(record["wireguard_public_key"]),
                    str(record["vpn_address"]),
                )
                devices = [
                    dict(row)
                    for row in conn.execute(
                        "SELECT * FROM devices ORDER BY device_id"
                    ).fetchall()
                ]
                self.hosts.sync(devices)
                if self.dns is not None:
                    dns_mutation = self.dns.ensure_record(
                        str(record["hostname"]),
                        "A",
                        self.dns.settings.public_gateway_ip,
                    )
                self.registry.consume_token(conn, digest)
        except Exception:
            # DNS is an external side effect, so restore its previous record set
            # before rolling back the local enrollment state.
            if dns_mutation is not None and self.dns is not None:
                try:
                    self.dns.restore(dns_mutation)
                except Exception:
                    pass

            # A newly inserted registry row rolls back with the DB transaction.
            # If peer application already succeeded, remove only that newly
            # created managed peer. Never remove a pre-existing valid device.
            if created and record is not None:
                try:
                    self.peers.remove_peer(
                        str(record["device_id"]),
                        str(record["wireguard_public_key"]),
                    )
                except Exception:
                    pass
            try:
                self.hosts.sync(self.registry.list_devices())
            except Exception:
                pass
            raise

        assert record is not None
        return {
            "version": 1,
            "device_id": record["device_id"],
            "hostname": record["hostname"],
            "vpn_address": record["vpn_address"],
            "gateway_address": gateway_ip,
            "gateway_endpoint": self.config.gateway_endpoint,
            "gateway_public_key": gateway_public_key,
            "allowed_ips": [gateway_allowed],
        }


class EnrollmentHandler(BaseHTTPRequestHandler):
    server_version = "gway-wireguard-enroll/1"
    protocol_version = "HTTP/1.1"

    @property
    def service(self) -> EnrollmentService:
        return self.server.enrollment_service  # type: ignore[attr-defined]

    def _send_json(self, status: int, payload: dict[str, Any]) -> None:
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        if self.path == "/health":
            self._send_json(200, {"status": "ok", "version": 1})
        else:
            self._send_json(404, {"error": "not_found"})

    def do_POST(self) -> None:
        if self.path != "/v1/enroll":
            self._send_json(404, {"error": "not_found"})
            return
        content_type = self.headers.get("Content-Type", "")
        if not content_type.lower().startswith("application/json"):
            self._send_json(
                415,
                {"error": "unsupported_media_type", "message": "application/json required"},
            )
            return
        try:
            length = int(self.headers.get("Content-Length", ""))
        except ValueError:
            length = -1
        if length < 1 or length > MAX_REQUEST_BYTES:
            self._send_json(
                413,
                {"error": "invalid_request_size", "message": "invalid request size"},
            )
            return
        raw = self.rfile.read(length)
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            self._send_json(
                400,
                {"error": "invalid_json", "message": "invalid JSON request"},
            )
            return

        try:
            response = self.service.enroll(payload)
        except EnrollmentRejected as exc:
            self._send_json(exc.status, {"error": exc.code, "message": str(exc)})
        except AddressPoolExhausted:
            self._send_json(
                503,
                {"error": "address_pool_exhausted", "message": "VPN address pool exhausted"},
            )
        except (
            RegistryError,
            PeerManagerError,
            HostsManagerError,
            DNSConfigurationError,
            DNSProviderError,
            OSError,
            ValueError,
        ):
            self._send_json(
                500,
                {"error": "server_error", "message": "enrollment service error"},
            )
        else:
            self._send_json(200, response)

    def log_message(self, fmt: str, *args: object) -> None:
        sys.stderr.write(
            "%s - - [%s] %s\n"
            % (self.address_string(), self.log_date_time_string(), fmt % args)
        )


def _is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def serve(config: ServerConfig) -> None:
    config.validate()
    use_tls = config.tls_cert is not None and config.tls_key is not None
    if not use_tls and not _is_loopback(config.bind_host):
        raise SystemExit(
            "refusing cleartext enrollment service on a non-loopback address; "
            "bind to loopback behind HTTPS or configure GWAY_TLS_CERT/GWAY_TLS_KEY"
        )

    service = EnrollmentService(config)
    server = ThreadingHTTPServer((config.bind_host, config.bind_port), EnrollmentHandler)
    server.enrollment_service = service  # type: ignore[attr-defined]

    if use_tls:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(
            certfile=str(config.tls_cert),
            keyfile=str(config.tls_key),
        )
        server.socket = context.wrap_socket(server.socket, server_side=True)

    scheme = "https" if use_tls else "http"
    print(
        f"gway-wireguard enrollment service listening on "
        f"{scheme}://{config.bind_host}:{config.bind_port}",
        flush=True,
    )
    server.serve_forever()


def main() -> int:
    parser = argparse.ArgumentParser(description="gway-wireguard enrollment service")
    parser.add_argument(
        "command",
        choices=("serve", "check"),
        nargs="?",
        default="serve",
    )
    args = parser.parse_args()
    config = ServerConfig.from_env()
    config.validate()
    if args.command == "check":
        Registry(
            config.db_path,
            network=config.wg_network,
            gateway_address=config.gateway_address,
        )
        dns_settings = DNSSettings.from_env()
        if dns_settings.enabled:
            DNSManager(dns_settings)
        print("server configuration valid")
        return 0
    serve(config)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
