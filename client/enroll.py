#!/usr/bin/env python3
"""HTTPS enrollment client used by the root gway-wireguard installer."""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request

DEVICE_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$")
PUBLIC_KEY_RE = re.compile(r"^[A-Za-z0-9+/]{43}=$")
ENDPOINT_RE = re.compile(r"^[A-Za-z0-9.-]+:[0-9]{1,5}$")


class EnrollmentClientError(RuntimeError):
    pass


def validate_url(url: str) -> str:
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != "https":
        raise EnrollmentClientError("enrollment URL must use HTTPS")
    if not parsed.hostname or parsed.username or parsed.password:
        raise EnrollmentClientError("invalid enrollment URL")
    if parsed.fragment:
        raise EnrollmentClientError("enrollment URL must not contain a fragment")
    return url


def validate_request(device_id: str, public_key: str) -> None:
    if not DEVICE_RE.fullmatch(device_id):
        raise EnrollmentClientError("invalid device ID")
    if not PUBLIC_KEY_RE.fullmatch(public_key):
        raise EnrollmentClientError("invalid device WireGuard public key")


def _validate_endpoint(value: object) -> str:
    if not isinstance(value, str) or not ENDPOINT_RE.fullmatch(value):
        raise EnrollmentClientError("invalid gateway endpoint in enrollment response")
    port = int(value.rsplit(":", 1)[1])
    if port < 1 or port > 65535:
        raise EnrollmentClientError("invalid gateway endpoint port")
    return value


def validate_response(payload: object, expected_device_id: str) -> dict[str, str]:
    if not isinstance(payload, dict):
        raise EnrollmentClientError("enrollment response is not a JSON object")
    if payload.get("version") != 1:
        raise EnrollmentClientError("unsupported enrollment response version")
    if payload.get("device_id") != expected_device_id:
        raise EnrollmentClientError("enrollment response device ID mismatch")

    hostname = payload.get("hostname")
    if not isinstance(hostname, str) or not hostname.startswith(
        expected_device_id + "."
    ):
        raise EnrollmentClientError("invalid hostname in enrollment response")

    gateway_public_key = payload.get("gateway_public_key")
    if not isinstance(gateway_public_key, str) or not PUBLIC_KEY_RE.fullmatch(
        gateway_public_key
    ):
        raise EnrollmentClientError(
            "invalid gateway WireGuard public key in enrollment response"
        )

    vpn_address = payload.get("vpn_address")
    if not isinstance(vpn_address, str):
        raise EnrollmentClientError("missing VPN address in enrollment response")
    try:
        vpn_network = ipaddress.ip_network(vpn_address, strict=False)
    except ValueError as exc:
        raise EnrollmentClientError(
            "invalid VPN address in enrollment response"
        ) from exc
    if vpn_network.version != 4 or vpn_network.prefixlen != 32:
        raise EnrollmentClientError("enrolled VPN address must be an IPv4 /32")

    gateway_address = payload.get("gateway_address")
    if not isinstance(gateway_address, str):
        raise EnrollmentClientError("missing gateway address in enrollment response")
    try:
        gateway_ip = ipaddress.ip_address(gateway_address)
    except ValueError as exc:
        raise EnrollmentClientError(
            "invalid gateway address in enrollment response"
        ) from exc
    if gateway_ip.version != 4:
        raise EnrollmentClientError("gateway address must be IPv4")

    allowed_ips = payload.get("allowed_ips")
    expected_allowed = f"{gateway_ip}/32"
    if allowed_ips != [expected_allowed]:
        raise EnrollmentClientError(
            "enrollment response must keep AllowedIPs restricted to the gateway /32"
        )

    return {
        "gateway_public_key": gateway_public_key,
        "vpn_address": f"{vpn_network.network_address}/32",
        "gateway_endpoint": _validate_endpoint(payload.get("gateway_endpoint")),
        "gateway_allowed_ip": expected_allowed,
        "hostname": hostname,
    }


def enroll(
    *,
    url: str,
    device_id: str,
    public_key: str,
    token: str,
    timeout: int = 15,
) -> dict[str, str]:
    validate_url(url)
    validate_request(device_id, public_key)
    if not token:
        raise EnrollmentClientError("missing enrollment token")

    body = json.dumps(
        {
            "device_id": device_id,
            "public_key": public_key,
            "token": token,
        },
        separators=(",", ":"),
    ).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "gway-wireguard-client/1",
        },
    )
    context = ssl.create_default_context()
    try:
        with urllib.request.urlopen(
            request,
            timeout=timeout,
            context=context,
        ) as response:
            raw = response.read(64 * 1024 + 1)
    except urllib.error.HTTPError as exc:
        try:
            error_payload = json.loads(exc.read(16 * 1024).decode("utf-8"))
            message = error_payload.get("message") or error_payload.get("error")
        except Exception:
            message = None
        raise EnrollmentClientError(
            f"enrollment rejected by server ({exc.code})"
            + (f": {message}" if message else "")
        ) from exc
    except (urllib.error.URLError, TimeoutError, ssl.SSLError) as exc:
        raise EnrollmentClientError(f"enrollment request failed: {exc}") from exc

    if len(raw) > 64 * 1024:
        raise EnrollmentClientError("enrollment response is too large")
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise EnrollmentClientError("invalid JSON enrollment response") from exc
    return validate_response(payload, device_id)


def main() -> int:
    parser = argparse.ArgumentParser(description="Enroll a gway-wireguard client")
    parser.add_argument("--url", required=True)
    parser.add_argument("--device-id", required=True)
    parser.add_argument("--public-key", required=True)
    parser.add_argument(
        "--check",
        action="store_true",
        help="validate arguments without making a network request",
    )
    args = parser.parse_args()
    try:
        validate_url(args.url)
        validate_request(args.device_id, args.public_key)
        if args.check:
            print("enrollment client configuration valid")
            return 0

        token = os.environ.get("GWAY_ENROLL_TOKEN", "")
        result = enroll(
            url=args.url,
            device_id=args.device_id,
            public_key=args.public_key,
            token=token,
        )
        print(result["gateway_public_key"])
        print(result["vpn_address"])
        print(result["gateway_endpoint"])
        print(result["gateway_allowed_ip"])
        print(result["hostname"])
        return 0
    except EnrollmentClientError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
