#!/usr/bin/env python3
"""Compatibility administrative CLI for gway-wireguard enrollment."""

from __future__ import annotations

import argparse
import sys

from enroll_api import ServerConfig
from gway_wireguard.admin_ops import (
    AdminSettings,
    create_enrollment_token,
    list_devices,
    revoke_device,
    sync_hosts,
)
from gway_wireguard.hosts_manager import HostsManagerError
from gway_wireguard.peer_manager import PeerManagerError
from gway_wireguard.registry import Registry, RegistryError


def _settings(config: ServerConfig) -> AdminSettings:
    return AdminSettings(
        db_path=config.db_path,
        wg_config=config.wg_config,
        wg_interface=config.wg_interface,
        wg_bin=config.wg_bin,
        wg_network=config.wg_network,
        gateway_address=config.gateway_address,
        hosts_path=config.hosts_path,
        apply_runtime=config.apply_runtime,
    )


def cmd_init(config: ServerConfig, _args: argparse.Namespace) -> int:
    Registry(
        config.db_path,
        network=config.wg_network,
        gateway_address=config.gateway_address,
    ).initialize()
    print(f"Registry initialized: {config.db_path}")
    return 0


def cmd_token(config: ServerConfig, args: argparse.Namespace) -> int:
    result = create_enrollment_token(
        device=args.device,
        ttl=args.ttl,
        settings=_settings(config),
    )
    scope = result["device"] or "any valid device"
    print(f"Enrollment token: {result['token']}")
    print(f"Scope:            {scope}")
    print(f"Expires:          {result['expires']}")
    print("This token is shown once and is not stored in plaintext.")
    return 0


def cmd_list(config: ServerConfig, _args: argparse.Namespace) -> int:
    rows = list_devices(settings=_settings(config))
    if not rows:
        print("No enrolled devices.")
        return 0
    print("DEVICE\tVPN ADDRESS\tENABLED\tPUBLIC KEY")
    for row in rows:
        print(
            f"{row['device_id']}\t{row['vpn_address']}\t"
            f"{'yes' if row['enabled'] else 'no'}\t{row['wireguard_public_key']}"
        )
    return 0


def cmd_sync_hosts(config: ServerConfig, _args: argparse.Namespace) -> int:
    result = sync_hosts(settings=_settings(config))
    state = "updated" if result["changed"] else "already current"
    print(f"Private hostnames {state}: {result['path']}")
    return 0


def cmd_revoke(config: ServerConfig, args: argparse.Namespace) -> int:
    result = revoke_device(args.device, settings=_settings(config))
    if result.get("already_revoked"):
        print(f"{result['device']} is already revoked.")
        return 0
    if result.get("hosts_warning"):
        print(
            f"warning: revoked peer but private hostname sync failed: "
            f"{result['hosts_warning']}",
            file=sys.stderr,
        )
    print(f"Revoked {result['device']}; WireGuard peer removed.")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Manage gway-wireguard enrollment and revocation"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    init = sub.add_parser("init", help="initialize the registry")
    init.set_defaults(func=cmd_init)

    token = sub.add_parser("token", help="create a one-time enrollment token")
    token.add_argument(
        "--device",
        help="restrict the token to one device ID; omit for any one enrollment",
    )
    token.add_argument(
        "--ttl",
        type=int,
        default=3600,
        help="token lifetime in seconds (default: 3600; maximum: 604800)",
    )
    token.set_defaults(func=cmd_token)

    listing = sub.add_parser("list", help="list enrolled devices")
    listing.set_defaults(func=cmd_list)

    sync = sub.add_parser(
        "sync-hosts",
        help="regenerate private short hostnames from the registry",
    )
    sync.set_defaults(func=cmd_sync_hosts)

    revoke = sub.add_parser("revoke", help="revoke an enrolled device")
    revoke.add_argument("device")
    revoke.set_defaults(func=cmd_revoke)
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    config = ServerConfig.from_env()
    config.validate()
    try:
        return args.func(config, args)
    except (RegistryError, PeerManagerError, HostsManagerError, ValueError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
