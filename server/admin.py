#!/usr/bin/env python3
"""Administrative CLI for gway-wireguard enrollment."""

from __future__ import annotations

import argparse
import sys

from enroll_api import ServerConfig
from hosts_manager import HostsManager, HostsManagerError
from peer_manager import PeerManager, PeerManagerError
from registry import Registry, RegistryError, validate_device_id


def registry_from_config(config: ServerConfig) -> Registry:
    return Registry(
        config.db_path,
        network=config.wg_network,
        gateway_address=config.gateway_address,
    )


def peer_manager_from_config(config: ServerConfig) -> PeerManager:
    return PeerManager(
        config.wg_config,
        interface=config.wg_interface,
        wg_bin=config.wg_bin,
        apply_runtime=config.apply_runtime,
    )


def hosts_manager_from_config(config: ServerConfig) -> HostsManager:
    return HostsManager(config.hosts_path)


def sync_hosts(config: ServerConfig, registry: Registry) -> bool:
    return hosts_manager_from_config(config).sync(registry.list_devices())


def cmd_init(config: ServerConfig, _args: argparse.Namespace) -> int:
    registry = registry_from_config(config)
    registry.initialize()
    print(f"Registry initialized: {config.db_path}")
    return 0


def cmd_token(config: ServerConfig, args: argparse.Namespace) -> int:
    registry = registry_from_config(config)
    token, expires = registry.create_token(
        device_id=args.device,
        ttl_seconds=args.ttl,
    )
    scope = args.device or "any valid device"
    print(f"Enrollment token: {token}")
    print(f"Scope:            {scope}")
    print(f"Expires:          {expires.isoformat(timespec='seconds')}")
    print("This token is shown once and is not stored in plaintext.")
    return 0


def cmd_list(config: ServerConfig, _args: argparse.Namespace) -> int:
    registry = registry_from_config(config)
    rows = registry.list_devices()
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
    registry = registry_from_config(config)
    changed = sync_hosts(config, registry)
    state = "updated" if changed else "already current"
    print(f"Private hostnames {state}: {config.hosts_path}")
    return 0


def cmd_revoke(config: ServerConfig, args: argparse.Namespace) -> int:
    device_id = validate_device_id(args.device)
    registry = registry_from_config(config)
    record = registry.get_device(device_id)
    if record is None:
        raise RegistryError(f"unknown device: {device_id}")
    if not record["enabled"]:
        print(f"{device_id} is already revoked.")
        return 0

    peers = peer_manager_from_config(config)
    public_key = str(record["wireguard_public_key"])
    try:
        peers.remove_peer(device_id, public_key)
        registry.revoke(device_id)
    except Exception:
        # If either persistent peer removal or the registry update fails after
        # runtime access changed, restore the known-good enrolled peer.
        try:
            peers.ensure_peer(
                device_id,
                public_key,
                str(record["vpn_address"]),
            )
        except Exception:
            pass
        raise

    # Revocation is the security boundary. If hostname cleanup fails afterward,
    # leave the peer revoked and report the stale convenience mapping rather
    # than restoring network access.
    try:
        sync_hosts(config, registry)
    except HostsManagerError as exc:
        print(f"warning: revoked peer but private hostname sync failed: {exc}", file=sys.stderr)

    print(f"Revoked {device_id}; WireGuard peer removed.")
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
