#!/usr/bin/env python3
"""Non-destructive WireGuard peer management for gway-wireguard."""

from __future__ import annotations

import os
import re
import subprocess
import tempfile
from pathlib import Path

from registry import validate_device_id, validate_public_key

BEGIN_PREFIX = "# BEGIN gway-wireguard managed peer: "
END_PREFIX = "# END gway-wireguard managed peer: "


class PeerManagerError(RuntimeError):
    pass


def _validate_address(address: str) -> str:
    import ipaddress

    try:
        parsed = ipaddress.ip_network(address, strict=False)
    except ValueError as exc:
        raise PeerManagerError(f"invalid peer address: {address}") from exc
    if parsed.version != 4 or parsed.prefixlen != 32:
        raise PeerManagerError("peer address must be an IPv4 /32")
    return f"{parsed.network_address}/32"


class PeerManager:
    def __init__(
        self,
        config_path: str | Path,
        *,
        interface: str = "gway",
        wg_bin: str = "wg",
        apply_runtime: bool = True,
    ) -> None:
        if not re.fullmatch(r"[A-Za-z0-9_.=-]{1,15}", interface):
            raise ValueError("invalid WireGuard interface name")
        self.config_path = Path(config_path)
        self.interface = interface
        self.wg_bin = wg_bin
        self.apply_runtime = apply_runtime

    def _read(self) -> str:
        if not self.config_path.exists():
            raise PeerManagerError(
                f"WireGuard config does not exist: {self.config_path}"
            )
        return self.config_path.read_text(encoding="utf-8")

    @staticmethod
    def _strip_managed_block(text: str, device_id: str) -> tuple[str, bool]:
        begin = f"{BEGIN_PREFIX}{device_id}"
        end = f"{END_PREFIX}{device_id}"
        lines = text.splitlines()
        output: list[str] = []
        inside = False
        found = False
        for line in lines:
            if line == begin:
                if inside:
                    raise PeerManagerError("nested managed peer markers")
                inside = True
                found = True
                continue
            if line == end:
                if not inside:
                    raise PeerManagerError("orphan managed peer end marker")
                inside = False
                continue
            if not inside:
                output.append(line)
        if inside:
            raise PeerManagerError(f"unterminated managed peer block for {device_id}")
        normalized = "\n".join(output).rstrip()
        return (normalized + "\n" if normalized else ""), found

    def reserved_networks(self) -> list[str]:
        """Return peer AllowedIPs already present, including unmanaged peers."""
        text = self._read()
        section = ""
        reserved: list[str] = []
        for raw_line in text.splitlines():
            line = raw_line.strip()
            if line.startswith("[") and line.endswith("]"):
                section = line
                continue
            if section != "[Peer]" or "=" not in line:
                continue
            key, value = (part.strip() for part in line.split("=", 1))
            if key != "AllowedIPs":
                continue
            for item in value.split(","):
                item = item.strip()
                if item:
                    reserved.append(item)
        return reserved

    def _atomic_write(self, content: str) -> None:
        self.config_path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp_name = tempfile.mkstemp(
            prefix=f".{self.config_path.name}.",
            dir=self.config_path.parent,
            text=True,
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(content)
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(tmp_name, 0o600)
            os.replace(tmp_name, self.config_path)
        finally:
            try:
                os.unlink(tmp_name)
            except FileNotFoundError:
                pass

    def _runtime_set(self, public_key: str, address: str) -> None:
        if not self.apply_runtime:
            return
        try:
            subprocess.run(
                [self.wg_bin, "show", self.interface],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                text=True,
            )
            subprocess.run(
                [
                    self.wg_bin,
                    "set",
                    self.interface,
                    "peer",
                    public_key,
                    "allowed-ips",
                    address,
                ],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                text=True,
            )
        except (OSError, subprocess.CalledProcessError) as exc:
            detail = getattr(exc, "stderr", "") or str(exc)
            raise PeerManagerError(
                f"failed to update live WireGuard peer: {detail.strip()}"
            ) from exc

    def _runtime_remove(self, public_key: str) -> None:
        if not self.apply_runtime:
            return
        try:
            subprocess.run(
                [
                    self.wg_bin,
                    "set",
                    self.interface,
                    "peer",
                    public_key,
                    "remove",
                ],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                text=True,
            )
        except (OSError, subprocess.CalledProcessError) as exc:
            detail = getattr(exc, "stderr", "") or str(exc)
            raise PeerManagerError(
                f"failed to remove live WireGuard peer: {detail.strip()}"
            ) from exc

    def ensure_peer(self, device_id: str, public_key: str, address: str) -> None:
        device_id = validate_device_id(device_id)
        public_key = validate_public_key(public_key)
        address = _validate_address(address)

        current = self._read()
        base, _ = self._strip_managed_block(current, device_id)
        # Do not silently claim a pre-Phase-3/manual peer or another device's
        # managed peer just because its public key matches this request.
        for raw_line in base.splitlines():
            line = raw_line.strip()
            if line.startswith("PublicKey") and "=" in line:
                _, existing_key = (part.strip() for part in line.split("=", 1))
                if existing_key == public_key:
                    raise PeerManagerError(
                        "WireGuard public key already exists in an unmanaged or "
                        "different managed peer"
                    )
        block = (
            f"{BEGIN_PREFIX}{device_id}\n"
            "[Peer]\n"
            f"# Device = {device_id}\n"
            f"PublicKey = {public_key}\n"
            f"AllowedIPs = {address}\n"
            f"{END_PREFIX}{device_id}\n"
        )
        desired = base.rstrip() + "\n\n" + block if base.strip() else block

        # Apply runtime state first. If it fails, persistent configuration remains
        # untouched and the enrollment transaction can safely roll back.
        self._runtime_set(public_key, address)
        if desired != current:
            self._atomic_write(desired)

    def remove_peer(self, device_id: str, public_key: str) -> bool:
        device_id = validate_device_id(device_id)
        public_key = validate_public_key(public_key)
        current = self._read()
        desired, found = self._strip_managed_block(current, device_id)

        # Remove runtime access before committing persistent revocation.
        self._runtime_remove(public_key)
        if found and desired != current:
            self._atomic_write(desired)
        return found
