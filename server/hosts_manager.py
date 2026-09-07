#!/usr/bin/env python3
"""Private short-hostname management for enrolled WireGuard devices."""

from __future__ import annotations

import ipaddress
import os
import stat
import tempfile
from pathlib import Path
from typing import Iterable, Mapping

from registry import validate_device_id

BEGIN_MARKER = "# BEGIN gway-wireguard managed hosts"
END_MARKER = "# END gway-wireguard managed hosts"


class HostsManagerError(RuntimeError):
    pass


def _host_line(record: Mapping[str, object]) -> tuple[str, str] | None:
    if not record.get("enabled"):
        return None
    device_id = validate_device_id(str(record["device_id"]))
    try:
        network = ipaddress.ip_network(str(record["vpn_address"]), strict=False)
    except ValueError as exc:
        raise HostsManagerError(
            f"invalid VPN address for {device_id}: {record['vpn_address']}"
        ) from exc
    if network.version != 4 or network.prefixlen != 32:
        raise HostsManagerError(f"VPN address for {device_id} must be an IPv4 /32")
    return device_id, f"{network.network_address}\t{device_id}"


class HostsManager:
    """Maintain only gway-wireguard's delimited block in a hosts file."""

    def __init__(self, path: str | Path = "/etc/hosts") -> None:
        self.path = Path(path)

    def _read(self) -> str:
        try:
            return self.path.read_text(encoding="utf-8")
        except OSError as exc:
            raise HostsManagerError(f"cannot read hosts file: {self.path}") from exc

    @staticmethod
    def _strip_managed_block(text: str) -> str:
        output: list[str] = []
        inside = False
        seen = False
        for line in text.splitlines():
            if line == BEGIN_MARKER:
                if inside or seen:
                    raise HostsManagerError("duplicate or nested managed hosts block")
                inside = True
                seen = True
                continue
            if line == END_MARKER:
                if not inside:
                    raise HostsManagerError("orphan managed hosts end marker")
                inside = False
                continue
            if not inside:
                output.append(line)
        if inside:
            raise HostsManagerError("unterminated managed hosts block")
        normalized = "\n".join(output).rstrip()
        return normalized + "\n" if normalized else ""

    def _atomic_write(self, content: str) -> None:
        try:
            original = self.path.stat()
        except OSError as exc:
            raise HostsManagerError(f"cannot stat hosts file: {self.path}") from exc

        fd, tmp_name = tempfile.mkstemp(
            prefix=f".{self.path.name}.",
            dir=self.path.parent,
            text=True,
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                os.fchmod(handle.fileno(), stat.S_IMODE(original.st_mode))
                try:
                    os.fchown(handle.fileno(), original.st_uid, original.st_gid)
                except PermissionError:
                    pass
                handle.write(content)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp_name, self.path)
        except OSError as exc:
            raise HostsManagerError(f"cannot update hosts file: {self.path}") from exc
        finally:
            try:
                os.unlink(tmp_name)
            except FileNotFoundError:
                pass

    def sync(self, devices: Iterable[Mapping[str, object]]) -> bool:
        """Render enabled registry devices as short names; return whether changed."""
        entries: dict[str, str] = {}
        for record in devices:
            entry = _host_line(record)
            if entry is None:
                continue
            device_id, line = entry
            if device_id in entries:
                raise HostsManagerError(f"duplicate device in hosts data: {device_id}")
            entries[device_id] = line

        block_lines = [BEGIN_MARKER]
        block_lines.extend(entries[key] for key in sorted(entries))
        block_lines.append(END_MARKER)
        block = "\n".join(block_lines) + "\n"

        current = self._read()
        base = self._strip_managed_block(current)
        desired = base.rstrip() + "\n\n" + block if base.strip() else block
        if desired == current:
            return False
        self._atomic_write(desired)
        return True
