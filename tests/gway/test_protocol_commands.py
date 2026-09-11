from __future__ import annotations

import inspect
import unittest

import gway_wire.gway as root
from gway_wire.gway import client, server
from gway_wire.gway.server import dns, hosts


PUBLIC_COMMANDS = (
    root.status,
    root.sync,
    client.enroll,
    client.sync,
    client.status,
    server.deploy,
    server.status,
    server.check,
    server.validate,
    server.token,
    server.devices,
    server.revoke,
    dns.status,
    dns.sync,
    dns.ensure,
    dns.delete,
    hosts.sync,
)


class ProtocolCommandTests(unittest.TestCase):
    def test_every_public_command_defaults_protocol_to_wireguard(self) -> None:
        for command in PUBLIC_COMMANDS:
            with self.subTest(command=f"{command.__module__}.{command.__name__}"):
                parameter = inspect.signature(command).parameters.get("protocol")
                self.assertIsNotNone(parameter)
                self.assertEqual(parameter.default, "wireguard")

    def test_unknown_protocol_is_rejected_before_topology_work(self) -> None:
        with self.assertRaisesRegex(ValueError, "unsupported protocol"):
            root.status(protocol="uart")


if __name__ == "__main__":
    unittest.main()
