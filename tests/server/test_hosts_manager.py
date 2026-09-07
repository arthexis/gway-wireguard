#!/usr/bin/env python3
import sys
import tempfile
import unittest
from pathlib import Path

SERVER = Path(__file__).resolve().parents[2] / "server"
sys.path.insert(0, str(SERVER))

from hosts_manager import (  # noqa: E402
    BEGIN_MARKER,
    END_MARKER,
    HostsManager,
    HostsManagerError,
)


class HostsManagerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "hosts"
        self.path.write_text("127.0.0.1 localhost\n10.0.0.5 unrelated\n")
        self.manager = HostsManager(self.path)

    def tearDown(self):
        self.tmp.cleanup()

    def test_sync_preserves_unmanaged_entries_and_sorts_devices(self):
        changed = self.manager.sync(
            [
                {"device_id": "gway-010", "vpn_address": "10.90.0.10/32", "enabled": 1},
                {"device_id": "gway-002", "vpn_address": "10.90.0.2/32", "enabled": 1},
                {"device_id": "gway-003", "vpn_address": "10.90.0.3/32", "enabled": 0},
            ]
        )
        self.assertTrue(changed)
        text = self.path.read_text()
        self.assertIn("127.0.0.1 localhost", text)
        self.assertIn("10.0.0.5 unrelated", text)
        self.assertIn(BEGIN_MARKER, text)
        self.assertIn(END_MARKER, text)
        self.assertIn("10.90.0.2\tgway-002", text)
        self.assertIn("10.90.0.10\tgway-010", text)
        self.assertNotIn("gway-003", text)
        self.assertLess(text.index("gway-002"), text.index("gway-010"))
        self.assertFalse(self.manager.sync(
            [
                {"device_id": "gway-002", "vpn_address": "10.90.0.2/32", "enabled": 1},
                {"device_id": "gway-010", "vpn_address": "10.90.0.10/32", "enabled": 1},
            ]
        ))

    def test_sync_replaces_only_existing_managed_block(self):
        self.path.write_text(
            "127.0.0.1 localhost\n\n"
            f"{BEGIN_MARKER}\n"
            "10.90.0.4\tgway-004\n"
            f"{END_MARKER}\n"
            "192.0.2.10 custom\n"
        )
        self.manager.sync(
            [{"device_id": "gway-005", "vpn_address": "10.90.0.5/32", "enabled": 1}]
        )
        text = self.path.read_text()
        self.assertNotIn("gway-004", text)
        self.assertIn("10.90.0.5\tgway-005", text)
        self.assertIn("192.0.2.10 custom", text)

    def test_invalid_managed_block_is_rejected(self):
        self.path.write_text(f"127.0.0.1 localhost\n{BEGIN_MARKER}\n")
        with self.assertRaises(HostsManagerError):
            self.manager.sync([])


if __name__ == "__main__":
    unittest.main()
