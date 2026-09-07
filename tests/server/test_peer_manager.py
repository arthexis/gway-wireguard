#!/usr/bin/env python3
import sys
import tempfile
import unittest
from pathlib import Path

SERVER = Path(__file__).resolve().parents[2] / "server"
sys.path.insert(0, str(SERVER))

from peer_manager import PeerManager  # noqa: E402

KEY_MANUAL = "M" * 43 + "="
KEY_A = "A" * 43 + "="


class PeerManagerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.config = Path(self.tmp.name) / "gway.conf"
        self.manual = (
            "[Interface]\n"
            "Address = 10.90.0.1/24\n"
            "PrivateKey = private\n\n"
            "[Peer]\n"
            f"PublicKey = {KEY_MANUAL}\n"
            "AllowedIPs = 10.90.0.2/32\n"
        )
        self.config.write_text(self.manual)
        self.manager = PeerManager(self.config, apply_runtime=False)

    def tearDown(self):
        self.tmp.cleanup()

    def test_ensure_peer_preserves_manual_peer(self):
        self.manager.ensure_peer("gway-004", KEY_A, "10.90.0.4/32")
        text = self.config.read_text()
        self.assertIn(KEY_MANUAL, text)
        self.assertIn("AllowedIPs = 10.90.0.2/32", text)
        self.assertIn("# BEGIN gway-wireguard managed peer: gway-004", text)
        self.assertIn(KEY_A, text)

    def test_update_is_idempotent_and_does_not_duplicate_block(self):
        self.manager.ensure_peer("gway-004", KEY_A, "10.90.0.4/32")
        first = self.config.read_text()
        self.manager.ensure_peer("gway-004", KEY_A, "10.90.0.4/32")
        second = self.config.read_text()
        self.assertEqual(first, second)
        self.assertEqual(
            second.count("# BEGIN gway-wireguard managed peer: gway-004"),
            1,
        )

    def test_remove_managed_peer_preserves_manual_peer(self):
        self.manager.ensure_peer("gway-004", KEY_A, "10.90.0.4/32")
        self.assertTrue(self.manager.remove_peer("gway-004", KEY_A))
        text = self.config.read_text()
        self.assertIn(KEY_MANUAL, text)
        self.assertNotIn(KEY_A, text)
        self.assertNotIn("managed peer: gway-004", text)

    def test_reserved_networks_include_manual_and_managed_peers(self):
        self.manager.ensure_peer("gway-004", KEY_A, "10.90.0.4/32")
        self.assertEqual(
            self.manager.reserved_networks(),
            ["10.90.0.2/32", "10.90.0.4/32"],
        )


if __name__ == "__main__":
    unittest.main()
