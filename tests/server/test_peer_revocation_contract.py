#!/usr/bin/env python3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from gway_wireguard.admin_ops import AdminSettings, revoke_device
from gway_wireguard.peer_manager import PeerManager
from gway_wireguard.registry import Registry

KEY_MANUAL = "M" * 43 + "="
KEY_A = "A" * 43 + "="
KEY_B = "B" * 43 + "="


class PeerRevocationContractTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        base = Path(self.tmp.name)
        self.db = base / "registry.sqlite3"
        self.config = base / "gway.conf"
        self.hosts = base / "hosts"
        self.config.write_text(
            "[Interface]\n"
            "Address = 10.90.0.1/24\n"
            "PrivateKey = private\n\n"
            "[Peer]\n"
            f"PublicKey = {KEY_MANUAL}\n"
            "AllowedIPs = 10.90.0.2/32\n"
        )
        self.hosts.write_text("127.0.0.1 localhost\n")
        self.settings = AdminSettings(
            db_path=self.db,
            wg_config=self.config,
            wg_interface="gway",
            wg_bin="wg",
            wg_network="10.90.0.0/24",
            gateway_address="10.90.0.1",
            hosts_path=self.hosts,
            apply_runtime=False,
        )
        self.registry = Registry(self.db)
        self.registry.initialize()
        self.peers = PeerManager(self.config, apply_runtime=False)

    def tearDown(self):
        self.tmp.cleanup()

    def _enroll(self, device: str, key: str) -> dict[str, object]:
        token, _ = self.registry.create_token(device_id=device)
        with self.registry.transaction() as conn:
            record, digest, _created = self.registry.prepare_enrollment(
                conn,
                device_id=device,
                public_key=key,
                token=token,
                base_domain="arthexis.com",
                externally_reserved=self.peers.reserved_networks(),
            )
            self.registry.consume_token(conn, digest)
        self.peers.ensure_peer(
            str(record["device_id"]),
            str(record["wireguard_public_key"]),
            str(record["vpn_address"]),
        )
        return record

    def _revoke(self, device: str) -> dict[str, object]:
        with patch.dict("os.environ", {"GWAY_DNS_PROVIDER": ""}, clear=False):
            return revoke_device(device, settings=self.settings)

    def test_multiple_managed_peers_coexist_with_unmanaged_peer(self):
        first = self._enroll("gway-004", KEY_A)
        second = self._enroll("gway-005", KEY_B)

        text = self.config.read_text()
        self.assertIn(KEY_MANUAL, text)
        self.assertIn(KEY_A, text)
        self.assertIn(KEY_B, text)
        self.assertEqual(first["vpn_address"], "10.90.0.3/32")
        self.assertEqual(second["vpn_address"], "10.90.0.4/32")
        self.assertEqual(len(self.peers.managed_peers()), 2)

    def test_revoke_one_device_preserves_other_managed_and_unmanaged_peers(self):
        first = self._enroll("gway-004", KEY_A)
        second = self._enroll("gway-005", KEY_B)

        result = self._revoke("gway-004")
        self.assertTrue(result["revoked"])
        self.assertFalse(result["already_revoked"])

        text = self.config.read_text()
        self.assertIn(KEY_MANUAL, text)
        self.assertNotIn(KEY_A, text)
        self.assertIn(KEY_B, text)
        self.assertNotIn("managed peer: gway-004", text)
        self.assertIn("managed peer: gway-005", text)

        revoked = self.registry.get_device("gway-004")
        active = self.registry.get_device("gway-005")
        self.assertIsNotNone(revoked)
        self.assertIsNotNone(active)
        assert revoked is not None
        assert active is not None
        self.assertEqual(revoked["enabled"], 0)
        self.assertEqual(active["enabled"], 1)
        self.assertEqual(active["vpn_address"], second["vpn_address"])
        self.assertEqual(first["vpn_address"], "10.90.0.3/32")

    def test_revoke_is_idempotent(self):
        self._enroll("gway-004", KEY_A)

        first = self._revoke("gway-004")
        second = self._revoke("gway-004")

        self.assertFalse(first["already_revoked"])
        self.assertTrue(second["already_revoked"])
        self.assertNotIn(KEY_A, self.config.read_text())
        record = self.registry.get_device("gway-004")
        self.assertIsNotNone(record)
        assert record is not None
        self.assertEqual(record["enabled"], 0)


if __name__ == "__main__":
    unittest.main()
