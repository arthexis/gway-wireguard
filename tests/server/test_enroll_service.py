#!/usr/bin/env python3
import sys
import tempfile
import unittest
from pathlib import Path

SERVER = Path(__file__).resolve().parents[2] / "server"
sys.path.insert(0, str(SERVER))

from enroll_api import EnrollmentService, ServerConfig  # noqa: E402
from registry import EnrollmentRejected  # noqa: E402

KEY_GATEWAY = "G" * 43 + "="
KEY_MANUAL = "M" * 43 + "="
KEY_DEVICE = "D" * 43 + "="


class EnrollmentServiceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        base = Path(self.tmp.name)
        self.db = base / "registry.sqlite3"
        self.config_path = base / "gway.conf"
        self.gateway_key = base / "server.pub"
        self.hosts_path = base / "hosts"
        self.gateway_key.write_text(KEY_GATEWAY + "\n")
        self.hosts_path.write_text("127.0.0.1 localhost\n")
        self.config_path.write_text(
            "[Interface]\n"
            "Address = 10.90.0.1/24\n"
            "PrivateKey = private\n\n"
            "[Peer]\n"
            f"PublicKey = {KEY_MANUAL}\n"
            "AllowedIPs = 10.90.0.2/32\n"
        )
        self.config = ServerConfig(
            db_path=self.db,
            wg_config=self.config_path,
            wg_interface="gway",
            wg_bin="wg",
            wg_network="10.90.0.0/24",
            gateway_address="10.90.0.1",
            gateway_endpoint="54.161.177.151:51820",
            gateway_public_key_path=self.gateway_key,
            base_domain="arthexis.com",
            hosts_path=self.hosts_path,
            bind_host="127.0.0.1",
            bind_port=8787,
            apply_runtime=False,
        )
        self.service = EnrollmentService(self.config)

    def tearDown(self):
        self.tmp.cleanup()

    def test_enrollment_consumes_token_allocates_address_and_preserves_manual_peer(self):
        token, _ = self.service.registry.create_token(device_id="gway-004")
        response = self.service.enroll(
            {
                "device_id": "gway-004",
                "public_key": KEY_DEVICE,
                "token": token,
            }
        )
        self.assertEqual(response["vpn_address"], "10.90.0.3/32")
        self.assertEqual(response["allowed_ips"], ["10.90.0.1/32"])
        self.assertEqual(response["gateway_public_key"], KEY_GATEWAY)
        text = self.config_path.read_text()
        self.assertIn(KEY_MANUAL, text)
        self.assertIn(KEY_DEVICE, text)
        hosts = self.hosts_path.read_text()
        self.assertIn("127.0.0.1 localhost", hosts)
        self.assertIn("10.90.0.3\tgway-004", hosts)

        with self.assertRaises(EnrollmentRejected):
            self.service.enroll(
                {
                    "device_id": "gway-004",
                    "public_key": KEY_DEVICE,
                    "token": token,
                }
            )

    def test_failed_peer_application_does_not_consume_token(self):
        token, _ = self.service.registry.create_token(device_id="gway-004")
        self.config_path.unlink()
        with self.assertRaises(Exception):
            self.service.enroll(
                {
                    "device_id": "gway-004",
                    "public_key": KEY_DEVICE,
                    "token": token,
                }
            )
        self.assertNotIn("gway-004", self.hosts_path.read_text())

        self.config_path.write_text(
            "[Interface]\nAddress = 10.90.0.1/24\nPrivateKey = private\n"
        )
        response = self.service.enroll(
            {
                "device_id": "gway-004",
                "public_key": KEY_DEVICE,
                "token": token,
            }
        )
        self.assertEqual(response["vpn_address"], "10.90.0.2/32")
        self.assertIn("10.90.0.2\tgway-004", self.hosts_path.read_text())


if __name__ == "__main__":
    unittest.main()
