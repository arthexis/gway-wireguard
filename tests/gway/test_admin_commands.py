from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from gway_wire.admin_ops import AdminSettings
from gway_wire.gway.server import token
from gway_wire.gway.server.device import list as device_list
from gway_wire.gway.server.device import revoke
from gway_wire.gway.server.hosts import sync
from gway_wire.peer_manager import PeerManager
from gway_wire.registry import Registry

KEY_DEVICE = "D" * 43 + "="


class GwayAdminCommandTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.db = root / "registry.sqlite3"
        self.wg_config = root / "gway.conf"
        self.hosts = root / "hosts"
        self.wg_config.write_text(
            "[Interface]\nAddress = 10.90.0.1/24\nPrivateKey = private\n",
            encoding="utf-8",
        )
        self.hosts.write_text("127.0.0.1\tlocalhost\n", encoding="utf-8")
        self.settings = AdminSettings(
            db_path=self.db,
            wg_config=self.wg_config,
            wg_interface="gway",
            wg_bin="wg",
            wg_network="10.90.0.0/24",
            gateway_address="10.90.0.1",
            hosts_path=self.hosts,
            apply_runtime=False,
        )

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _enroll_fixture(self) -> None:
        registry = Registry(self.db)
        enrollment_token, _ = registry.create_token(
            device_id="gway-004", token="t" * 24
        )
        with registry.transaction() as conn:
            record, digest, _created = registry.prepare_enrollment(
                conn,
                device_id="gway-004",
                public_key=KEY_DEVICE,
                token=enrollment_token,
                base_domain="arthexis.com",
            )
            PeerManager(self.wg_config, apply_runtime=False).ensure_peer(
                "gway-004",
                KEY_DEVICE,
                str(record["vpn_address"]),
            )
            registry.consume_token(conn, digest)

    def test_server_token_uses_shared_registry(self) -> None:
        with patch.object(AdminSettings, "from_env", return_value=self.settings):
            result = token(device="gway-004", ttl=120)

        self.assertEqual(result["device"], "gway-004")
        self.assertTrue(result["token"])
        self.assertTrue(self.db.exists())

    def test_server_device_hosts_and_revoke_share_domain_state(self) -> None:
        self._enroll_fixture()

        with patch.object(AdminSettings, "from_env", return_value=self.settings):
            rows = device_list()
            synced = sync()
            revoked = revoke("gway-004")

        self.assertEqual(rows[0]["device_id"], "gway-004")
        self.assertTrue(synced["changed"])
        self.assertTrue(revoked["revoked"])
        self.assertNotIn(KEY_DEVICE, self.wg_config.read_text(encoding="utf-8"))
        self.assertNotIn("10.90.0.2\tgway-004", self.hosts.read_text(encoding="utf-8"))

        record = Registry(self.db).get_device("gway-004")
        self.assertIsNotNone(record)
        assert record is not None
        self.assertFalse(record["enabled"])


if __name__ == "__main__":
    unittest.main()
