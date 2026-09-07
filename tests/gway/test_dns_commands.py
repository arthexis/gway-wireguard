from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from gway_wireguard.admin_ops import AdminSettings
from gway_wireguard.dns import DNSManager, DNSRecord, DNSSettings
from gway_wireguard.gway.device import revoke
from gway_wireguard.gway.dns import delete, ensure, status, sync
from gway_wireguard.peer_manager import PeerManager
from gway_wireguard.registry import Registry

KEY_DEVICE = "D" * 43 + "="


class FakeProvider:
    def __init__(self) -> None:
        self.records: dict[tuple[str, str], list[DNSRecord]] = {}

    def get_records(self, name: str, record_type: str) -> list[DNSRecord]:
        return list(self.records.get((name, record_type), []))

    def replace_records(
        self,
        name: str,
        record_type: str,
        records: list[DNSRecord],
    ) -> None:
        self.records[(name, record_type)] = list(records)

    def delete_records(self, name: str, record_type: str) -> None:
        self.records.pop((name, record_type), None)


class GwayDNSCommandTests(unittest.TestCase):
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
        self.admin_settings = AdminSettings(
            db_path=self.db,
            wg_config=self.wg_config,
            wg_interface="gway",
            wg_bin="wg",
            wg_network="10.90.0.0/24",
            gateway_address="10.90.0.1",
            hosts_path=self.hosts,
            apply_runtime=False,
        )
        self.dns_settings = DNSSettings(
            provider="godaddy",
            base_domain="arthexis.com",
            public_gateway_ip="54.161.177.151",
            ttl=600,
            vpn_hostname="vpn.arthexis.com",
            register_hostname="register.arthexis.com",
            godaddy_key="key",
            godaddy_secret="secret",
        )
        self.provider = FakeProvider()
        self.manager = DNSManager(self.dns_settings, provider=self.provider)
        self._enroll_fixture()

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _enroll_fixture(self) -> None:
        registry = Registry(self.db)
        token, _ = registry.create_token(device_id="gway-004", token="t" * 24)
        with registry.transaction() as conn:
            record, digest, _created = registry.prepare_enrollment(
                conn,
                device_id="gway-004",
                public_key=KEY_DEVICE,
                token=token,
                base_domain="arthexis.com",
            )
            PeerManager(self.wg_config, apply_runtime=False).ensure_peer(
                "gway-004",
                KEY_DEVICE,
                str(record["vpn_address"]),
            )
            registry.consume_token(conn, digest)

    def patches(self):
        return (
            patch.object(AdminSettings, "from_env", return_value=self.admin_settings),
            patch(
                "gway_wireguard.admin_ops.DNSSettings.from_env",
                return_value=self.dns_settings,
            ),
            patch("gway_wireguard.admin_ops.DNSManager", return_value=self.manager),
        )

    def test_dns_commands_use_registry_identity_and_hide_credentials(self) -> None:
        admin_patch, settings_patch, manager_patch = self.patches()
        with admin_patch, settings_patch, manager_patch:
            dns_status = status()
            ensured = ensure("gway-004")
            synced = sync()
            deleted = delete("gway-004")

        self.assertTrue(dns_status["enabled"])
        self.assertTrue(dns_status["credentials_configured"])
        self.assertNotIn("key", dns_status)
        self.assertNotIn("secret", dns_status)
        self.assertEqual(ensured["hostname"], "gway-004.arthexis.com")
        self.assertIn("vpn.arthexis.com", synced["ensured"])
        self.assertTrue(deleted["changed"])
        self.assertNotIn(("gway-004", "A"), self.provider.records)

    def test_revoke_deletes_dns_and_repeated_revoke_repairs_stale_dns(self) -> None:
        self.provider.records[("gway-004", "A")] = [
            DNSRecord("54.161.177.151", 600)
        ]
        admin_patch, settings_patch, manager_patch = self.patches()
        with admin_patch, settings_patch, manager_patch:
            first = revoke("gway-004")
        self.assertTrue(first["dns_changed"])
        self.assertNotIn(("gway-004", "A"), self.provider.records)

        self.provider.records[("gway-004", "A")] = [
            DNSRecord("54.161.177.151", 600)
        ]
        admin_patch, settings_patch, manager_patch = self.patches()
        with admin_patch, settings_patch, manager_patch:
            second = revoke("gway-004")
        self.assertTrue(second["already_revoked"])
        self.assertTrue(second["dns_changed"])
        self.assertNotIn(("gway-004", "A"), self.provider.records)


if __name__ == "__main__":
    unittest.main()
