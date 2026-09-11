from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import gway_wire.gway as root
from gway_wire.admin_ops import AdminSettings
from gway_wire.gway import client, server
from gway_wire.gway import topology
from gway_wire.registry import Registry


class SimplifiedCommandTests(unittest.TestCase):
    def test_root_namespace_only_has_topology_commands(self) -> None:
        self.assertTrue(callable(root.status))
        self.assertTrue(callable(root.sync))
        for name in ("enroll", "token", "deploy"):
            self.assertFalse(hasattr(root, name), name)

    @patch("gway_wire.gway.server._server_installer")
    @patch("gway_wire.gway.server.subprocess.run")
    def test_plain_server_deploy_only_runs_installer(self, run, installer) -> None:
        path = Path("/managed/gway-wire/server/install.sh")
        installer.return_value = path
        run.return_value = subprocess.CompletedProcess(
            ["bash", str(path)], 0, stdout="ok\n", stderr=""
        )

        result = server.deploy()

        self.assertTrue(result["success"])
        self.assertNotIn("ready", result)

    @patch("gway_wire.gway.server._server_installer")
    @patch("gway_wire.gway.server.subprocess.run")
    def test_server_deploy_domain_applies_readiness_gate(self, run, installer) -> None:
        path = Path("/managed/gway-wire/server/install.sh")
        installer.return_value = path
        run.return_value = subprocess.CompletedProcess(
            ["bash", str(path)], 0, stdout="ok\n", stderr=""
        )

        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            registry = base / "registry.sqlite3"
            registry.write_bytes(b"sqlite")
            env = base / "server.env"
            env.write_text(
                "\n".join(
                    [
                        f"GWAY_REGISTRY_DB={registry}",
                        "GWAY_BASE_DOMAIN=arthexis.com",
                        "GWAY_DNS_PROVIDER=godaddy",
                        "GWAY_VPN_HOSTNAME=vpn.arthexis.com",
                        "GWAY_REGISTER_HOSTNAME=register.arthexis.com",
                        "GWAY_GODADDY_KEY=key",
                        "GWAY_GODADDY_SECRET=secret",
                    ]
                )
                + "\n",
                encoding="utf-8",
            )

            result = server.deploy(domain="arthexis.com", env_file=env)

        self.assertTrue(result["success"])
        self.assertTrue(result["ready"])
        self.assertEqual(result["domain"], "arthexis.com")

    def test_server_token_is_direct_server_command(self) -> None:
        with (
            patch.object(AdminSettings, "from_env") as settings,
            patch(
                "gway_wire.gway.server.create_enrollment_token",
                return_value={"token": "value", "device": "gway-004"},
            ) as create,
        ):
            settings.return_value = object()
            result = server.token(device="gway-004", ttl=120)

        self.assertEqual(result["token"], "value")
        create.assert_called_once_with(device="gway-004", ttl=120)

    @patch("gway_wire.gway.client.subprocess.run")
    def test_client_enroll_rejects_token_issued_on_same_device(self, run) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root_dir = Path(directory)
            registry_path = root_dir / "registry.sqlite3"
            registry = Registry(registry_path)
            token, _ = registry.create_token(
                device_id="gway-004",
                token="same-device-token-1234567890",
            )
            env = root_dir / "server.env"
            env.write_text(
                f"GWAY_REGISTRY_DB={registry_path}\n",
                encoding="utf-8",
            )
            with patch.object(client, "_DEFAULT_SERVER_ENV_FILE", env):
                result = client.enroll(device="gway-004", token=token)

        self.assertFalse(result["success"])
        self.assertEqual(result["exit_code"], 2)
        self.assertIn("created on this device", result["error"])
        run.assert_not_called()

    @patch("gway_wire.gway.client.subprocess.run")
    def test_client_enroll_fails_closed_when_local_registry_is_missing(self, run) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root_dir = Path(directory)
            env = root_dir / "server.env"
            env.write_text(
                f"GWAY_REGISTRY_DB={root_dir / 'missing.sqlite3'}\n",
                encoding="utf-8",
            )
            with patch.object(client, "_DEFAULT_SERVER_ENV_FILE", env):
                result = client.enroll(device="gway-004", token="remote-token")

        self.assertFalse(result["success"])
        self.assertEqual(result["exit_code"], 2)
        self.assertIn("cannot validate enrollment token", result["error"])
        run.assert_not_called()

    def test_server_devices_and_revoke_are_flat_commands(self) -> None:
        with patch(
            "gway_wire.gway.server.list_devices",
            return_value=[{"device_id": "gway-004"}],
        ) as listed:
            self.assertEqual(server.devices()[0]["device_id"], "gway-004")
            listed.assert_called_once_with()
        with patch(
            "gway_wire.gway.server.revoke_device",
            return_value={"revoked": True},
        ) as revoke:
            self.assertTrue(server.revoke("gway-004")["revoked"])
            revoke.assert_called_once_with("gway-004")

    def test_server_status_is_static_snapshot(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root_dir = Path(directory)
            registry = root_dir / "registry.sqlite3"
            registry.write_bytes(b"sqlite")
            wg_config = root_dir / "gway.conf"
            wg_config.write_text("[Interface]\n", encoding="utf-8")
            env = root_dir / "server.env"
            env.write_text(
                "\n".join(
                    [
                        "GWAY_BASE_DOMAIN=arthexis.com",
                        f"GWAY_REGISTRY_DB={registry}",
                        f"GWAY_WG_CONFIG={wg_config}",
                        "GWAY_WG_INTERFACE=gway",
                        "GWAY_DNS_PROVIDER=none",
                    ]
                )
                + "\n",
                encoding="utf-8",
            )
            result = server.status(env_file=env)

        self.assertTrue(result["configured"])
        self.assertEqual(result["domain"], "arthexis.com")
        self.assertTrue(result["registry_exists"])
        self.assertNotIn("managed_peers", result)

    @patch("gway_wire.gway.server._run_installer", return_value={"success": True})
    def test_server_check_defaults_to_all_checks(self, run_installer) -> None:
        with tempfile.TemporaryDirectory() as directory:
            env = Path(directory) / "server.env"
            env.write_text(
                "GWAY_BASE_DOMAIN=arthexis.com\nGWAY_DNS_PROVIDER=none\n",
                encoding="utf-8",
            )
            with patch(
                "gway_wire.gway.server._dns_status_for",
                return_value={"valid": True},
            ):
                result = server.check(env_file=env)

        self.assertEqual(set(result), {"source", "config", "dns", "peers"})
        run_installer.assert_called_once_with("--check")

    @patch("gway_wire.gway.client.subprocess.run")
    def test_client_status_is_static_unless_debug_requested(self, run) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory)
            (state / "client-address").write_text(
                "10.90.0.2/32\n",
                encoding="utf-8",
            )
            (state / "server-endpoint").write_text(
                "vpn.example.com:51820\n",
                encoding="utf-8",
            )
            result = client.status(state_dir=state)

        self.assertTrue(result["configured"])
        self.assertEqual(result["vpn_address"], "10.90.0.2/32")
        run.assert_not_called()

    def test_topology_status_maps_multiple_domains_and_filters_roles(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root_dir = Path(directory)
            registry = root_dir / "registry.sqlite3"
            registry.write_bytes(b"sqlite")
            (root_dir / "server.env").write_text(
                "\n".join(
                    [
                        "GWAY_BASE_DOMAIN=arthexis.com",
                        f"GWAY_REGISTRY_DB={registry}",
                        "GWAY_DNS_PROVIDER=none",
                    ]
                )
                + "\n",
                encoding="utf-8",
            )
            client_dir = root_dir / "clients" / "example.com"
            client_dir.mkdir(parents=True)
            (client_dir / "domain").write_text("example.com\n", encoding="utf-8")
            (client_dir / "interface").write_text(
                "gway-example\n",
                encoding="utf-8",
            )
            (client_dir / "client-address").write_text(
                "10.90.1.2/32\n",
                encoding="utf-8",
            )

            combined = root.status(root=root_dir)
            servers_only = root.status(server=True, root=root_dir)
            clients_only = root.status(client=True, root=root_dir)

        self.assertIn("arthexis.com", combined["servers"])
        self.assertIn("example.com", combined["clients"])
        self.assertEqual(set(servers_only), {"servers"})
        self.assertEqual(set(clients_only), {"clients"})

    def test_topology_sync_filters_by_domain_across_roles(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root_dir = Path(directory)
            client_dir = root_dir / "clients" / "example.com"
            client_dir.mkdir(parents=True)
            (client_dir / "domain").write_text("example.com\n", encoding="utf-8")

            with patch.object(
                topology.client_commands,
                "sync",
                return_value={"success": True},
            ) as client_sync:
                result = root.sync(domain="example.com", root=root_dir)

        self.assertEqual(result["servers"], {})
        self.assertTrue(result["clients"]["example.com"]["success"])
        client_sync.assert_called_once()


if __name__ == "__main__":
    unittest.main()
