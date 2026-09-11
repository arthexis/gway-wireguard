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
        with patch.object(AdminSettings, "from_env") as settings, patch(
            "gway_wire.gway.server.create_enrollment_token",
            return_value={"token": "value", "device": "gway-004"},
        ) as create:
            settings.return_value = object()
            result = server.token(device="gway-004", ttl=120)

        self.assertEqual(result["token"], "value")
        create.assert_called_once_with(device="gway-004", ttl=120)

    @patch("gway_wire.gway.client.subprocess.run")
    def test_client_status_is_role_scoped(self, run) -> None:
        run.return_value = subprocess.CompletedProcess(
            ["wg", "show", "gway"], 0, stdout="interface: gway\n", stderr=""
        )

        result = client.status()

        self.assertTrue(result["available"])
        self.assertEqual(result["interface"], "gway")

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
                        "GWAY_VPN_HOSTNAME=vpn.arthexis.com",
                        "GWAY_REGISTER_HOSTNAME=register.arthexis.com",
                    ]
                )
                + "\n",
                encoding="utf-8",
            )
            client_dir = root_dir / "clients" / "example.com"
            client_dir.mkdir(parents=True)
            (client_dir / "domain").write_text("example.com\n", encoding="utf-8")
            (client_dir / "interface").write_text("gway-example\n", encoding="utf-8")

            with patch.object(
                topology.client_commands,
                "status",
                return_value={"available": True, "interface": "gway-example"},
            ):
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
