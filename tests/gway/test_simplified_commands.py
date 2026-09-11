from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from gway_wire.gway import server, token
from gway_wire.admin_ops import AdminSettings


class SimplifiedCommandTests(unittest.TestCase):
    @patch("gway_wire.gway.server._server_installer")
    @patch("gway_wire.gway.server.subprocess.run")
    def test_plain_deploy_only_runs_installer(self, run, installer) -> None:
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
    def test_deploy_domain_applies_readiness_gate(self, run, installer) -> None:
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

    def test_token_is_direct_command(self) -> None:
        with patch.object(AdminSettings, "from_env") as settings, patch(
            "gway_wire.gway.create_enrollment_token",
            return_value={"token": "value", "device": "gway-004"},
        ) as create:
            settings.return_value = object()
            result = token(device="gway-004", ttl=120)

        self.assertEqual(result["token"], "value")
        create.assert_called_once_with(device="gway-004", ttl=120)


if __name__ == "__main__":
    unittest.main()
