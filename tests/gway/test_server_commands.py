from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from gway_wireguard.gway import server


def completed(
    arguments: list[str], *, returncode: int = 0
) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(
        arguments,
        returncode,
        stdout="server output\n",
        stderr="server error\n" if returncode else "",
    )


class ServerCommandTests(unittest.TestCase):
    @patch("gway_wireguard.gway.server._server_installer")
    @patch("gway_wireguard.gway.server.subprocess.run")
    def test_deploy_runs_server_installer(self, run, installer) -> None:
        path = Path("/managed/gway-wireguard/server/install.sh")
        installer.return_value = path
        run.return_value = completed(["bash", str(path)])

        result = server.deploy()

        self.assertEqual(
            result,
            {
                "success": True,
                "exit_code": 0,
                "output": "server output",
                "error": "",
            },
        )
        run.assert_called_once_with(
            ["bash", str(path)],
            check=False,
            capture_output=True,
            text=True,
        )

    @patch("gway_wireguard.gway.server._server_installer")
    @patch("gway_wireguard.gway.server.subprocess.run")
    def test_status_is_non_mutating_installer_mode(self, run, installer) -> None:
        path = Path("/managed/gway-wireguard/server/install.sh")
        installer.return_value = path
        run.return_value = completed(["bash", str(path), "--status"])

        result = server.status()

        self.assertTrue(result["success"])
        run.assert_called_once_with(
            ["bash", str(path), "--status"],
            check=False,
            capture_output=True,
            text=True,
        )

    @patch("gway_wireguard.gway.server._server_installer")
    @patch("gway_wireguard.gway.server.subprocess.run")
    def test_check_is_non_mutating_installer_mode(self, run, installer) -> None:
        path = Path("/managed/gway-wireguard/server/install.sh")
        installer.return_value = path
        run.return_value = completed(["bash", str(path), "--check"])

        result = server.check()

        self.assertTrue(result["success"])
        run.assert_called_once_with(
            ["bash", str(path), "--check"],
            check=False,
            capture_output=True,
            text=True,
        )

    @patch("gway_wireguard.gway.server._server_installer")
    @patch("gway_wireguard.gway.server.subprocess.run")
    def test_server_command_returns_installer_failure(self, run, installer) -> None:
        path = Path("/managed/gway-wireguard/server/install.sh")
        installer.return_value = path
        run.return_value = completed(["bash", str(path)], returncode=1)

        result = server.deploy()

        self.assertEqual(
            result,
            {
                "success": False,
                "exit_code": 1,
                "output": "server output",
                "error": "server error",
            },
        )

    def test_ready_rejects_domain_mismatch_and_disabled_dns(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            registry = base / "registry.sqlite3"
            registry.write_bytes(b"sqlite")
            env = base / "server.env"
            env.write_text(
                "\n".join(
                    [
                        f"GWAY_REGISTRY_DB={registry}",
                        "GWAY_BASE_DOMAIN=example.com",
                        "GWAY_DNS_PROVIDER=none",
                        "GWAY_VPN_HOSTNAME=vpn.example.com",
                        "GWAY_REGISTER_HOSTNAME=register.example.com",
                    ]
                )
                + "\n",
                encoding="utf-8",
            )

            result = server.ready(expected_domain="arthexis.com", env_file=env)

            self.assertFalse(result["ready"])
            self.assertIn(
                "base domain mismatch: configured=example.com expected=arthexis.com",
                result["issues"],
            )
            self.assertIn("DNS provider is disabled", result["issues"])

    def test_ready_accepts_expected_godaddy_configuration(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            registry = base / "registry.sqlite3"
            registry.write_bytes(b"sqlite")
            key = base / "godaddy.key"
            secret = base / "godaddy.secret"
            key.write_text("key\n", encoding="utf-8")
            secret.write_text("secret\n", encoding="utf-8")
            env = base / "server.env"
            env.write_text(
                "\n".join(
                    [
                        f"GWAY_REGISTRY_DB={registry}",
                        "GWAY_BASE_DOMAIN=arthexis.com",
                        "GWAY_DNS_PROVIDER=godaddy",
                        "GWAY_VPN_HOSTNAME=vpn.arthexis.com",
                        "GWAY_REGISTER_HOSTNAME=register.arthexis.com",
                        f"GWAY_GODADDY_KEY_FILE={key}",
                        f"GWAY_GODADDY_SECRET_FILE={secret}",
                    ]
                )
                + "\n",
                encoding="utf-8",
            )

            result = server.ready(expected_domain="arthexis.com", env_file=env)

            self.assertTrue(result["ready"])
            self.assertEqual(result["issues"], [])
            self.assertEqual(result["dns_provider"], "godaddy")


if __name__ == "__main__":
    unittest.main()
