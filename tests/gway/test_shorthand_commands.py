from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import gway_wire.gway as root
from gway_wire.gway import client, server, topology


class ShorthandCommandTests(unittest.TestCase):
    @patch("gway_wire.gway.client._client_installer", return_value=Path("/tmp/install.sh"))
    @patch("gway_wire.gway.client.subprocess.run")
    def test_enroll_url_alias_adds_default_path(self, run, installer) -> None:
        run.return_value = subprocess.CompletedProcess([], 0, stdout="ok\n", stderr="")

        result = client.enroll(device="gway-001", url="register.gelectriic.com")

        self.assertTrue(result["success"])
        self.assertIn(
            "https://register.gelectriic.com/v1/enroll",
            run.call_args.args[0],
        )
        installer.assert_called_once_with()

    @patch("gway_wire.gway.client._client_installer", return_value=Path("/tmp/install.sh"))
    @patch("gway_wire.gway.client.subprocess.run")
    def test_enroll_url_alias_keeps_explicit_path(self, run, installer) -> None:
        run.return_value = subprocess.CompletedProcess([], 0, stdout="ok\n", stderr="")

        client.enroll(url="https://register.gelectriic.com/custom/enroll")

        self.assertIn(
            "https://register.gelectriic.com/custom/enroll",
            run.call_args.args[0],
        )
        installer.assert_called_once_with()

    @patch("gway_wire.gway.server._readiness")
    @patch("gway_wire.gway.server._run_installer", return_value={"success": True})
    def test_deploy_dns_alias_overrides_require_dns(self, run_installer, readiness) -> None:
        readiness.return_value = {"ready": True}

        result = server.deploy("gelectriic.com", dns=False)

        self.assertTrue(result["success"])
        self.assertFalse(readiness.call_args.kwargs["require_dns"])
        run_installer.assert_called_once()

    @patch("gway_wire.gway.server._domain_preflight")
    def test_check_dns_alias_overrides_require_dns(self, preflight) -> None:
        preflight.return_value = {"deployable": True}

        with tempfile.TemporaryDirectory() as directory:
            server.check(
                "gelectriic.com",
                dns=False,
                env_file=Path(directory) / "server.env",
            )

        self.assertFalse(preflight.call_args.args[2])

    @patch("gway_wire.gway.server._dns_status_for", return_value={"valid": True})
    def test_dns_provider_and_provider_select_same_check(self, dns_status) -> None:
        with tempfile.TemporaryDirectory() as directory:
            env = Path(directory) / "server.env"
            env.write_text("GWAY_BASE_DOMAIN=gelectriic.com\n", encoding="utf-8")

            explicit = server.check(
                "gelectriic.com",
                dns_provider=True,
                env_file=env,
            )
            alias = server.check(
                "gelectriic.com",
                provider=True,
                env_file=env,
            )

        self.assertEqual(explicit["dns"], {"valid": True})
        self.assertEqual(alias["dns"], {"valid": True})
        self.assertEqual(dns_status.call_count, 2)

    def test_root_check_delegates_without_server_prefix(self) -> None:
        with (
            tempfile.TemporaryDirectory() as directory,
            patch.object(
                topology.server_commands,
                "check",
                return_value={"deployable": True},
            ) as checked,
        ):
            result = root.check(
                "gelectriic.com",
                dns=False,
                provider=True,
                root=Path(directory),
            )

        self.assertTrue(result["deployable"])
        checked.assert_called_once()
        self.assertEqual(checked.call_args.args[0], "gelectriic.com")
        self.assertFalse(checked.call_args.kwargs["dns"])
        self.assertTrue(checked.call_args.kwargs["provider"])


if __name__ == "__main__":
    unittest.main()
