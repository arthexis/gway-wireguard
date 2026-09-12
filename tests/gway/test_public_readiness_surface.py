from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from gway_wire.surface import server


class PublicReadinessSurfaceTests(unittest.TestCase):
    def test_fqdn_and_domain_are_exact_aliases(self) -> None:
        self.assertEqual(
            server._one_fqdn((), fqdn="register.example.com", domain="register.example.com"),
            "register.example.com",
        )
        self.assertEqual(
            server._one_fqdn(("register.example.com",), domain="register.example.com"),
            "register.example.com",
        )
        with self.assertRaisesRegex(ValueError, "must agree"):
            server._one_fqdn((), fqdn="register.example.com", domain="example.com")

    @patch("gway_wire.surface.server.exposure_ensure")
    @patch("gway_wire.surface.server.check")
    @patch("gway_wire.surface.server.legacy._run_installer")
    def test_deploy_passes_exact_fqdn_to_web_without_deriving_domain(
        self, run_installer, readiness, ensure
    ) -> None:
        run_installer.return_value = {
            "success": True,
            "exit_code": 0,
            "output": "ok",
            "error": "",
        }
        ensure.return_value = {"success": True, "fqdn": "register.example.com"}
        readiness.return_value = {
            "fqdn": "register.example.com",
            "ok": True,
            "ready": True,
            "checks": {},
        }

        with tempfile.TemporaryDirectory() as directory:
            env = Path(directory) / "server.env"
            env.write_text(
                "\n".join(
                    [
                        "GWAY_BASE_DOMAIN=example.com",
                        "GWAY_REGISTER_HOSTNAME=old.example.com",
                        "GWAY_VPN_HOSTNAME=vpn.example.com",
                        "GWAY_DNS_PROVIDER=none",
                        "GWAY_PUBLIC_GATEWAY_IP=203.0.113.9",
                        "GWAY_ENROLL_BIND=127.0.0.1",
                        "GWAY_ENROLL_PORT=8787",
                    ]
                )
                + "\n",
                encoding="utf-8",
            )
            result = server.deploy(
                fqdn="register.example.com",
                env_file=env,
                require_dns=False,
                cert_email="ops@example.com",
            )
            written = env.read_text(encoding="utf-8")

        self.assertTrue(result["success"])
        install_env = run_installer.call_args.kwargs["env"]
        self.assertEqual(install_env["REGISTER_HOSTNAME"], "register.example.com")
        self.assertNotIn("BASE_DOMAIN", install_env)
        self.assertNotIn("VPN_HOSTNAME", install_env)
        self.assertIn("GWAY_BASE_DOMAIN=example.com", written)
        self.assertIn("GWAY_VPN_HOSTNAME=vpn.example.com", written)
        self.assertIn("GWAY_REGISTER_HOSTNAME=register.example.com", written)
        ensure.assert_called_once()
        kwargs = ensure.call_args.kwargs
        self.assertEqual(kwargs["fqdn"], "register.example.com")
        self.assertEqual(kwargs["upstream"], "http://127.0.0.1:8787")
        self.assertEqual(kwargs["dns_zone"], "example.com")
        self.assertEqual(kwargs["public_address"], "203.0.113.9")
        self.assertIsNone(kwargs["dns_provider"])

    @patch("gway_wire.surface.server.exposure_ensure")
    @patch("gway_wire.surface.server.legacy._run_installer")
    def test_deploy_restores_environment_when_web_exposure_fails(
        self, run_installer, ensure
    ) -> None:
        run_installer.return_value = {
            "success": True,
            "exit_code": 0,
            "output": "",
            "error": "",
        }
        ensure.side_effect = RuntimeError("public health failed")
        with tempfile.TemporaryDirectory() as directory:
            env = Path(directory) / "server.env"
            original = (
                "GWAY_BASE_DOMAIN=example.com\n"
                "GWAY_REGISTER_HOSTNAME=old.example.com\n"
                "GWAY_DNS_PROVIDER=none\n"
            )
            env.write_text(original, encoding="utf-8")
            result = server.deploy(
                fqdn="register.example.com",
                env_file=env,
                require_dns=False,
                cert_email="ops@example.com",
            )
            restored = env.read_text(encoding="utf-8")

        self.assertFalse(result["success"])
        self.assertIn("public health failed", result["web"]["error"])
        self.assertEqual(restored, original)

    @patch("gway_wire.surface.server.exposure_ensure")
    @patch("gway_wire.surface.server.legacy._run_installer")
    def test_failed_fresh_deploy_removes_new_environment(self, run_installer, ensure) -> None:
        def install(*args, **kwargs):
            env.write_text(
                "GWAY_BASE_DOMAIN=example.com\n"
                "GWAY_REGISTER_HOSTNAME=register.example.com\n"
                "GWAY_ENROLL_BIND=127.0.0.1\n"
                "GWAY_ENROLL_PORT=8787\n",
                encoding="utf-8",
            )
            return {"success": True, "exit_code": 0, "output": "", "error": ""}

        ensure.side_effect = RuntimeError("public health failed")
        with tempfile.TemporaryDirectory() as directory:
            env = Path(directory) / "server.env"
            run_installer.side_effect = install
            result = server.deploy(
                fqdn="register.example.com",
                env_file=env,
                require_dns=False,
                cert_email="ops@example.com",
            )
            exists_after = env.exists()

        self.assertFalse(result["success"])
        self.assertFalse(exists_after)

    def test_wireguard_check_detects_missing_tooling(self) -> None:
        with patch("gway_wire.surface.server.shutil.which", return_value=None):
            result = server._wireguard({"GWAY_WG_INTERFACE": "gway"})
        self.assertFalse(result["ok"])
        self.assertIn("wg executable not found", result["detail"])

    def test_udp_listener_check_detects_missing_port(self) -> None:
        observed = subprocess.CompletedProcess(
            ["ss", "-lun"],
            0,
            stdout="State Recv-Q Send-Q Local Address:Port\n",
            stderr="",
        )
        with (
            patch("gway_wire.surface.server.shutil.which", return_value="/usr/bin/ss"),
            patch("gway_wire.surface.server.subprocess.run", return_value=observed),
        ):
            result = server._listener({})
        self.assertFalse(result["ok"])
        self.assertEqual(result["protocol"], "udp")
        self.assertEqual(result["port"], 51820)

    def test_invalid_ports_return_failed_checks_instead_of_raising(self) -> None:
        listener = server._listener({"GWAY_WG_PORT": "not-a-port"})
        enrollment = server._enrollment({"GWAY_ENROLL_PORT": "70000"}, 1.0)
        self.assertFalse(listener["ok"])
        self.assertIn("integer port", listener["detail"])
        self.assertFalse(enrollment["ok"])
        self.assertIn("between 1 and 65535", enrollment["detail"])

    def test_enrollment_check_detects_missing_loopback_health(self) -> None:
        with patch("gway_wire.surface.server.urlopen", side_effect=OSError("refused")):
            result = server._enrollment(
                {"GWAY_ENROLL_BIND": "127.0.0.1", "GWAY_ENROLL_PORT": "8787"},
                1.0,
            )
        self.assertFalse(result["ok"])
        self.assertEqual(result["url"], "http://127.0.0.1:8787/health")

    @patch("gway_wire.surface.server._peers", return_value={"ok": True, "count": 0})
    @patch("gway_wire.surface.server._web")
    @patch("gway_wire.surface.server._enrollment", return_value={"ok": True})
    @patch("gway_wire.surface.server._listener", return_value={"ok": True})
    @patch("gway_wire.surface.server._wireguard", return_value={"ok": True})
    @patch("gway_wire.surface.server._local_config", return_value={"ready": True, "ok": True})
    @patch("gway_wire.surface.server.legacy._run_installer", return_value={"success": True})
    def test_check_without_selectors_runs_full_readiness_and_aggregates(
        self,
        run_installer,
        local_config,
        wireguard,
        listener,
        enrollment,
        web_check,
        peers,
    ) -> None:
        web_check.return_value = {
            "fqdn": "register.example.com",
            "ok": False,
            "checks": [
                {"check": "dns", "ok": True},
                {"check": "certificate", "ok": False},
                {"check": "tls", "ok": False},
                {"check": "public_health", "ok": False},
            ],
        }
        with tempfile.TemporaryDirectory() as directory:
            env = Path(directory) / "server.env"
            env.write_text(
                "GWAY_BASE_DOMAIN=example.com\n"
                "GWAY_REGISTER_HOSTNAME=register.example.com\n"
                "GWAY_DNS_PROVIDER=godaddy\n",
                encoding="utf-8",
            )
            result = server.check(fqdn="register.example.com", env_file=env)

        self.assertFalse(result["ok"])
        self.assertFalse(result["ready"])
        self.assertEqual(
            set(result["checks"]),
            {
                "source",
                "config",
                "wireguard",
                "listener",
                "enrollment",
                "web",
                "dns",
                "tls",
                "public",
                "peers",
            },
        )
        self.assertFalse(result["checks"]["tls"]["ok"])
        self.assertFalse(result["checks"]["public"]["ok"])
        run_installer.assert_called_once_with("--check")

    @patch("gway_wire.surface.server._peers", return_value={"ok": True, "count": 0})
    @patch("gway_wire.surface.server._web")
    @patch("gway_wire.surface.server._enrollment", return_value={"ok": True})
    @patch("gway_wire.surface.server._listener", return_value={"ok": True})
    @patch("gway_wire.surface.server._wireguard", return_value={"ok": True})
    @patch("gway_wire.surface.server._local_config", return_value={"ready": True, "ok": True})
    @patch("gway_wire.surface.server.legacy._run_installer", return_value={"success": True})
    def test_full_readiness_can_be_green_with_zero_managed_peers(
        self,
        run_installer,
        local_config,
        wireguard,
        listener,
        enrollment,
        web_check,
        peers,
    ) -> None:
        web_check.return_value = {
            "fqdn": "register.example.com",
            "ok": True,
            "checks": [
                {"check": "dns", "ok": True},
                {"check": "certificate", "ok": True},
                {"check": "tls", "ok": True},
                {"check": "public_health", "ok": True},
            ],
        }
        with tempfile.TemporaryDirectory() as directory:
            env = Path(directory) / "server.env"
            env.write_text(
                "GWAY_BASE_DOMAIN=example.com\n"
                "GWAY_REGISTER_HOSTNAME=register.example.com\n"
                "GWAY_DNS_PROVIDER=godaddy\n"
                "GWAY_PUBLIC_GATEWAY_IP=203.0.113.9\n",
                encoding="utf-8",
            )
            result = server.check(fqdn="register.example.com", env_file=env)

        self.assertTrue(result["ok"])
        self.assertTrue(result["ready"])
        self.assertEqual(result["checks"]["peers"]["count"], 0)

    def test_status_reports_exact_public_fqdn(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            env = Path(directory) / "server.env"
            env.write_text(
                "GWAY_BASE_DOMAIN=example.com\n"
                "GWAY_REGISTER_HOSTNAME=register.example.com\n",
                encoding="utf-8",
            )
            result = server.status(env_file=env)
        self.assertEqual(result["fqdn"], "register.example.com")


if __name__ == "__main__":
    unittest.main()
