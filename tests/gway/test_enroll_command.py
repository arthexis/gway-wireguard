from __future__ import annotations

import subprocess
import unittest
from pathlib import Path
from unittest.mock import patch

from gway_wireguard.gway import enroll


class GwayEnrollCommandTests(unittest.TestCase):
    @patch(
        "gway_wireguard.gway._client_installer", return_value=Path("/repo/install.sh")
    )
    @patch("gway_wireguard.gway.subprocess.run")
    def test_enroll_uses_arthexis_default_without_cwd(self, run, _installer) -> None:
        run.return_value = subprocess.CompletedProcess(
            ["bash", "/repo/install.sh"],
            0,
            stdout="configured\n",
            stderr="",
        )

        result = enroll(token_file=Path("/root/gway-enrollment.token"))

        self.assertTrue(result["success"])
        self.assertEqual(result["exit_code"], 0)
        self.assertEqual(result["output"], "configured")
        run.assert_called_once_with(
            [
                "bash",
                "/repo/install.sh",
                "--token-file",
                "/root/gway-enrollment.token",
                "--enroll-url",
                "https://register.arthexis.com/v1/enroll",
            ],
            check=False,
            capture_output=True,
            text=True,
        )

    @patch(
        "gway_wireguard.gway._client_installer", return_value=Path("/repo/install.sh")
    )
    @patch("gway_wireguard.gway.subprocess.run")
    @patch("gway_wireguard.gway.getpass.getpass", return_value=" prompted-token ")
    def test_enroll_prompts_when_token_is_missing(
        self, prompt, run, _installer
    ) -> None:
        run.return_value = subprocess.CompletedProcess(
            ["bash", "/repo/install.sh"],
            0,
            stdout="configured\n",
            stderr="",
        )

        result = enroll(device="gway-004")

        self.assertTrue(result["success"])
        prompt.assert_called_once_with("Enrollment token: ")
        command = run.call_args.args[0]
        self.assertNotIn("--token", command)
        self.assertNotIn("prompted-token", command)
        self.assertEqual(
            run.call_args.kwargs["env"]["GWAY_ENROLL_TOKEN"], "prompted-token"
        )

    @patch("gway_wireguard.gway.subprocess.run")
    @patch("gway_wireguard.gway.getpass.getpass", return_value="   ")
    def test_enroll_rejects_empty_interactive_token(self, prompt, run) -> None:
        result = enroll()

        self.assertFalse(result["success"])
        self.assertEqual(result["exit_code"], 2)
        self.assertEqual(result["error"], "no enrollment token provided")
        prompt.assert_called_once_with("Enrollment token: ")
        run.assert_not_called()

    @patch("gway_wireguard.gway.subprocess.run")
    @patch("gway_wireguard.gway.getpass.getpass", side_effect=EOFError)
    def test_enroll_handles_missing_interactive_input(self, prompt, run) -> None:
        result = enroll()

        self.assertFalse(result["success"])
        self.assertEqual(result["exit_code"], 2)
        self.assertEqual(result["error"], "no enrollment token provided")
        prompt.assert_called_once_with("Enrollment token: ")
        run.assert_not_called()

    @patch(
        "gway_wireguard.gway._client_installer", return_value=Path("/repo/install.sh")
    )
    @patch("gway_wireguard.gway.subprocess.run")
    def test_enroll_accepts_explicit_device_and_url(self, run, _installer) -> None:
        run.return_value = subprocess.CompletedProcess(
            ["bash", "/repo/install.sh"],
            0,
            stdout="ok\n",
            stderr="",
        )

        enroll(
            device="gway-004",
            token_file=Path("/root/token"),
            enroll_url="https://register.example.test/v1/enroll",
        )

        command = run.call_args.args[0]
        self.assertEqual(command[:2], ["bash", "/repo/install.sh"])
        self.assertIn("gway-004", command)
        self.assertIn("https://register.example.test/v1/enroll", command)

    @patch(
        "gway_wireguard.gway._client_installer", return_value=Path("/repo/install.sh")
    )
    @patch("gway_wireguard.gway.subprocess.run")
    def test_enroll_reports_installer_failure(self, run, _installer) -> None:
        run.return_value = subprocess.CompletedProcess(
            ["bash", "/repo/install.sh"],
            1,
            stdout="",
            stderr="error: authenticated enrollment failed\n",
        )

        result = enroll(device="gway-004", token="secret")

        self.assertFalse(result["success"])
        self.assertEqual(result["exit_code"], 1)
        self.assertEqual(result["error"], "error: authenticated enrollment failed")
        self.assertNotIn("secret", repr(result))


if __name__ == "__main__":
    unittest.main()
