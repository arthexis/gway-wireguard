from __future__ import annotations

import subprocess
import unittest
from pathlib import Path
from unittest.mock import patch

from gway_wireguard.gway import server


def completed(arguments: list[str], *, returncode: int = 0) -> subprocess.CompletedProcess[str]:
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


if __name__ == "__main__":
    unittest.main()
