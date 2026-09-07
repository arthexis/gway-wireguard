from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from gway_wireguard.gway import status
from gway_wireguard.gway.peer import managed


class GwayCommandTests(unittest.TestCase):
    @patch("gway_wireguard.gway.subprocess.run")
    def test_status_reports_live_interface(self, run) -> None:
        run.return_value = subprocess.CompletedProcess(
            ["wg", "show", "gway"],
            0,
            stdout="interface: gway\npublic key: example\nprivate key: (hidden)\n",
            stderr="",
        )

        result = status()

        self.assertTrue(result["available"])
        self.assertEqual(result["interface"], "gway")
        self.assertIn("private key: (hidden)", result["output"])
        run.assert_called_once_with(
            ["wg", "show", "gway"],
            check=False,
            capture_output=True,
            text=True,
        )

    @patch("gway_wireguard.gway.subprocess.run", side_effect=FileNotFoundError("wg"))
    def test_status_is_runnable_without_wireguard_installed(self, _run) -> None:
        result = status()

        self.assertFalse(result["available"])
        self.assertEqual(result["interface"], "gway")

    def test_managed_lists_only_managed_peer_blocks(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / "gway.conf"
            config.write_text(
                """[Interface]
Address = 10.90.0.1/24

[Peer]
PublicKey = unmanaged
AllowedIPs = 10.90.0.2/32

# BEGIN gway-wireguard managed peer: gway-004
[Peer]
# Device = gway-004
PublicKey = managed-key
AllowedIPs = 10.90.0.4/32
# END gway-wireguard managed peer: gway-004
""",
                encoding="utf-8",
            )

            self.assertEqual(
                managed(config),
                [
                    {
                        "device": "gway-004",
                        "public_key": "managed-key",
                        "allowed_ips": "10.90.0.4/32",
                    }
                ],
            )


if __name__ == "__main__":
    unittest.main()
