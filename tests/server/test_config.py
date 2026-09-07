#!/usr/bin/env python3
from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from gway_wireguard.config import read_environment_file, server_environment


class ServerEnvironmentTests(unittest.TestCase):
    def test_reads_installer_environment_subset(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "server.env"
            path.write_text(
                "# comment\n"
                "GWAY_DNS_PROVIDER=godaddy\n"
                "GWAY_BASE_DOMAIN='arthexis.com'\n"
                'GWAY_REGISTER_HOSTNAME="register.arthexis.com"\n',
                encoding="utf-8",
            )
            self.assertEqual(
                read_environment_file(path),
                {
                    "GWAY_DNS_PROVIDER": "godaddy",
                    "GWAY_BASE_DOMAIN": "arthexis.com",
                    "GWAY_REGISTER_HOSTNAME": "register.arthexis.com",
                },
            )

    def test_process_environment_overrides_installed_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "server.env"
            path.write_text(
                "GWAY_DNS_PROVIDER=godaddy\n"
                "GWAY_PUBLIC_GATEWAY_IP=192.0.2.10\n",
                encoding="utf-8",
            )
            clean = {
                "GWAY_SERVER_ENV_FILE": str(path),
                "GWAY_PUBLIC_GATEWAY_IP": "54.161.177.151",
            }
            with patch.dict(os.environ, clean, clear=True):
                values = server_environment()

            self.assertEqual(values["GWAY_DNS_PROVIDER"], "godaddy")
            self.assertEqual(values["GWAY_PUBLIC_GATEWAY_IP"], "54.161.177.151")


if __name__ == "__main__":
    unittest.main()
