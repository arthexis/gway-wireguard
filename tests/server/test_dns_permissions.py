#!/usr/bin/env python3
from __future__ import annotations

import unittest
from unittest.mock import patch

from gway_wireguard.dns import DNSConfigurationError, DNSSettings


class DNSPermissionRegressionTests(unittest.TestCase):
    @patch(
        "gway_wireguard.dns.service._read_optional_secret",
        side_effect=AssertionError("disabled DNS must not inspect secret files"),
    )
    @patch(
        "gway_wireguard.dns.service.server_environment",
        return_value={"GWAY_DNS_PROVIDER": "none"},
    )
    def test_disabled_dns_does_not_probe_secret_files(
        self,
        _server_environment,
        secret_reader,
    ) -> None:
        settings = DNSSettings.from_env()

        self.assertFalse(settings.enabled)
        self.assertIsNone(settings.godaddy_key)
        self.assertIsNone(settings.godaddy_secret)
        secret_reader.assert_not_called()
        settings.validate()

    @patch(
        "gway_wireguard.dns.service.server_environment",
        return_value={"GWAY_DNS_PROVIDER": "godaddy"},
    )
    @patch(
        "gway_wireguard.dns.service.Path.exists",
        side_effect=PermissionError(13, "Permission denied"),
    )
    def test_unreadable_secret_directory_becomes_configuration_state(
        self,
        _path_exists,
        _server_environment,
    ) -> None:
        settings = DNSSettings.from_env()

        self.assertTrue(settings.enabled)
        self.assertIsNone(settings.godaddy_key)
        self.assertIsNone(settings.godaddy_secret)
        with self.assertRaisesRegex(
            DNSConfigurationError,
            "credentials are not configured or not readable",
        ):
            settings.validate()


if __name__ == "__main__":
    unittest.main()
