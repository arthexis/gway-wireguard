#!/usr/bin/env python3
from __future__ import annotations

import json
import unittest
from unittest.mock import patch

from gway_wireguard.dns import DNSManager, DNSRecord, DNSSettings
from gway_wireguard.dns.godaddy import GoDaddyProvider


class FakeProvider:
    def __init__(self) -> None:
        self.records: dict[tuple[str, str], list[DNSRecord]] = {}
        self.replacements: list[tuple[str, str, list[DNSRecord]]] = []
        self.deletions: list[tuple[str, str]] = []

    def get_records(self, name: str, record_type: str) -> list[DNSRecord]:
        return list(self.records.get((name, record_type), []))

    def replace_records(
        self,
        name: str,
        record_type: str,
        records: list[DNSRecord],
    ) -> None:
        self.records[(name, record_type)] = list(records)
        self.replacements.append((name, record_type, list(records)))

    def delete_records(self, name: str, record_type: str) -> None:
        self.records.pop((name, record_type), None)
        self.deletions.append((name, record_type))


class DNSManagerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.provider = FakeProvider()
        self.settings = DNSSettings(
            provider="godaddy",
            base_domain="arthexis.com",
            public_gateway_ip="54.161.177.151",
            ttl=600,
            vpn_hostname="vpn.arthexis.com",
            register_hostname="register.arthexis.com",
            godaddy_key="key",
            godaddy_secret="secret",
        )
        self.manager = DNSManager(self.settings, provider=self.provider)

    def test_ensure_is_idempotent_and_restore_recovers_previous_state(self) -> None:
        self.provider.records[("gway-004", "A")] = [
            DNSRecord("192.0.2.10", 600)
        ]
        mutation = self.manager.ensure_record(
            "gway-004.arthexis.com", "A", "54.161.177.151"
        )
        self.assertTrue(mutation.changed)
        self.assertEqual(
            self.provider.records[("gway-004", "A")],
            [DNSRecord("54.161.177.151", 600)],
        )

        second = self.manager.ensure_record(
            "gway-004.arthexis.com", "A", "54.161.177.151"
        )
        self.assertFalse(second.changed)

        self.manager.restore(mutation)
        self.assertEqual(
            self.provider.records[("gway-004", "A")],
            [DNSRecord("192.0.2.10", 600)],
        )

    def test_sync_owns_operational_and_registry_device_records(self) -> None:
        self.provider.records[("gway-005", "A")] = [
            DNSRecord("54.161.177.151", 600)
        ]
        result = self.manager.sync_devices(
            [
                {
                    "hostname": "gway-004.arthexis.com",
                    "enabled": 1,
                },
                {
                    "hostname": "gway-005.arthexis.com",
                    "enabled": 0,
                },
            ]
        )
        self.assertTrue(result["changed"])
        self.assertEqual(
            self.provider.records[("vpn", "A")],
            [DNSRecord("54.161.177.151", 600)],
        )
        self.assertEqual(
            self.provider.records[("register", "A")],
            [DNSRecord("54.161.177.151", 600)],
        )
        self.assertEqual(
            self.provider.records[("gway-004", "A")],
            [DNSRecord("54.161.177.151", 600)],
        )
        self.assertNotIn(("gway-005", "A"), self.provider.records)


class _Response:
    def __init__(self, body: bytes) -> None:
        self.body = body

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        return None

    def read(self) -> bytes:
        return self.body


class GoDaddyProviderTests(unittest.TestCase):
    @patch("gway_wireguard.dns.godaddy.urlopen")
    def test_get_and_replace_use_explicit_record_endpoint(self, open_url) -> None:
        open_url.side_effect = [
            _Response(b'[{"data":"54.161.177.151","ttl":600}]'),
            _Response(b""),
        ]
        provider = GoDaddyProvider(
            domain="arthexis.com",
            key="key",
            secret="secret",
        )

        records = provider.get_records("gway-004", "A")
        self.assertEqual(records, [DNSRecord("54.161.177.151", 600)])
        get_request = open_url.call_args_list[0].args[0]
        self.assertEqual(get_request.get_method(), "GET")
        self.assertTrue(
            get_request.full_url.endswith(
                "/domains/arthexis.com/records/A/gway-004"
            )
        )
        self.assertEqual(
            get_request.get_header("Authorization"),
            "sso-key key:secret",
        )

        provider.replace_records(
            "gway-004", "A", [DNSRecord("54.161.177.151", 600)]
        )
        put_request = open_url.call_args_list[1].args[0]
        self.assertEqual(put_request.get_method(), "PUT")
        self.assertEqual(
            json.loads(put_request.data.decode("utf-8")),
            [{"data": "54.161.177.151", "ttl": 600}],
        )


if __name__ == "__main__":
    unittest.main()
