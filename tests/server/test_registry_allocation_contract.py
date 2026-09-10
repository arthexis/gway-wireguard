#!/usr/bin/env python3
import tempfile
import unittest
from pathlib import Path

from gway_wireguard.registry import AddressPoolExhausted, EnrollmentRejected, Registry

KEY_A = "A" * 43 + "="
KEY_B = "B" * 43 + "="


class RegistryAllocationContractTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = Path(self.tmp.name) / "registry.sqlite3"

    def tearDown(self):
        self.tmp.cleanup()

    def _enroll(self, registry: Registry, device: str, key: str) -> dict[str, object]:
        token, _ = registry.create_token(device_id=device)
        with registry.transaction() as conn:
            record, digest, _created = registry.prepare_enrollment(
                conn,
                device_id=device,
                public_key=key,
                token=token,
                base_domain="arthexis.com",
            )
            registry.consume_token(conn, digest)
        return record

    def test_allocations_are_unique_and_stable(self):
        registry = Registry(self.db)
        first = self._enroll(registry, "gway-004", KEY_A)
        second = self._enroll(registry, "gway-005", KEY_B)

        self.assertEqual(first["vpn_address"], "10.90.0.2/32")
        self.assertEqual(second["vpn_address"], "10.90.0.3/32")
        self.assertNotEqual(first["vpn_address"], second["vpn_address"])

        token, _ = registry.create_token(device_id="gway-004")
        with registry.transaction() as conn:
            repeated, digest, created = registry.prepare_enrollment(
                conn,
                device_id="gway-004",
                public_key=KEY_A,
                token=token,
                base_domain="arthexis.com",
            )
            registry.consume_token(conn, digest)

        self.assertFalse(created)
        self.assertEqual(repeated["vpn_address"], first["vpn_address"])

    def test_public_key_cannot_be_shared_between_devices(self):
        registry = Registry(self.db)
        self._enroll(registry, "gway-004", KEY_A)

        token, _ = registry.create_token(device_id="gway-005")
        with registry.transaction() as conn:
            with self.assertRaises(EnrollmentRejected) as caught:
                registry.prepare_enrollment(
                    conn,
                    device_id="gway-005",
                    public_key=KEY_A,
                    token=token,
                    base_domain="arthexis.com",
                )

        self.assertEqual(caught.exception.code, "public_key_conflict")
        self.assertIsNone(registry.get_device("gway-005"))

    def test_allocator_reports_pool_exhaustion_without_duplicate_assignment(self):
        registry = Registry(
            self.db,
            network="10.90.0.0/30",
            gateway_address="10.90.0.1",
        )
        first = self._enroll(registry, "gway-004", KEY_A)
        self.assertEqual(first["vpn_address"], "10.90.0.2/32")

        token, _ = registry.create_token(device_id="gway-005")
        with registry.transaction() as conn:
            with self.assertRaises(AddressPoolExhausted):
                registry.prepare_enrollment(
                    conn,
                    device_id="gway-005",
                    public_key=KEY_B,
                    token=token,
                    base_domain="arthexis.com",
                )

        self.assertIsNone(registry.get_device("gway-005"))

    def test_external_reservations_are_never_allocated(self):
        registry = Registry(self.db)
        token, _ = registry.create_token(device_id="gway-004")
        with registry.transaction() as conn:
            record, digest, _created = registry.prepare_enrollment(
                conn,
                device_id="gway-004",
                public_key=KEY_A,
                token=token,
                base_domain="arthexis.com",
                externally_reserved=("10.90.0.2/32", "10.90.0.3/32"),
            )
            registry.consume_token(conn, digest)

        self.assertEqual(record["vpn_address"], "10.90.0.4/32")


if __name__ == "__main__":
    unittest.main()
