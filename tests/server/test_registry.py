#!/usr/bin/env python3
import datetime as dt
import sys
import tempfile
import unittest
from pathlib import Path

SERVER = Path(__file__).resolve().parents[2] / "server"
sys.path.insert(0, str(SERVER))

from registry import EnrollmentRejected, Registry  # noqa: E402

KEY_A = "A" * 43 + "="
KEY_B = "B" * 43 + "="


class RegistryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = Path(self.tmp.name) / "registry.sqlite3"
        self.registry = Registry(self.db)
        self.registry.initialize()

    def tearDown(self):
        self.tmp.cleanup()

    def enroll(self, device, key, token, reserved=()):
        with self.registry.transaction() as conn:
            record, digest, created = self.registry.prepare_enrollment(
                conn,
                device_id=device,
                public_key=key,
                token=token,
                base_domain="arthexis.com",
                externally_reserved=reserved,
            )
            self.registry.consume_token(conn, digest)
        return record, created

    def test_one_time_token_and_address_allocation_skip_manual_peer(self):
        token, _ = self.registry.create_token(device_id="gway-004")
        record, created = self.enroll(
            "gway-004",
            KEY_A,
            token,
            reserved=("10.90.0.2/32",),
        )
        self.assertTrue(created)
        self.assertEqual(record["vpn_address"], "10.90.0.3/32")

        with self.assertRaises(EnrollmentRejected) as caught:
            self.enroll("gway-005", KEY_B, token)
        self.assertEqual(caught.exception.status, 403)

    def test_device_scoped_token_cannot_enroll_another_device(self):
        token, _ = self.registry.create_token(device_id="gway-004")
        with self.assertRaises(EnrollmentRejected) as caught:
            self.enroll("gway-005", KEY_A, token)
        self.assertEqual(caught.exception.code, "invalid_enrollment_token")

    def test_fresh_token_reuses_same_address_for_same_device_and_key(self):
        token1, _ = self.registry.create_token(device_id="gway-004")
        first, _ = self.enroll("gway-004", KEY_A, token1)
        token2, _ = self.registry.create_token(device_id="gway-004")
        second, created = self.enroll("gway-004", KEY_A, token2)
        self.assertFalse(created)
        self.assertEqual(first["vpn_address"], second["vpn_address"])

    def test_identity_cannot_silently_change_key(self):
        token1, _ = self.registry.create_token(device_id="gway-004")
        self.enroll("gway-004", KEY_A, token1)
        token2, _ = self.registry.create_token(device_id="gway-004")
        with self.assertRaises(EnrollmentRejected) as caught:
            self.enroll("gway-004", KEY_B, token2)
        self.assertEqual(caught.exception.code, "device_key_conflict")

    def test_expired_token_is_rejected_without_consumption(self):
        now = dt.datetime(2026, 9, 6, 12, 0, tzinfo=dt.timezone.utc)
        token, _ = self.registry.create_token(
            device_id="gway-004",
            ttl_seconds=10,
            now=now,
        )
        with self.registry.transaction() as conn:
            with self.assertRaises(EnrollmentRejected) as caught:
                self.registry.prepare_enrollment(
                    conn,
                    device_id="gway-004",
                    public_key=KEY_A,
                    token=token,
                    base_domain="arthexis.com",
                    now=now + dt.timedelta(seconds=11),
                )
        self.assertEqual(caught.exception.code, "expired_enrollment_token")

    def test_revoked_device_cannot_reenroll(self):
        token1, _ = self.registry.create_token(device_id="gway-004")
        self.enroll("gway-004", KEY_A, token1)
        self.registry.revoke("gway-004")
        token2, _ = self.registry.create_token(device_id="gway-004")
        with self.assertRaises(EnrollmentRejected) as caught:
            self.enroll("gway-004", KEY_A, token2)
        self.assertEqual(caught.exception.code, "device_revoked")


if __name__ == "__main__":
    unittest.main()
