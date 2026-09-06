#!/usr/bin/env python3
import sys
import unittest
from pathlib import Path

CLIENT = Path(__file__).resolve().parents[2] / "client"
sys.path.insert(0, str(CLIENT))

from enroll import EnrollmentClientError, validate_response, validate_url  # noqa: E402

KEY_GATEWAY = "G" * 43 + "="


class ClientEnrollmentTests(unittest.TestCase):
    def valid_response(self):
        return {
            "version": 1,
            "device_id": "gway-004",
            "hostname": "gway-004.arthexis.com",
            "vpn_address": "10.90.0.4/32",
            "gateway_address": "10.90.0.1",
            "gateway_endpoint": "54.161.177.151:51820",
            "gateway_public_key": KEY_GATEWAY,
            "allowed_ips": ["10.90.0.1/32"],
        }

    def test_https_is_required(self):
        self.assertEqual(
            validate_url("https://register.arthexis.com/v1/enroll"),
            "https://register.arthexis.com/v1/enroll",
        )
        with self.assertRaises(EnrollmentClientError):
            validate_url("http://register.arthexis.com/v1/enroll")

    def test_valid_response_is_normalized(self):
        result = validate_response(self.valid_response(), "gway-004")
        self.assertEqual(result["vpn_address"], "10.90.0.4/32")
        self.assertEqual(result["gateway_allowed_ip"], "10.90.0.1/32")

    def test_broad_allowed_ips_are_rejected(self):
        payload = self.valid_response()
        payload["allowed_ips"] = ["10.90.0.0/24"]
        with self.assertRaises(EnrollmentClientError):
            validate_response(payload, "gway-004")

    def test_device_mismatch_is_rejected(self):
        payload = self.valid_response()
        payload["device_id"] = "gway-005"
        with self.assertRaises(EnrollmentClientError):
            validate_response(payload, "gway-004")


if __name__ == "__main__":
    unittest.main()
