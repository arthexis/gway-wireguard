#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import http.client
import json
import sqlite3
import sys
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path

SERVER = Path(__file__).resolve().parents[2] / "server"
sys.path.insert(0, str(SERVER))

from enroll_api import EnrollmentHandler  # noqa: E402
from registry import EnrollmentRejected, Registry  # noqa: E402


class StubEnrollmentService:
    def __init__(self) -> None:
        self.payload: object | None = None
        self.error: Exception | None = None
        self.response: dict[str, object] = {
            "version": 1,
            "device_id": "gway-004",
            "hostname": "gway-004.arthexis.com",
            "vpn_address": "10.90.0.3/32",
            "gateway_address": "10.90.0.1",
            "gateway_endpoint": "54.161.177.151:51820",
            "gateway_public_key": "G" * 43 + "=",
            "allowed_ips": ["10.90.0.1/32"],
        }

    def enroll(self, payload: object) -> dict[str, object]:
        self.payload = payload
        if self.error is not None:
            raise self.error
        return self.response


class EnrollmentHTTPContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.service = StubEnrollmentService()
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), EnrollmentHandler)
        self.server.enrollment_service = self.service  # type: ignore[attr-defined]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)

    def _post(
        self,
        path: str,
        body: bytes,
        *,
        content_type: str = "application/json",
    ) -> tuple[int, dict[str, object]]:
        connection = http.client.HTTPConnection(*self.server.server_address, timeout=2)
        connection.request(
            "POST",
            path,
            body=body,
            headers={"Content-Type": content_type},
        )
        response = connection.getresponse()
        payload = json.loads(response.read().decode("utf-8"))
        status = response.status
        connection.close()
        return status, payload

    def test_v1_enroll_accepts_json_and_returns_versioned_contract(self) -> None:
        request = {
            "device_id": "gway-004",
            "public_key": "D" * 43 + "=",
            "token": "enrollment-token",
        }
        status, response = self._post(
            "/v1/enroll",
            json.dumps(request).encode("utf-8"),
        )

        self.assertEqual(status, 200)
        self.assertEqual(self.service.payload, request)
        self.assertEqual(response, self.service.response)
        self.assertNotIn("private_key", response)
        self.assertNotIn("token", response)

    def test_rejected_enrollment_maps_status_and_error_code(self) -> None:
        self.service.error = EnrollmentRejected(
            "invalid or already-used enrollment token",
            code="invalid_enrollment_token",
            status=403,
        )
        status, response = self._post(
            "/v1/enroll",
            b'{"device_id":"gway-004","public_key":"key","token":"used"}',
        )

        self.assertEqual(status, 403)
        self.assertEqual(response["error"], "invalid_enrollment_token")

    def test_invalid_json_and_media_type_are_rejected_before_service(self) -> None:
        status, response = self._post("/v1/enroll", b"{not-json")
        self.assertEqual(status, 400)
        self.assertEqual(response["error"], "invalid_json")
        self.assertIsNone(self.service.payload)

        status, response = self._post(
            "/v1/enroll",
            b"device_id=gway-004",
            content_type="application/x-www-form-urlencoded",
        )
        self.assertEqual(status, 415)
        self.assertEqual(response["error"], "unsupported_media_type")
        self.assertIsNone(self.service.payload)

    def test_unknown_enrollment_version_is_not_routed(self) -> None:
        status, response = self._post("/v2/enroll", b"{}")
        self.assertEqual(status, 404)
        self.assertEqual(response["error"], "not_found")
        self.assertIsNone(self.service.payload)


class EnrollmentTokenStorageContractTests(unittest.TestCase):
    def test_plaintext_token_is_never_persisted(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            db = Path(directory) / "registry.sqlite3"
            registry = Registry(db)
            token = "known-enrollment-token-value-1234567890"
            returned, _expires = registry.create_token(
                device_id="gway-004",
                token=token,
            )

            self.assertEqual(returned, token)
            with sqlite3.connect(db) as conn:
                row = conn.execute(
                    "SELECT token_hash FROM enrollment_tokens"
                ).fetchone()
            self.assertIsNotNone(row)
            assert row is not None
            self.assertEqual(
                row[0],
                hashlib.sha256(token.encode("utf-8")).hexdigest(),
            )
            self.assertNotEqual(row[0], token)
            self.assertNotIn(token.encode("utf-8"), db.read_bytes())


if __name__ == "__main__":
    unittest.main()
