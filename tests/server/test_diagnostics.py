from __future__ import annotations

import io
import json
import os
import unittest
from contextlib import redirect_stderr
from unittest.mock import patch

from gway_wireguard.diagnostics import log_enrollment_event


class EnrollmentDiagnosticsTests(unittest.TestCase):
    def test_enrollment_diagnostics_redact_token_and_dns_credentials(self) -> None:
        token = "one-time-token"
        dns_key = "godaddy-key"
        dns_secret = "godaddy-secret"
        error = RuntimeError(f"failed {token} {dns_key} {dns_secret}")
        stderr = io.StringIO()

        with patch.dict(
            os.environ,
            {
                "GWAY_GODADDY_KEY": dns_key,
                "GWAY_GODADDY_SECRET": dns_secret,
            },
        ):
            with redirect_stderr(stderr):
                log_enrollment_event(
                    "enrollment_failed",
                    request_id="req-123",
                    device_id="gway-004",
                    stage="dns_ensure",
                    error=error,
                    payload={"device_id": "gway-004", "token": token},
                )

        event = json.loads(stderr.getvalue())
        self.assertEqual(event["event"], "enrollment_failed")
        self.assertEqual(event["request_id"], "req-123")
        self.assertEqual(event["device_id"], "gway-004")
        self.assertEqual(event["stage"], "dns_ensure")
        self.assertEqual(event["exception"], "RuntimeError")
        self.assertNotIn(token, event["message"])
        self.assertNotIn(dns_key, event["message"])
        self.assertNotIn(dns_secret, event["message"])
        self.assertEqual(event["message"].count("<redacted>"), 3)

    def test_success_diagnostic_contains_no_secret_fields(self) -> None:
        stderr = io.StringIO()

        with redirect_stderr(stderr):
            log_enrollment_event(
                "enrollment_succeeded",
                request_id="req-456",
                device_id="gway-004",
                stage="complete",
            )

        event = json.loads(stderr.getvalue())
        self.assertEqual(
            event,
            {
                "device_id": "gway-004",
                "event": "enrollment_succeeded",
                "request_id": "req-456",
                "stage": "complete",
            },
        )


if __name__ == "__main__":
    unittest.main()
