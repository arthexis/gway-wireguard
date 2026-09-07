from __future__ import annotations

import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stderr
from pathlib import Path
from unittest.mock import patch

SERVER = Path(__file__).resolve().parents[2] / "server"
sys.path.insert(0, str(SERVER))

from enroll_api import EnrollmentService, ServerConfig  # noqa: E402
from peer_manager import PeerManagerError  # noqa: E402

KEY_GATEWAY = "G" * 43 + "="
KEY_DEVICE = "D" * 43 + "="


class EnrollmentDiagnosticStageTests(unittest.TestCase):
    def test_peer_failure_reports_stage_without_logging_token(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            gateway_key = base / "server.pub"
            wg_config = base / "gway.conf"
            hosts = base / "hosts"
            gateway_key.write_text(KEY_GATEWAY + "\n", encoding="utf-8")
            wg_config.write_text(
                "[Interface]\nAddress = 10.90.0.1/24\nPrivateKey = private\n",
                encoding="utf-8",
            )
            hosts.write_text("127.0.0.1 localhost\n", encoding="utf-8")
            config = ServerConfig(
                db_path=base / "registry.sqlite3",
                wg_config=wg_config,
                wg_interface="gway",
                wg_bin="wg",
                wg_network="10.90.0.0/24",
                gateway_address="10.90.0.1",
                gateway_endpoint="54.161.177.151:51820",
                gateway_public_key_path=gateway_key,
                base_domain="arthexis.com",
                hosts_path=hosts,
                bind_host="127.0.0.1",
                bind_port=8787,
                apply_runtime=False,
            )
            service = EnrollmentService(config)
            token, _ = service.registry.create_token(device_id="gway-004")
            stderr = io.StringIO()

            with patch("enroll_api.new_request_id", return_value="req-stage"):
                with patch.object(
                    service.peers,
                    "ensure_peer",
                    side_effect=PeerManagerError(f"peer failed with {token}"),
                ):
                    with redirect_stderr(stderr):
                        with self.assertRaises(PeerManagerError):
                            service.enroll(
                                {
                                    "device_id": "gway-004",
                                    "public_key": KEY_DEVICE,
                                    "token": token,
                                }
                            )

            events = [json.loads(line) for line in stderr.getvalue().splitlines()]
            failure = next(
                event for event in events if event["event"] == "enrollment_failed"
            )
            self.assertEqual(failure["request_id"], "req-stage")
            self.assertEqual(failure["device_id"], "gway-004")
            self.assertEqual(failure["stage"], "peer_apply")
            self.assertEqual(failure["exception"], "PeerManagerError")
            self.assertNotIn(token, failure["message"])
            self.assertIn("<redacted>", failure["message"])


if __name__ == "__main__":
    unittest.main()
