#!/usr/bin/env python3
from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
INSTALLER = ROOT / "install.sh"


class OneCommandBootstrapTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp.name)
        self.state = self.base / "state"
        self.wg_config = self.base / "gway.conf"
        self.fake_bin = self.base / "bin"
        self.fake_bin.mkdir()
        self.calls = self.base / "enroll-calls"

        source = INSTALLER.read_text(encoding="utf-8")
        # Keep the production orchestration intact while replacing only operations
        # that require root/systemd in CI.
        source = source.replace(
            'require_root() {\n    [[ "${EUID}" -eq 0 ]] || die "run this command as root (for example with sudo)"\n}',
            'require_root() { :; }',
        )
        start = source.index("apply_wireguard_config() {")
        end = source.index("\n\nprint_prepare_summary()", start)
        source = (
            source[:start]
            + textwrap.dedent(
                f'''\
                apply_wireguard_config() {{
                    TMP_CONFIG="$(mktemp)"
                    render_wireguard_config "${{TMP_CONFIG}}"
                    cp "${{TMP_CONFIG}}" "{self.wg_config}"
                    rm -f -- "${{TMP_CONFIG}}"
                    TMP_CONFIG=""
                }}'''
            )
            + source[end:]
        )
        self.install = self.base / "install.sh"
        self.install.write_text(source, encoding="utf-8")
        self.install.chmod(0o755)

        client = self.base / "client"
        client.mkdir()
        enroll = client / "enroll.py"
        enroll.write_text(
            textwrap.dedent(
                f'''\
                import os
                from pathlib import Path

                calls = Path({str(self.calls)!r})
                calls.write_text(calls.read_text() + "1\\n" if calls.exists() else "1\\n")
                assert os.environ.get("GWAY_ENROLL_TOKEN") == "one-time-token"
                print("GGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGG=")
                print("10.90.0.4/32")
                print("vpn.arthexis.com:51820")
                print("10.90.0.1/32")
                print("gway-004.arthexis.com")
                '''
            ),
            encoding="utf-8",
        )

        self._write_fake(
            "wg",
            '''#!/usr/bin/env bash
            if [[ "$1" == "genkey" ]]; then
              echo 'PPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPP='
            elif [[ "$1" == "pubkey" ]]; then
              cat >/dev/null
              echo 'DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD='
            fi
            ''',
        )
        self._write_fake("wg-quick", "#!/usr/bin/env bash\nexit 0\n")

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _write_fake(self, name: str, body: str) -> None:
        path = self.fake_bin / name
        path.write_text(textwrap.dedent(body), encoding="utf-8")
        path.chmod(0o755)

    def _run(self, *extra: str) -> subprocess.CompletedProcess[str]:
        env = os.environ.copy()
        env["STATE_DIR"] = str(self.state)
        env["PATH"] = f"{self.fake_bin}:{env['PATH']}"
        return subprocess.run(
            [str(self.install), "--device", "gway-004", *extra],
            cwd=self.base,
            env=env,
            text=True,
            capture_output=True,
            check=False,
        )

    def test_fresh_token_bootstraps_complete_local_configuration(self) -> None:
        result = self._run("--token", "one-time-token")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.calls.read_text(), "1\n")
        self.assertEqual((self.state / "device-id").read_text().strip(), "gway-004")
        self.assertEqual((self.state / "client-address").read_text().strip(), "10.90.0.4/32")
        self.assertEqual(
            (self.state / "server-endpoint").read_text().strip(),
            "vpn.arthexis.com:51820",
        )
        self.assertEqual(
            (self.state / "hostname").read_text().strip(),
            "gway-004.arthexis.com",
        )
        config = self.wg_config.read_text()
        self.assertIn("Address = 10.90.0.4/32", config)
        self.assertIn("AllowedIPs = 10.90.0.1/32", config)
        self.assertIn("Endpoint = vpn.arthexis.com:51820", config)
        self.assertNotIn("one-time-token", config)
        for path in self.state.iterdir():
            if path.is_file():
                self.assertNotIn("one-time-token", path.read_text())

    def test_complete_local_state_skips_reenrollment(self) -> None:
        first = self._run("--token", "one-time-token")
        self.assertEqual(first.returncode, 0, first.stderr)
        second = self._run()
        self.assertEqual(second.returncode, 0, second.stderr)
        self.assertEqual(self.calls.read_text(), "1\n")
        self.assertEqual(
            (self.state / "private.key").read_text(),
            "PPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPP=\n",
        )


if __name__ == "__main__":
    unittest.main()
