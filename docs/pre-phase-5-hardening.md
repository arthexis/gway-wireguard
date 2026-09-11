# Pre-Phase-5 hardening

This checkpoint closes the operational gap between updating the managed
`gway-wire` checkout and applying that checkout to the gateway service.
It also makes enrollment failures diagnosable from the gateway journal without
returning internal details to enrollment clients.

## Server lifecycle through GWAY

Updating source and deploying server state remain intentionally separate:

```bash
sudo gway upgrade wire
sudo gway wire server check
sudo gway wire server deploy --domain arthexis.com
sudo gway wire server status
```

`server check` delegates to `server/install.sh --check` and is non-mutating.
`server status` delegates to `server/install.sh --status` and is non-mutating.
`server deploy` delegates to the existing idempotent server installer, which
copies the current managed checkout into `/opt/gway-wireguard/server`, validates
configuration, reconciles registry/DNS state, and restarts the managed service
when appropriate.

When `--domain` is supplied, deployment also applies the production readiness
gate for that domain. Without `--domain`, deployment remains usable for
DNS-disabled or development configurations.

## Production readiness gate

For the production gateway, use deployment with the intended domain:

```bash
sudo gway wire server deploy --domain arthexis.com
```

The readiness check reads the deployed `/etc/gway-wireguard/server.env` without
sourcing it and does not print credential contents. It verifies:

- the deployed environment exists and is readable;
- the registry path exists;
- the configured base domain matches the requested production domain;
- DNS is enabled;
- `vpn.<domain>` and `register.<domain>` match the configured base domain;
- GoDaddy credential files exist and are non-empty when that provider is selected.

## Enrollment diagnostics

Enrollment clients continue to receive generic server errors for internal
failures. The gateway emits structured JSON events to stderr, which systemd
captures in the service journal.

Inspect recent events with:

```bash
sudo journalctl -u gway-wireguard-enroll.service -n 100 --no-pager
```

Failure events include an opaque request ID, validated device ID, failing stage,
exception type, and redacted message. Enrollment tokens and configured GoDaddy
API credentials are redacted from exception text before it is written to the
journal. Request bodies and WireGuard private keys are never logged.

## Live exit checklist before Phase 5

Keep the legacy `gway-001` peer unmanaged during this validation.

1. Upgrade the current gateway source with `sudo gway upgrade wire`.
2. Deploy and require a clean production-domain result with `sudo gway wire server deploy --domain arthexis.com`.
3. Verify `gway-001` remains present and reachable with `gway wire server peer managed` and WireGuard diagnostics.
4. Create a fresh device-scoped token with `sudo gway wire server token --device gway-004`.
5. On the disposable box, enroll with `sudo gway wire client enroll --device gway-004 --token '<token>'`.
6. Confirm its registry-assigned VPN `/32`; do not infer the address from the device suffix.
7. Verify `gway wire client status`, a recent WireGuard handshake, and bidirectional gateway reachability.
8. Verify `getent hosts gway-004` and SSH from the gateway over WireGuard.
9. Verify `gway-004.arthexis.com` points to the public gateway address.
10. Verify replay of the successfully consumed token is rejected.
11. Run `gway wire server dns ensure gway-004` and `gway wire server dns sync` repeatedly and verify idempotency.
12. Exercise `gway wire server device revoke gway-004` on the disposable identity, or defer revocation if it is intended to remain the first managed production peer.
13. Record the live findings in implementation tracking issue #2 before starting Phase 5 reverse-proxy work.
