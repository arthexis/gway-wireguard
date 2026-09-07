# Pre-Phase-5 hardening

This checkpoint closes the operational gap between updating the managed
`gway-wireguard` checkout and applying that checkout to the gateway service.
It also makes enrollment failures diagnosable from the gateway journal without
returning internal details to enrollment clients.

## Server lifecycle through GWAY

Updating source and deploying server state remain intentionally separate:

```bash
sudo gway upgrade wireguard
sudo gway wireguard server check
sudo gway wireguard server deploy
sudo gway wireguard server status
```

`server check` delegates to `server/install.sh --check` and is non-mutating.
`server status` delegates to `server/install.sh --status` and is non-mutating.
`server deploy` delegates to the existing idempotent server installer, which
copies the current managed checkout into `/opt/gway-wireguard/server`, validates
configuration, reconciles registry/DNS state, and restarts the managed service
when appropriate.

The separation is deliberate: `gway upgrade wireguard` updates the managed
source checkout and its GWAY environment, while `server deploy` changes the
running gateway.

## Production readiness gate

`server status` is descriptive and can legitimately report a development or
DNS-disabled installation as healthy. Before Phase 5, use the stricter readiness
command against the intended production domain:

```bash
sudo gway wireguard server ready --expected-domain arthexis.com
```

The readiness check reads the deployed `/etc/gway-wireguard/server.env` without
sourcing it and does not print credential contents. It verifies:

- the deployed environment exists and is readable;
- the registry path exists;
- the configured base domain matches the requested production domain;
- DNS is enabled unless explicitly disabled for the check;
- `vpn.<domain>` and `register.<domain>` match the configured base domain;
- GoDaddy credential files exist and are non-empty when that provider is selected.

This is intentionally separate from installation so DNS-disabled bootstrap
configuration remains usable for development while production validation fails
clearly instead of looking Phase-5-ready.

## Enrollment diagnostics

Enrollment clients continue to receive generic server errors for internal
failures. The gateway now emits structured JSON events to stderr, which systemd
captures in the service journal.

Inspect recent events with:

```bash
sudo journalctl -u gway-wireguard-enroll.service -n 100 --no-pager
```

Failure events include:

- an opaque request ID;
- the validated device ID;
- the failing stage;
- exception type and redacted message.

Stages currently include:

```text
gateway_public_key
peer_reservations
registry_prepare
peer_apply
hosts_sync
dns_ensure
token_consume
```

Rollback failures are logged separately as `dns_restore`, `peer_remove`, or
`hosts_restore`. Enrollment tokens and configured GoDaddy API credentials are
redacted from exception text before it is written to the journal. Request
bodies and WireGuard private keys are never logged.

## Live exit checklist before Phase 5

Keep the legacy `gway-001` peer unmanaged during this validation.

1. Upgrade and deploy the current gateway code.
2. Run `server ready --expected-domain arthexis.com` and require a clean result.
3. Verify `gway-001` remains present and reachable.
4. Create a fresh device-scoped token for `gway-004`.
5. Enroll `gway-004` through `https://register.arthexis.com/v1/enroll`.
6. Confirm its registry-assigned VPN `/32`; do not infer the address from the
   device suffix.
7. Verify WireGuard handshake and bidirectional gateway reachability.
8. Verify `getent hosts gway-004` and SSH from the gateway over WireGuard.
9. Verify `gway-004.arthexis.com` points to the public gateway address.
10. Verify replay of the successfully consumed token is rejected.
11. Run DNS ensure/sync repeatedly and verify idempotency.
12. Exercise revocation on a disposable/test identity, or defer revocation of
    `gway-004` if it is intended to remain the first managed production peer.
13. Record the live findings in implementation tracking issue #2 before
    starting Phase 5 reverse-proxy work.
