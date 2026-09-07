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
2. Verify `gway-001` remains present and reachable.
3. Create a fresh device-scoped token for `gway-004`.
4. Enroll `gway-004` through `https://register.gelectriic.com/v1/enroll`.
5. Confirm its registry-assigned VPN `/32`; do not infer the address from the
   device suffix.
6. Verify WireGuard handshake and bidirectional gateway reachability.
7. Verify `getent hosts gway-004` and SSH from the gateway over WireGuard.
8. Verify `gway-004.gelectriic.com` points to the public gateway address.
9. Verify replay of the successfully consumed token is rejected.
10. Run DNS ensure/sync repeatedly and verify idempotency.
11. Exercise revocation on a disposable/test identity, or defer revocation of
    `gway-004` if it is intended to remain the first managed production peer.
12. Record the live findings in implementation tracking issue #2 before
    starting Phase 5 reverse-proxy work.
