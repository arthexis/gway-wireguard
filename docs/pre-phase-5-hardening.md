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

`server check` performs active validation and is non-mutating. With no selector
flags it runs all configured checks; `--source`, `--config`, `--dns`, and
`--peers` restrict validation to selected areas. `server status` is intentionally
cheap and only reads configured state unless `--debug` is requested.
`server deploy` delegates to the existing idempotent server installer, which
copies the current managed checkout into `/opt/gway-wireguard/server`, validates
configuration, reconciles registry/DNS state, and restarts the managed service
when appropriate. Supplying `--domain` also applies the production-readiness
gate to that deployed domain.

The separation is deliberate: `gway upgrade wire` updates the managed source
checkout and its GWAY environment, while `server deploy` changes the running
gateway.

## Topology status and reconciliation

Top-level `status` and `sync` operate across every configured relationship on
the host. This allows a host to participate as a client, server, or both for
multiple domains without changing the command surface:

```bash
gway wire status
gway wire status --server
gway wire status --client
sudo gway wire sync
sudo gway wire sync --domain arthexis.com
```

`status` returns `servers` and `clients` maps keyed by domain. `sync` reconciles
both roles when present; `--domain` restricts the operation to one domain.

## Enrollment diagnostics

Enrollment clients continue to receive generic server errors for internal
failures. The gateway emits structured JSON events to stderr, which systemd
captures in the service journal.

Inspect recent events with:

```bash
sudo journalctl -u gway-wireguard-enroll.service -n 100 --no-pager
```

Failure events include an opaque request ID, validated device ID, failing stage,
exception type, and redacted message. Enrollment tokens, configured GoDaddy API
credentials, request bodies, and WireGuard private keys are not logged.

## Live exit checklist before Phase 5

Keep the legacy `gway-001` peer unmanaged during this validation.

1. Upgrade and deploy the current gateway code with `server deploy --domain arthexis.com`.
2. Run `gway wire server check` and require every selected check to pass before treating `arthexis.com` as clean.
3. Run `gway wire status --server` to record the configured server snapshot.
4. Verify `gway-001` remains present and reachable.
5. Create a fresh device-scoped token with `gway wire server token --device gway-004`.
6. Enroll `gway-004` through `https://register.arthexis.com/v1/enroll` using `gway wire client enroll`.
7. Confirm its registry-assigned VPN `/32`; do not infer the address from the device suffix.
8. Verify WireGuard handshake and bidirectional gateway reachability.
9. Verify `getent hosts gway-004` and SSH from the gateway over WireGuard.
10. Verify `gway-004.arthexis.com` points to the public gateway address.
11. Verify replay of the successfully consumed token is rejected.
12. Run `gway wire sync --domain arthexis.com` repeatedly and verify idempotency.
13. Exercise revocation on a disposable/test identity, or defer revocation of `gway-004` if it is intended to remain the first managed production peer.
14. Record the live findings in implementation tracking issue #2 before starting Phase 5 reverse-proxy work.
