# gway-wire

Endpoint connectivity for Gway-family devices. WireGuard is the first implemented backend; the `wire` name intentionally leaves room for endpoint transports such as UART and other protocols without making them part of the general network-configuration surface.

The project is under active development and is **not yet ready for unattended production installation**.

## GWAY integration

The repository is a managed Python-adapter project for GWAY. `wire` is the canonical project name; the former `wireguard` name and its short `wg` form remain aliases for compatibility. Role-specific operations are explicitly scoped to `client` or `server`, while top-level `status` and `sync` operate across the configured topology.

```bash
gway install wire
gway wire status
gway wire status --server
gway wire status --client
gway wire sync
gway wire sync --domain arthexis.com
```

`status` is deliberately cheap: it reads configured state and returns maps keyed by domain for both configured roles without running validation or reconciliation work:

```text
{
  "servers": {"arthexis.com": {...}},
  "clients": {"example.com": {...}}
}
```

With neither filter, both maps are returned. `--server` or `--client` restricts the result to that role; supplying both includes both. `--debug` adds deeper diagnostic detail, including managed peer information and live client WireGuard output. `sync` reconciles every configured relationship on the host, while `--domain` limits reconciliation to that domain regardless of whether this host is acting as a client, server, or both.

The topology reader supports the existing single-instance state under `/etc/gway-wireguard` and domain-scoped state for multiple relationships under `/etc/gway-wireguard/servers/*.env` and `/etc/gway-wireguard/clients/<domain>/`.

Client-side commands operate on one local endpoint relationship:

```bash
gway wire client status
gway wire client sync
gway wire client enroll --device gway-004 --token '<one-time-token>'
```

Server-side lifecycle and administration commands operate on gateway state:

```bash
gway wire server token --device gway-004
gway wire server devices
gway wire server revoke gway-004
gway wire server hosts sync

gway wire server dns status
gway wire server dns sync
gway wire server dns ensure gway-004
gway wire server dns delete gway-004
```

`server status` only reads the configured server snapshot. `server check` actively validates one or more aspects of the server. With no check flags it runs every available check; individual checks can be selected with `--source`, `--config`, `--dns`, or `--peers`. Managed peer inspection is intentionally hidden from the ordinary command tree and is available through `server check --peers` or `status --debug`.

Gateway deployment can optionally enforce production-domain readiness in the same command:

```bash
sudo gway wire server deploy --domain arthexis.com
```

Without `--domain`, `server deploy` performs the deployment without the production DNS/domain gate.

GWAY Sigils are available automatically in command argument values. The project itself does not depend on or import `sigils`; eager `%[...]` values are captured by GWAY before project-aware resolution, and lazy `[...]` values are resolved after the managed project and command are known:

```bash
gway wire client status --interface '[project.name]'
gway wire client status --interface '[command.name]'
gway wire client status --interface '%[cwd]/[project.name]'
```

Project and command routing remain literal, so `wire client status` selects the command before its argument values are interpolated.

The current implementation is the WireGuard backend. Client and server `status` commands read persisted configuration by default, while `--debug` adds live/diagnostic detail. Top-level `status` aggregates all discovered relationships. Server token, device administration, private-hostname, and DNS operations delegate to the same packaged implementation used by the enrollment service and compatibility server scripts.

The canonical Python namespace is `gway_wire`. The previous `gway_wireguard` namespace remains packaged during the transition so existing imports do not break immediately.

Mutating administrative commands require access to root-owned gateway state. Until GWAY's system/appliance installation mode owns that privilege boundary, `server/admin.py` remains the standalone gateway compatibility entrypoint for the Phase 3 operations it already supports.

## Scope

`gway-wire` owns connections between endpoints rather than general network configuration. WireGuard remains the only implemented transport today. Future transports can fit under the same endpoint model when there is a concrete need, including UART and other point-to-point protocols. Wi-Fi, Ethernet, address management, and broad host networking remain concerns for network-oriented projects rather than `wire` itself.

## Client workflow

A fresh device can generate its key locally, enroll with a one-time token, receive its centrally allocated VPN address, and configure the WireGuard tunnel without manual server peer editing:

```bash
gway install wire
sudo gway wire client enroll --device gway-004 --token '<one-time-token>'
```

For better command-line secret hygiene, `--token-file PATH` or `GWAY_ENROLL_TOKEN` can be used instead of placing the token directly in the command line.

An already configured client reuses its persisted identity, key, address, and gateway configuration without requesting a new VPN address.

Administrative services remain private over WireGuard. The gateway maintains registry-driven short names such as:

```bash
ssh arthe@gway-004
```

These private short names are separate from the public DNS names managed in Phase 4.

## Phase 4 public DNS

When server-side DNS automation is enabled, enrollment ensures an explicit public A record such as:

```text
gway-004.arthexis.com -> 54.161.177.151
```

The initial provider is GoDaddy, isolated behind a provider-neutral DNS interface. DNS credentials remain only on the gateway; they are never returned by the enrollment API or copied to deployed devices.

The same DNS manager also owns the operational records:

```text
vpn.arthexis.com
register.arthexis.com
```

`gway wire server dns sync` reconciles those names plus all registry-owned device records. Disabled/revoked registry devices have their explicit A records removed. Enrollment DNS changes are reversible: if a later enrollment step fails, the prior provider record set is restored. Revocation treats network access as the security boundary and never restores a revoked peer merely because DNS cleanup failed.

See [docs/phase-4.md](docs/phase-4.md) for provider configuration and validation.

## Current status

- Phase 0: repository bootstrap — complete.
- Phase 1: manual WireGuard proof of concept — complete and validated on `gway-001`.
- Phase 2: idempotent client installer — complete and validated on `gway-001`.
- Phase 3: authenticated enrollment service and private short-hostname resolution — software complete; live fresh-device validation still required.
- Phase 4: provider-neutral DNS automation with GoDaddy adapter — complete, including live provider reconciliation.
- Phase 5+: HTTPS reverse proxy and hardening — pending.

Existing/manual WireGuard peers remain preserved. The registry allocates around addresses already present in the WireGuard configuration instead of treating an empty registry as an empty network.

See [PLAN.md](PLAN.md) and the phase-specific documents under [docs/](docs/).
