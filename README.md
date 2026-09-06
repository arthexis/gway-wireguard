# gway-wireguard

Secure WireGuard enrollment and public routing for Gway-family devices.

The project is under active development and is **not yet ready for unattended production installation**.

## Client workflow

Phase 3 completes authenticated WireGuard enrollment. A fresh device can generate its key locally, enroll with a one-time token, receive its centrally allocated VPN address, and configure the tunnel without manual server peer editing:

```bash
git clone https://github.com/arthexis/gway-wireguard.git
cd gway-wireguard
sudo ./install.sh --device gway-004 --token '<one-time-token>'
```

For better command-line secret hygiene, `--token-file PATH` or `GWAY_ENROLL_TOKEN` can be used instead of placing the token directly in the command line.

An already configured Phase 2 client continues to reuse its persisted identity, key, address, and gateway configuration without contacting the enrollment API or requesting a new address.

The target design gives a deployed device a stable hostname such as `gway-004.arthexis.com` while the device initiates an outbound WireGuard tunnel to a central gateway. Public HTTPS routing and DNS automation remain later phases; administrative services remain private to the WireGuard network by default.

See [PLAN.md](PLAN.md) for the architecture and phased implementation plan.

## Current status

- Phase 0: repository bootstrap — complete.
- Phase 1: manual WireGuard proof of concept — complete and validated on `gway-001`.
- Phase 2: idempotent client installer — complete and validated on `gway-001`.
- Phase 3: authenticated enrollment service — implemented; live gateway/device validation pending.
- Phase 4+: DNS automation, reverse proxy, and hardening — pending.

Phase 3 intentionally preserves pre-existing/manual WireGuard peers on the gateway. The registry allocates around addresses already present in the WireGuard configuration instead of treating an empty registry as an empty network.

See [docs/phase-1.md](docs/phase-1.md), [docs/phase-2.md](docs/phase-2.md), and [docs/phase-3.md](docs/phase-3.md) for the phase-specific procedures.
