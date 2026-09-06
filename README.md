# gway-wireguard

Secure WireGuard enrollment and public routing for Gway-family devices.

The project is under active development and is **not yet ready for unattended production installation**.

## Client workflow

Phase 2 provides an idempotent client installer. Automatic server enrollment arrives in Phase 3.

On a fresh device:

```bash
git clone https://github.com/arthexis/gway-wireguard.git
cd gway-wireguard
sudo ./install.sh --prepare --device gway-004
```

After the printed device public key has been registered on the gateway:

```bash
sudo ./install.sh \
  --server-public-key '<gateway-public-key>' \
  --client-address 10.90.0.4/32
```

The target design gives a deployed device a stable hostname such as `gway-004.arthexis.com` while the device initiates an outbound WireGuard tunnel to a central gateway. Public HTTPS is terminated at the gateway; administrative services remain private to the WireGuard network by default.

See [PLAN.md](PLAN.md) for the architecture and phased implementation plan.

## Current status

- Phase 0: repository bootstrap — complete.
- Phase 1: manual WireGuard proof-of-concept tooling — merged; real-device findings remain tracked in issue #2.
- Phase 2: idempotent client installer — in implementation.
- Phase 3+: enrollment, DNS, reverse proxy, and hardening — pending.

See [docs/phase-1.md](docs/phase-1.md) for the manual tunnel test procedure and [docs/phase-2.md](docs/phase-2.md) for the client installer.
