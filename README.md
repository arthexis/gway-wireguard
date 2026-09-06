# gway-wireguard

Secure WireGuard enrollment and public routing for Gway-family devices.

The project is under active development and is **not yet ready for unattended production installation**.

## Intended client workflow

The eventual client workflow remains:

```bash
git clone https://github.com/arthexis/gway-wireguard.git
cd gway-wireguard
sudo ./install.sh
```

The target design gives a deployed device a stable hostname such as `gway-004.arthexis.com` while the device initiates an outbound WireGuard tunnel to a central gateway. Public HTTPS is terminated at the gateway; administrative services remain private to the WireGuard network by default.

See [PLAN.md](PLAN.md) for the architecture and phased implementation plan.

## Current status

Phase 0 is complete. Phase 1 provides a deliberately manual WireGuard proof of concept for the gateway and `gway-004` before enrollment, DNS, and reverse-proxy automation are introduced.

See [docs/phase-1.md](docs/phase-1.md) for the current test procedure.

The root `install.sh` remains intentionally disabled until Phase 2, when the one-command client installer is implemented.
