# gway-wireguard

Secure WireGuard enrollment and public routing for Gway-family devices.

This repository is in bootstrap development. It is **not yet ready to configure a production box**.

## Intended client workflow

```bash
git clone https://github.com/arthexis/gway-wireguard.git
cd gway-wireguard
sudo ./install.sh
```

The target design gives a deployed device a stable hostname such as `gway-004.arthexis.com` while the device initiates an outbound WireGuard tunnel to a central gateway. Public HTTPS is terminated at the gateway; administrative services remain private to the WireGuard network by default.

See [PLAN.md](PLAN.md) for the architecture, security requirements, and phased implementation plan.

## Current status

Phase 0: repository bootstrap.

The installer scripts currently fail intentionally until the corresponding implementation phases are complete.
