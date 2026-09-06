# Phase 2: client installer

Phase 2 turns the manual client steps from Phase 1 into an idempotent root-level installer while intentionally leaving server enrollment manual until Phase 3.

## Fresh device flow

On the box:

```bash
git clone https://github.com/arthexis/gway-wireguard.git
cd gway-wireguard
sudo ./install.sh --prepare --device gway-004
```

`--prepare` installs WireGuard when required, persists the device identity, and generates the device keypair under `/etc/gway-wireguard/`.

The private key is never printed. Copy only the displayed device **public** key to the gateway.

On the gateway, Phase 1 still supplies the manual peer operation:

```bash
sudo CLIENT_PUBLIC_KEY='<device-public-key>' \
  CLIENT_ADDRESS='10.90.0.4/32' \
  ./server/manual-setup.sh apply
```

Then configure the client using the gateway public key and address allocated to the device:

```bash
sudo ./install.sh \
  --device gway-004 \
  --server-public-key '<gateway-public-key>' \
  --client-address 10.90.0.4/32
```

The endpoint defaults to `54.161.177.151:51820`, the gateway tunnel IP defaults to `10.90.0.1/32`, and keepalive defaults to 25 seconds. Override them when necessary:

```bash
sudo ./install.sh \
  --server-public-key '<gateway-public-key>' \
  --client-address 10.90.0.4/32 \
  --server-endpoint vpn.example.com:51820 \
  --server-tunnel-ip 10.90.0.1/32 \
  --keepalive 25
```

## Identity

Identity resolution is deterministic:

1. `--device`;
2. existing `/etc/gway-wireguard/device-id`;
3. current short hostname.

The selected device ID must be a lowercase DNS-safe label. Once persisted, `install.sh` refuses to silently change it.

## Persistent state

Client state is stored in:

```text
/etc/gway-wireguard/device-id
/etc/gway-wireguard/private.key
/etc/gway-wireguard/public.key
/etc/gway-wireguard/server-public-key
/etc/gway-wireguard/client-address
/etc/gway-wireguard/server-endpoint
/etc/gway-wireguard/server-tunnel-ip
/etc/gway-wireguard/keepalive
```

The WireGuard interface remains:

```text
/etc/wireguard/gway.conf
```

The installer reuses an existing private key and persisted configuration. Re-running the same command does not generate a new identity or key.

## Repair / idempotency

A later run can omit values already persisted:

```bash
sudo ./install.sh
```

The installer regenerates the desired WireGuard configuration from persisted state, ensures `wg-quick@gway` is enabled, and restarts it only when the generated configuration changed.

## Status

```bash
sudo ./install.sh --status
```

This prints identity, public key, persisted endpoint/address, service state, and `wg show` output when available. It never prints the private key.

## Non-mutating validation

CI and operators can validate arguments without root or system changes:

```bash
./install.sh --check \
  --device gway-004 \
  --server-public-key '<gateway-public-key>' \
  --client-address 10.90.0.4/32
```

## Phase boundary

Phase 2 does **not** create or update the server peer automatically. A freshly generated device public key still has to be registered manually on the gateway.

Phase 3 introduces authenticated enrollment so a fresh device can submit its public key, receive its assigned VPN address and gateway settings, and complete the final one-command workflow without manual peer editing.
