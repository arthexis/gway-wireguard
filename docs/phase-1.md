# Phase 1: manual WireGuard proof of concept

Phase 1 proves the transport before enrollment, DNS automation, or public reverse-proxy routing is implemented.

## Target topology

```text
gateway (54.161.177.151)                gway-004 (behind NAT)
10.90.0.1/24            <--- WG --->     10.90.0.4/32
UDP 51820                                  outbound initiated
```

The client routes only `10.90.0.1/32` through the tunnel in this phase. Ordinary Internet traffic is not routed through the gateway, and no client service is intentionally made public.

## 1. Prepare the gateway

On the server currently hosting the gateway endpoint:

```bash
git clone https://github.com/arthexis/gway-wireguard.git
cd gway-wireguard
sudo ./server/manual-setup.sh prepare
```

Save the printed **gateway public key**. The private key remains under `/etc/gway-wireguard/` and must not be copied off the server.

Ensure the cloud/provider firewall and any host firewall allow inbound **UDP 51820** to the gateway. Do not open an SSH port on `gway-004` to the public Internet for this test.

## 2. Prepare gway-004

On `gway-004`:

```bash
git clone https://github.com/arthexis/gway-wireguard.git
cd gway-wireguard
sudo ./client/manual-setup.sh prepare
```

Save the printed **device public key**. The device private key remains on `gway-004`.

## 3. Apply the gateway peer

Back on the gateway, provide only the device public key:

```bash
sudo CLIENT_PUBLIC_KEY='<gway-004-public-key>' ./server/manual-setup.sh apply
```

This configures:

- interface `gway`;
- gateway address `10.90.0.1/24`;
- UDP listen port `51820`;
- one peer allowed to use `10.90.0.4/32`.

## 4. Apply the client peer

On `gway-004`, provide only the gateway public key:

```bash
sudo SERVER_PUBLIC_KEY='<gateway-public-key>' ./client/manual-setup.sh apply
```

The current proof-of-concept endpoint defaults to:

```text
54.161.177.151:51820
```

It can be overridden without editing the script:

```bash
sudo SERVER_ENDPOINT='example.net:51820' \
  SERVER_PUBLIC_KEY='<gateway-public-key>' \
  ./client/manual-setup.sh apply
```

## 5. Verify the tunnel

On `gway-004`:

```bash
sudo ./client/manual-setup.sh status
ping -c 3 10.90.0.1
```

On the gateway:

```bash
sudo ./server/manual-setup.sh status
ping -c 3 10.90.0.4
```

`wg show` should report a recent handshake after the client starts sending traffic.

If SSH is already running on `gway-004`, test it **from the gateway through the VPN address**:

```bash
ssh arthe@10.90.0.4
```

This does not require exposing the device's SSH port through the deployment router.

## Troubleshooting observations to record

Add real deployment findings to the implementation tracking issue, especially:

- whether UDP 51820 required a cloud-provider firewall change;
- observed handshake and keepalive behavior behind the deployment NAT;
- whether `10.90.0.0/24` conflicts with any network at either endpoint;
- whether host firewall rules interfere with tunnel traffic;
- whether SSH over `10.90.0.4` works as expected;
- any service-management differences on the target Debian/Raspberry Pi OS release.

## Phase 1 exit criteria

Phase 1 is complete only after a real `gway-004` has demonstrated:

1. a persistent WireGuard handshake from behind NAT;
2. bidirectional reachability between `10.90.0.1` and `10.90.0.4`;
3. management access through the tunnel without public device SSH exposure;
4. documented firewall/network findings.

DNS enrollment and `gway-004.arthexis.com` public HTTP routing intentionally remain later phases.
