# Phase 4 — Public DNS automation

Phase 4 adds server-side public DNS reconciliation without changing the deployed-device enrollment protocol.

## Goals

- keep DNS provider credentials only on the central gateway;
- manage explicit A records rather than a wildcard;
- isolate GoDaddy behind a provider-neutral interface;
- make DNS updates idempotent;
- ensure enrollment creates/repairs the device public hostname;
- remove a revoked device's public DNS record without weakening revocation if the provider is unavailable;
- expose operator actions through base GWAY rather than another handwritten CLI.

## Managed records

Initial public target:

```text
vpn.arthexis.com          -> <public gateway IPv4>
register.arthexis.com     -> <public gateway IPv4>
gway-004.arthexis.com     -> <public gateway IPv4>
```

Every device hostname comes from the server registry. Device numeric suffixes do not determine WireGuard addresses and DNS never points a device name directly at its private `10.90.0.0/24` address.

## Provider configuration

The default is deliberately disabled:

```text
GWAY_DNS_PROVIDER=none
```

To enable GoDaddy, edit the gateway's root-readable server environment:

```text
/etc/gway-wireguard/server.env
```

and set:

```text
GWAY_DNS_PROVIDER=godaddy
GWAY_PUBLIC_GATEWAY_IP=54.161.177.151
GWAY_DNS_TTL=600
GWAY_VPN_HOSTNAME=vpn.arthexis.com
GWAY_REGISTER_HOSTNAME=register.arthexis.com
GWAY_GODADDY_KEY_FILE=/etc/gway-wireguard/godaddy.key
GWAY_GODADDY_SECRET_FILE=/etc/gway-wireguard/godaddy.secret
```

Store the GoDaddy API key and secret separately with root-only permissions:

```bash
sudo install -o root -g root -m 600 /dev/null /etc/gway-wireguard/godaddy.key
sudo install -o root -g root -m 600 /dev/null /etc/gway-wireguard/godaddy.secret
sudo editor /etc/gway-wireguard/godaddy.key
sudo editor /etc/gway-wireguard/godaddy.secret
```

The files contain only the credential value with surrounding whitespace stripped. Direct `GWAY_GODADDY_KEY` and `GWAY_GODADDY_SECRET` environment variables are also supported for controlled automation, but credential files are preferred on the gateway.

Do not place GoDaddy credentials in this repository, device provisioning data, enrollment tokens, or any deployed client state.

## Install/reconcile

After configuring the provider, rerun the idempotent server installer:

```bash
cd gway-wireguard
sudo ./server/install.sh
```

When DNS is enabled, the installer validates credential availability and runs a DNS sync before restarting the enrollment service.

The canonical GWAY operations are:

```bash
gway wireguard dns status
gway wireguard dns sync
gway wireguard dns ensure gway-004
gway wireguard dns delete gway-004
```

`dns status` never returns the key or secret. `dns ensure` accepts a registry device ID, not an arbitrary hostname. `dns delete` likewise resolves the hostname through the registry so the command cannot be used as a generic DNS deletion primitive.

## Enrollment behavior

When DNS is disabled, Phase 3 enrollment behavior is unchanged.

When DNS is enabled, enrollment performs this logical sequence inside the local registry transaction:

1. validate the enrollment request/token;
2. create or reuse the registry device row;
3. ensure the WireGuard peer;
4. reconcile the private short hostname;
5. ensure `<device-id>.arthexis.com` points to the configured public gateway IPv4;
6. consume the one-time token;
7. commit the registry transaction and return the normal enrollment response.

DNS is an external side effect, so the DNS manager captures the previous record set before changing it. If a later enrollment step fails, it restores the previous DNS record set while the local transaction/peer/hosts state is rolled back.

## Revocation behavior

Revocation still treats WireGuard access as the security boundary:

1. remove live/persistent WireGuard access;
2. mark the registry row disabled;
3. remove the private short hostname;
4. best-effort delete the explicit public A record.

A DNS provider failure after revocation is reported as a warning and does not restore network access. Re-running revocation for an already-disabled device retries private-host and DNS cleanup.

## Provider interface

Desired-state logic lives in `gway_wireguard.dns.service`. Provider adapters implement only record transport operations:

```python
get_records(name, record_type)
replace_records(name, record_type, records)
delete_records(name, record_type)
```

The initial `GoDaddyProvider` uses GoDaddy's v1 domain-record endpoint and `Authorization: sso-key <key>:<secret>`. Provider-specific code does not know about enrollment tokens, WireGuard peers, registry allocation, GWAY CLI parsing, or revocation policy.

## Live validation checklist

Before marking Phase 4 complete:

1. configure GoDaddy credentials on the actual gateway;
2. run `gway wireguard dns status` and confirm provider/configuration is valid without credential disclosure;
3. run `gway wireguard dns sync` twice and confirm the second run is unchanged;
4. verify `vpn.arthexis.com` and `register.arthexis.com` resolve to the gateway public IPv4;
5. enroll a fresh test device and verify its explicit public A record appears;
6. verify an enrollment retry/repair does not duplicate DNS records;
7. revoke the test device and verify its public record disappears;
8. temporarily induce a provider failure in a controlled test and confirm revocation still removes WireGuard access;
9. confirm no GoDaddy credentials exist on the enrolled device.

Phase 5 will use these explicit public hostnames to generate safe HTTPS hostname-to-peer reverse-proxy routing.
