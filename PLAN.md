# gway-wireguard Implementation Plan

## Purpose

`gway-wireguard` will initially be a **private** repository and will provide a small, auditable mechanism for giving deployed Gway-family boxes a stable Internet identity such as:

```text
gway-004.arthexis.com
audi-003.arthexis.com
```

A box must be able to bootstrap itself from a fresh supported Debian/Raspberry Pi OS installation by cloning this repository and running one command:

```bash
sudo ./install.sh
```

The box must not require a public IP address, router port forwarding, or direct exposure of SSH to the Internet.

The initial deployment target is `arthexis.com`, with the public gateway hosted on the existing Gelectriic server. The design must not hard-code the `gway` brand so the same mechanism can later support other device prefixes or customer-specific identities.

---

## Goals

1. One-command client installation from a cloned repository.
2. Stable public device names such as `gway-004.arthexis.com`.
3. Outbound-only tunnel establishment from deployed boxes.
4. WireGuard as the encrypted device-to-gateway transport.
5. Public HTTP/HTTPS traffic terminated at the central server and proxied through WireGuard.
6. Administrative services such as SSH remain private to the WireGuard network by default.
7. Device private keys are generated locally and never transmitted.
8. Enrollment is authenticated with short-lived or one-time credentials.
9. DNS credentials remain on the control server and never reach deployed boxes.
10. Installation, repair, and reinstallation are idempotent.
11. Server-side components maintain an explicit registry of enrolled devices.
12. DNS integration begins with GoDaddy but is isolated behind a provider interface.
13. The implementation is small enough to audit and test independently from the main Arthexis/Gway repository.

---

## Non-goals for the first release

- General-purpose VPN management.
- Full mesh networking between deployed boxes.
- Public exposure of SSH, databases, or arbitrary local ports.
- Wildcard `*.arthexis.com` routing.
- Automatic discovery of arbitrary services on a box.
- A large web administration UI.
- Replacing the main Gway provisioning/imaging system.
- Supporting multiple VPN backends in the first release.

---

## Proposed Architecture

```text
                         Internet
                            |
                +-----------+-----------+
                |                       |
       gway-004.arthexis.com     vpn.arthexis.com
                |                       |
              HTTPS                WireGuard/UDP
                |                       |
                v                       v
        +---------------------------------------+
        |      Central Arthexis gateway         |
        |                                       |
        |  nginx/Caddy      WireGuard wg0       |
        |       |              10.90.0.1        |
        |       |                   |            |
        |       +-------------------+            |
        |                    |                  |
        |             enrollment service        |
        |             device registry           |
        |             DNS provider adapter      |
        +--------------------+------------------+
                             |
                       encrypted tunnel
                             |
                     +-------v--------+
                     |    gway-004    |
                     | 10.90.0.4/32   |
                     | local service  |
                     | e.g. :8000     |
                     +----------------+
```

The deployed box initiates the WireGuard connection. No inbound port forwarding is required at the deployment site.

---

## Naming Model

The public hostname is derived from the device identity:

```text
<device-id>.arthexis.com
```

Examples:

```text
gway-004.arthexis.com
audi-003.arthexis.com
```

The implementation must treat the device ID as opaque after validation; it must not assume that all IDs begin with `gway-`.

Initial validation should allow conservative DNS-safe names only:

```text
[a-z0-9][a-z0-9-]{0,62}
```

Additional policy, such as permitted prefixes, can live on the server.

---

## Repository Layout

Initial target layout:

```text
gway-wireguard/
├── PLAN.md
├── README.md
├── LICENSE
├── VERSION
├── install.sh
├── uninstall.sh
├── client/
│   ├── enroll.py
│   ├── status.py
│   ├── config.py
│   └── systemd/
│       └── gway-wireguard.service
├── server/
│   ├── install.sh
│   ├── app/
│   │   ├── api.py
│   │   ├── registry.py
│   │   ├── wireguard.py
│   │   ├── proxy.py
│   │   └── dns/
│   │       ├── base.py
│   │       └── godaddy.py
│   └── systemd/
├── tests/
│   ├── client/
│   ├── server/
│   └── integration/
└── docs/
    ├── enrollment.md
    ├── security.md
    └── operations.md
```

`install.sh` at repository root is the primary user-facing entry point for a deployed box.

---

## Client Installation Flow

The expected operator workflow is:

```bash
git clone https://github.com/arthexis/gway-wireguard.git
cd gway-wireguard
sudo ./install.sh
```

Optional explicit identity/bootstrap arguments may be supported:

```bash
sudo ./install.sh --device gway-004 --token <one-time-token>
```

The installer performs these steps:

1. Verify root privileges.
2. Verify a supported Debian-family OS and architecture.
3. Install required system packages, primarily WireGuard and minimal runtime dependencies.
4. Determine the device identity.
5. Check for an existing installation and reuse it when valid.
6. Generate a WireGuard keypair locally if one does not already exist.
7. Read a one-time enrollment token from an argument, environment variable, provisioning file, or interactive prompt.
8. Send the device ID and WireGuard public key to the enrollment endpoint.
9. Receive the assigned VPN address, gateway endpoint, gateway public key, allowed IPs, and public hostname.
10. Write the WireGuard configuration with restrictive permissions.
11. Enable the tunnel through systemd.
12. Verify a WireGuard handshake.
13. Verify reachability of the gateway over the tunnel.
14. Verify the assigned public hostname if public routing is enabled.
15. Print a concise installation summary.

The private WireGuard key must never be sent to the enrollment server.

---

## Device Identity Resolution

The client should resolve identity using an explicit and deterministic precedence order:

1. `--device`
2. Existing `/etc/gway-wireguard/device-id`
3. Existing Gway device identity, if a stable supported location/API exists
4. System hostname when it passes validation

Once enrolled, the resolved identity is persisted and does not silently change because the Linux hostname changes.

Changing a device identity after enrollment must be an explicit re-enrollment operation.

---

## Client State

Persistent state should live under:

```text
/etc/gway-wireguard/
```

Suggested files:

```text
/etc/gway-wireguard/device-id
/etc/gway-wireguard/private.key
/etc/gway-wireguard/public.key
/etc/gway-wireguard/config.json
```

WireGuard runtime configuration should use the normal system location:

```text
/etc/wireguard/gway.conf
```

All sensitive files must be owned by root with restrictive permissions.

---

## WireGuard Network

Initial private network:

```text
10.90.0.0/24
```

Example allocation:

```text
Gateway       10.90.0.1
gway-004      10.90.0.4
audi-003      10.90.0.8
```

The server registry, not the client, allocates addresses.

Initial clients should use a narrow `AllowedIPs` configuration. Do not route ordinary Internet traffic through the gateway.

A typical client peer configuration will include:

```ini
Endpoint = vpn.arthexis.com:51820
PersistentKeepalive = 25
```

The exact keepalive value should remain configurable.

---

## Enrollment Protocol

Initial endpoint:

```text
POST https://register.arthexis.com/v1/enroll
```

Conceptual request:

```json
{
  "device_id": "gway-004",
  "public_key": "<wireguard-public-key>",
  "token": "<one-time-enrollment-token>"
}
```

Conceptual response:

```json
{
  "device_id": "gway-004",
  "hostname": "gway-004.arthexis.com",
  "vpn_address": "10.90.0.4/32",
  "gateway_address": "10.90.0.1",
  "gateway_endpoint": "vpn.arthexis.com:51820",
  "gateway_public_key": "<gateway-public-key>",
  "allowed_ips": ["10.90.0.0/24"]
}
```

The final schema should be versioned from the beginning.

---

## Enrollment Token Model

The repository must contain no reusable production enrollment secret.

Preferred first implementation:

1. Administrator creates a one-time enrollment token on the server.
2. Token is provided to the installer.
3. Token authorizes one specific device ID or one enrollment.
4. Successful enrollment consumes the token.
5. Permanent authentication thereafter relies on the enrolled device key and explicitly designed control-plane credentials if needed.

Tokens should have an expiration time and be stored server-side as hashes rather than plaintext where practical.

---

## Server Device Registry

The central server is the source of truth for enrolled devices.

Minimum record:

```text
device_id
hostname
wireguard_public_key
vpn_address
enabled
created_at
updated_at
```

Useful later fields:

```text
last_handshake
last_seen
public_http_enabled
service_port
customer
notes
```

SQLite is sufficient for the initial implementation if access is serialized and backup/restore is documented. The registry layer should make migration to PostgreSQL straightforward if needed later.

---

## DNS Management

The deployed client must never receive GoDaddy credentials.

Enrollment triggers a server-side DNS operation:

```text
gway-004.arthexis.com -> <gateway-public-ip>
```

The DNS subsystem should expose a small provider-neutral interface such as:

```python
ensure_record(hostname, record_type, value)
delete_record(hostname)
```

The first provider implementation will target GoDaddy.

This keeps future migration to Cloudflare, Route 53, or another DNS provider from affecting the client protocol.

No wildcard `*.arthexis.com` record is required.

---

## Reverse Proxy

The gateway terminates public TLS and proxies only explicitly registered hostnames.

Conceptually:

```text
gway-004.arthexis.com
        ->
10.90.0.4:<registered-service-port>
```

Unknown hostnames must not be dynamically mapped to arbitrary WireGuard peers.

Initial behavior for an unknown or disabled device hostname should be a normal 404/closed response.

The reverse-proxy configuration should be generated from the device registry or accessed through a safe dynamic configuration mechanism.

The first implementation should use whichever proxy is already appropriate on the Gelectriic server. The integration layer should avoid coupling the entire project to one proxy implementation.

---

## Public vs Administrative Services

Public hostname:

```text
https://gway-004.arthexis.com
```

This exposes only services explicitly marked public.

Administrative access remains inside the WireGuard network:

```bash
ssh arthe@10.90.0.4
```

Do not expose these by default through public DNS/proxy routing:

- SSH
- database ports
- debugging servers
- device management APIs
- unrestricted local HTTP ports

The firewall should enforce this distinction rather than relying only on application convention.

---

## Idempotency

Running:

```bash
sudo ./install.sh
```

multiple times must be safe.

The installer should:

- detect the existing identity;
- retain an existing private key;
- validate current configuration;
- repair missing systemd/configuration pieces;
- avoid requesting a new VPN address unnecessarily;
- avoid duplicate DNS records;
- report "no changes required" when appropriate.

A `--re-enroll` flag may later permit intentional replacement of enrollment state.

---

## Uninstall and Revocation

Client uninstall:

```bash
sudo ./uninstall.sh
```

must stop and disable the local tunnel and remove installed configuration according to explicit options.

Destructive removal of the device private key should require an explicit flag.

Server-side revocation is more important than client uninstall. Revocation must be able to:

1. disable the WireGuard peer;
2. disable public proxy routing;
3. optionally remove the DNS record;
4. invalidate any remaining control-plane credentials.

A lost/stolen box must therefore be revocable without access to the box itself.

---

## Status and Diagnostics

Initial client diagnostic command can be:

```bash
sudo ./install.sh --status
```

or a dedicated script/module exposed later as:

```text
gway-wireguard status
```

Expected information:

```text
Device:          gway-004
Hostname:        gway-004.arthexis.com
VPN address:     10.90.0.4
Endpoint:        vpn.arthexis.com:51820
Tunnel:          connected
Last handshake:  <age>
Public route:    healthy
```

Diagnostics must never print private keys or enrollment secrets.

---

## Security Requirements

The first implementation must enforce these boundaries:

- Device WireGuard private keys are generated on-device.
- Private keys never leave the device.
- DNS provider credentials exist only on the server.
- Enrollment credentials are one-time or short-lived.
- Enrollment is HTTPS-only.
- Device IDs are validated before use in DNS, files, commands, or proxy configuration.
- Server-side command execution must not interpolate untrusted values into shell commands.
- Peer IP allocation is controlled centrally.
- WireGuard peers do not automatically receive access to each other.
- Public routing is explicit per device.
- SSH is not public by default.
- Sensitive files use restrictive permissions.
- Logs redact tokens and secrets.
- Revocation is supported from the first usable release.

---

## Firewall Policy

The public gateway should require only the ports needed for the design, approximately:

```text
TCP 80/443      HTTPS/TLS
UDP 51820       WireGuard
```

SSH access to the gateway itself should follow the server's existing administrative policy.

WireGuard forwarding rules should permit only the flows actually required by the reverse proxy and administration.

Do not enable unrestricted peer-to-peer forwarding.

---

## Server Installation

The server portion should eventually support:

```bash
cd gway-wireguard/server
sudo ./install.sh
```

It should:

1. install WireGuard and required runtime packages;
2. generate/persist the gateway keypair;
3. configure the WireGuard interface;
4. configure firewall rules;
5. install the enrollment service;
6. initialize the registry;
7. configure the DNS provider;
8. configure the reverse-proxy integration;
9. enable services;
10. run health checks.

Server installation should be repeatable and should not overwrite unrelated nginx/Caddy configuration.

---

## Configuration

Configuration must be externalized rather than hard-coded.

Example server settings:

```text
BASE_DOMAIN=arthexis.com
PUBLIC_GATEWAY_IP=54.161.177.151
VPN_HOSTNAME=vpn.arthexis.com
REGISTER_HOSTNAME=register.arthexis.com
WG_INTERFACE=wg0
WG_NETWORK=10.90.0.0/24
WG_PORT=51820
DNS_PROVIDER=godaddy
```

Secrets must not be committed to the repository.

Use a root-readable environment/configuration file or systemd credentials/secrets mechanism appropriate to the host.

---

## Testing Strategy

### Unit tests

Cover:

- device ID validation;
- identity resolution;
- address allocation;
- enrollment token consumption;
- registry operations;
- WireGuard configuration generation;
- DNS desired-state logic;
- reverse-proxy mapping generation;
- idempotent installer decisions.

### Integration tests

Use network namespaces/containers where practical to simulate:

```text
gateway <-> NAT <-> device
```

Verify:

- client can establish a tunnel from behind NAT;
- repeat enrollment does not duplicate peers;
- revoked devices lose access;
- public service routing reaches only the intended peer;
- one device cannot impersonate another hostname;
- unknown hostnames do not proxy;
- client-to-client access is blocked unless explicitly enabled.

### Installation tests

CI should test supported Debian releases in containers/VMs where possible.

Real Raspberry Pi validation remains a release-readiness step for ARM-specific behavior.

---

## CI

Initial GitHub Actions should include:

1. shell syntax/static checks for user-facing scripts;
2. Python tests;
3. formatting/linting if Python is used;
4. configuration-generation tests;
5. installation smoke tests on Debian;
6. secret scanning/no-production-secret checks.

Tests should verify present behavior and security invariants rather than existing solely to prove removed features stay removed.

---

## Implementation Phases

### Phase 0 — Repository bootstrap

- Create repository as private initially.
- Add `PLAN.md`.
- Add README, license, VERSION, `.gitignore`.
- Add empty client/server/test package structure.
- Establish CI skeleton.

### Phase 1 — Manual WireGuard proof of concept

- Configure gateway WireGuard interface.
- Configure one test box (`gway-004`) manually.
- Validate connection from behind NAT.
- Validate management access through private VPN IP.
- Keep DNS/proxy automation out of this phase.

Success criterion:

```text
gateway <-> gway-004
```

has stable WireGuard connectivity and no inbound deployment-site configuration.

### Phase 2 — Client installer

- Implement `install.sh`.
- Generate/reuse local keys.
- Persist identity.
- Generate WireGuard config.
- Configure systemd.
- Add status/health reporting.
- Make reruns idempotent.

Success criterion:

A fresh Gway box can become a working WireGuard peer from one installer invocation plus bootstrap credentials.

### Phase 3 — Enrollment service

- Implement registry.
- Implement one-time tokens.
- Allocate VPN addresses.
- Add/remove WireGuard peers.
- Implement revocation.

Success criterion:

No manual editing of server WireGuard configuration is needed when adding a box.

### Phase 4 — DNS automation

- Add DNS provider interface.
- Implement GoDaddy provider.
- Create/update explicit device A records.
- Add `vpn.arthexis.com` and `register.arthexis.com` operational records as required.

Success criterion:

Enrolling `gway-004` can ensure `gway-004.arthexis.com` points to the gateway without exposing DNS credentials to the device.

### Phase 5 — HTTPS reverse proxy

- Register intended local service port.
- Generate safe hostname-to-peer routing.
- Obtain/renew TLS certificates.
- Reject unknown/disabled mappings.
- Add proxy health checks.

Success criterion:

```text
https://gway-004.arthexis.com
```

reaches only the intended public service on `gway-004`.

### Phase 6 — Hardening

- Firewall tests.
- Peer isolation.
- Token expiration and replay protection.
- Rate limiting for enrollment.
- Revocation tests.
- Backup/restore for registry and server keys.
- Failure/recovery documentation.
- Threat-model review.

### Phase 7 — Integration with Gway provisioning

Keep this repository usable independently, but allow a Gway image/provisioner to call it automatically.

Possible end-state UX:

```bash
gway wireguard enroll
gway wireguard status
```

The main Gway project should consume this repository's stable interface rather than absorbing its implementation.

---

## Initial Deployment Sequence

For the first real box, use this order:

1. Confirm control of `54.161.177.151`.
2. Create `gway-004.arthexis.com` pointing to `54.161.177.151`.
3. Add `vpn.arthexis.com` pointing to `54.161.177.151`.
4. Add `register.arthexis.com` when the enrollment service exists.
5. Install WireGuard on the gateway.
6. Establish a manual `gway-004` peer.
7. Verify NAT traversal and handshake behavior.
8. Implement the client installer around the known-working configuration.
9. Implement enrollment and server-side peer automation.
10. Implement GoDaddy DNS automation.
11. Implement HTTPS reverse-proxy routing.
12. Harden and automate tests.

The public DNS record for a device may be created before the proxy is enabled, but it must not unintentionally expose unrelated services on the gateway.

---

## Key Design Decisions

The initial design intentionally chooses:

- explicit hostnames such as `gway-004.arthexis.com`;
- a central public gateway rather than exposing boxes directly;
- WireGuard rather than direct port forwarding;
- outbound tunnel establishment from boxes;
- local generation of device private keys;
- server-owned DNS credentials;
- explicit DNS records rather than a wildcard;
- explicit public-service mappings rather than arbitrary port forwarding;
- private SSH/administration over WireGuard;
- a provider abstraction around GoDaddy;
- an independent repository that Gway can later consume.

These are the defaults unless implementation experience shows a concrete reason to revise them.