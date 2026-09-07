# Phase 3: authenticated enrollment

Phase 3 removes the manual server-side peer-registration step from a fresh client install. The gateway now owns device registration, one-time enrollment tokens, VPN address allocation, managed WireGuard peers, private administrative hostname resolution, and revocation.

## Components

The server implementation is intentionally small and uses only the Python standard library:

- `server/registry.py` — SQLite device registry, hashed one-time tokens, serialized address allocation.
- `server/peer_manager.py` — non-destructive persistent/runtime WireGuard peer updates.
- `server/hosts_manager.py` — managed `/etc/hosts` block for private short device names.
- `server/enroll_api.py` — versioned `POST /v1/enroll` API and `/health`.
- `server/admin.py` — registry initialization, token creation, device listing, hostname sync, and revocation.
- `server/install.sh` — idempotent Debian-family server installation.
- `client/enroll.py` — strict HTTPS enrollment client used by root `install.sh`.

The default registry is `/var/lib/gway-wireguard/registry.sqlite3`. Enrollment tokens are stored only as SHA-256 hashes. A token is consumed only after the peer update and private hostname update succeed.

## 1. Install the gateway service

On the existing WireGuard gateway:

```bash
git pull
sudo ./server/install.sh
```

The installer reuses `/etc/gway-wireguard/server.key` and `server.pub`. If `/etc/wireguard/gway.conf` already exists, it is preserved rather than regenerated. This is important for the Phase 1/2 `gway-001` peer.

New Phase 3 peers are stored in clearly delimited managed blocks. Existing unmanaged peers are left untouched and their `AllowedIPs` are treated as reserved during address allocation.

The enrollment API defaults to:

```text
127.0.0.1:8787
```

It refuses cleartext HTTP on a non-loopback bind address.

## 2. Put enrollment behind HTTPS

The client accepts only an `https://` enrollment URL. The intended endpoint remains:

```text
https://register.arthexis.com/v1/enroll
```

DNS and reverse-proxy automation are Phases 4 and 5, so during Phase 3 validation the gateway's existing HTTPS termination must proxy the registration hostname/path to:

```text
http://127.0.0.1:8787
```

Do not expose the loopback HTTP listener directly to the Internet.

As an alternative for an explicitly managed deployment, `server.env` supports `GWAY_TLS_CERT` and `GWAY_TLS_KEY`; when both are configured the service can serve TLS directly. Certificate provisioning itself is not part of Phase 3.

## 3. Create a one-time token

Create a device-scoped token:

```bash
sudo /opt/gway-wireguard/server/admin.py token --device gway-004
```

The default lifetime is one hour. Override it in seconds:

```bash
sudo /opt/gway-wireguard/server/admin.py token --device gway-004 --ttl 1800
```

The plaintext token is printed once. The registry stores only its hash. A token can authorize only one successful enrollment and cannot be replayed.

Omitting `--device` creates a token valid for any one syntactically valid device ID:

```bash
sudo /opt/gway-wireguard/server/admin.py token
```

Device-scoped tokens are preferred for normal provisioning.

## 4. Enroll a fresh device

On the device:

```bash
git clone https://github.com/arthexis/gway-wireguard.git
cd gway-wireguard
sudo ./install.sh --device gway-004 --token '<one-time-token>'
```

To avoid putting the token in the shell command line:

```bash
sudo ./install.sh --device gway-004 --token-file /root/gway-enrollment.token
```

or provide `GWAY_ENROLL_TOKEN` through the provisioning environment.

The installer:

1. generates/reuses the device WireGuard key locally;
2. sends only the device ID, public key, and one-time token over HTTPS;
3. receives its registry-assigned `/32`, gateway endpoint/public key, and hostname;
4. enforces a narrow gateway-only `AllowedIPs` value (`10.90.0.1/32`);
5. persists non-secret enrollment state;
6. starts or repairs `wg-quick@gway`.

The private WireGuard key and enrollment token are never sent to logs or persisted by the installer.

A rerun with a complete local configuration does not call the enrollment API and does not consume another token.

## Address allocation and existing peers

The default pool is `10.90.0.0/24`, with `10.90.0.1` reserved for the gateway.

Allocation considers both registry rows and every peer `AllowedIPs` already present in `/etc/wireguard/gway.conf`. For example, the currently validated manual `gway-001` peer at `10.90.0.2/32` causes the first fresh registry enrollment to receive `10.90.0.3/32`, not `.2`.

The service does not automatically claim a public key already present in an unmanaged peer. That prevents silent migration or duplicate peer definitions.

## Private administrative hostnames

Every enabled Phase 3 registry device is also rendered into a delimited block in the gateway's `/etc/hosts`. The registry remains the source of truth: the short name is the `device_id`, while the address is the allocated WireGuard `/32`.

For example, enrollment of `gway-004` at `10.90.0.3/32` produces:

```text
# BEGIN gway-wireguard managed hosts
10.90.0.3    gway-004
# END gway-wireguard managed hosts
```

This makes administrative access from the gateway use the stable device identity rather than an address:

```bash
ssh arthe@gway-004
```

Only the marked block is managed. Existing `/etc/hosts` entries before or after it are preserved. Re-running the sync is safe and idempotent:

```bash
sudo /opt/gway-wireguard/server/admin.py sync-hosts
```

This private short-name resolution is intentionally separate from public DNS. `gway-004.arthexis.com` remains the public-service hostname handled by later DNS/proxy phases; `gway-004` resolves directly to its WireGuard address only on the gateway.

The current `gway-001` predates the Phase 3 registry, so the gateway cannot safely infer its identity from an unmanaged WireGuard peer. Until it is explicitly migrated into the registry, add its already-validated mapping once outside the managed block:

```bash
echo '10.90.0.2 gway-001' | sudo tee -a /etc/hosts
```

The managed sync preserves that line.

## Revocation

List registered devices:

```bash
sudo /opt/gway-wireguard/server/admin.py list
```

Revoke one:

```bash
sudo /opt/gway-wireguard/server/admin.py revoke gway-004
```

Revocation removes the live WireGuard peer, removes its managed persistent block, marks the registry record disabled, and removes its managed private short hostname. A revoked device cannot re-enroll merely by obtaining another token.

DNS/proxy removal joins this revocation flow in later phases.

## Server configuration

`server/install.sh` creates root-readable:

```text
/etc/gway-wireguard/server.env
```

Important settings include:

```text
GWAY_REGISTRY_DB=/var/lib/gway-wireguard/registry.sqlite3
GWAY_WG_CONFIG=/etc/wireguard/gway.conf
GWAY_WG_INTERFACE=gway
GWAY_WG_NETWORK=10.90.0.0/24
GWAY_GATEWAY_ADDRESS=10.90.0.1
GWAY_GATEWAY_ENDPOINT=54.161.177.151:51820
GWAY_GATEWAY_PUBLIC_KEY=/etc/gway-wireguard/server.pub
GWAY_BASE_DOMAIN=arthexis.com
GWAY_HOSTS_FILE=/etc/hosts
GWAY_ENROLL_BIND=127.0.0.1
GWAY_ENROLL_PORT=8787
```

The file is preserved on installer reruns so operator changes are not silently overwritten.

## Validation

Before mutating either host:

```bash
./server/install.sh --check
./install.sh --check \
  --device gway-004 \
  --token placeholder \
  --enroll-url https://register.arthexis.com/v1/enroll
```

After gateway installation:

```bash
sudo ./server/install.sh --status
curl http://127.0.0.1:8787/health
sudo wg show gway
```

After enrolling a real box, verify:

```bash
sudo ./install.sh --status
ping -c 3 10.90.0.1
```

and from the gateway:

```bash
getent hosts gway-004
ping -c 3 gway-004
ssh arthe@gway-004
```

Phase 3 is live-validated when a fresh box enrolls with one token, the gateway adds it without manual WireGuard editing or disturbing `gway-001`, the short private hostname resolves to its allocated WireGuard address, bidirectional tunnel access works, replaying the consumed token fails, and server-side revocation removes access and the managed short name.
