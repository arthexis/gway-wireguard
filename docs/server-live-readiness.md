# Live server readiness and public enrollment ownership

This document defines the next server-readiness increment for `gway-wire`, based on the first Ubuntu 22 / Raspberry Pi live validation.

## Goal

`gway wire server check <domain>` should answer the operational question: **is this gateway actually ready for a fresh remote device to enroll and establish WireGuard connectivity?**

A configuration-only success is not sufficient. The default check must cover the same prerequisites that were manually validated during the live test.

## Ownership boundary

`gway-wire` owns the VPN/enrollment service and describes the public enrollment endpoint it needs.

`gway-web` owns public HTTP(S) exposure, including:

- the `register.<domain>` site definition;
- reverse-proxy exposure to `127.0.0.1:<enrollment-port>`;
- public DNS record provisioning;
- TLS certificate provisioning/renewal;
- Nginx/backend activation;
- public HTTPS and health validation.

`gway-wire` should not grow another Nginx/Certbot/DNS implementation. It should delegate public endpoint setup and checks through the `gway web` surface.

The desired endpoint is:

```text
https://register.<domain>/v1/enroll
        -> gway web
        -> 127.0.0.1:8787
        -> gway-wire enrollment service
```

The enrollment service must remain loopback-only by default. Port 8787 must not be exposed directly.

### Required `gway-web` capability

The current `gway-web` implementation can define/serve sites, manage Certbot, test Nginx, and perform public checks, but its DNS module currently targets ACME DNS-01 TXT records. Before Wire can delegate the whole public endpoint transaction, Web must expose provider-neutral ordinary record management for the site's public address (initially an A record; AAAA later where appropriate).

The intended Wire orchestration is equivalent to:

```text
gway web site wire-register --create \
  --domain register.example.com \
  --host 127.0.0.1 \
  --port 8787 \
  --health-path /health \
  --certbot

gway web dns wire-register --ensure
gway web serve wire-register ...
gway web check wire-register
```

Exact Web CLI spelling may evolve, but Wire should depend on the capability rather than provider-specific APIs.

## Default server checks

With no selector flags, `gway wire server check <domain>` should run **all** applicable checks and return a structured result for each. Selector flags should allow running one subset when diagnosing a failure.

### 1. Source / package readiness

Equivalent to the current installer `--check` preflight.

Validate that the installed Wire project/server source can be used without mutation.

### 2. Deployed configuration

Validate:

- deployed environment exists and parses;
- configured base domain matches the requested domain;
- registry exists;
- expected `vpn.<domain>` and `register.<domain>` hostnames match;
- required paths are present;
- selected protocol is supported.

### 3. WireGuard tooling

Validate the underlying WireGuard dependency that we manually checked with:

```text
wg --version
```

The check should fail clearly if `wg` is missing or unusable.

### 4. WireGuard interface

Validate the configured interface, normally `gway`, equivalent to:

```text
ip link show type wireguard
wg show gway
```

Report at least:

- interface exists;
- interface is up;
- public key is available;
- configured listen port;
- peer count.

A peer handshake is useful diagnostic information but must not be required on a new server with no enrolled devices.

### 5. UDP listener

Validate that the configured WireGuard port, normally UDP 51820, is actually listening. This is the programmatic equivalent of:

```text
ss -lunp | grep 51820
```

Do not accidentally test TCP 51820.

### 6. Enrollment service process/listener

Validate that the local enrollment service is active and bound to the expected loopback address/port, normally:

```text
127.0.0.1:8787
```

Equivalent manual validation:

```text
ss -lntp | grep 8787
```

The check should fail if the service is unexpectedly bound to a public wildcard address unless explicitly configured otherwise.

### 7. Local enrollment HTTP health

Probe the enrollment service directly over loopback. The health route must be defined as part of the enrollment API contract rather than assumed by deployment scripts.

Preferred contract:

```text
GET /health
```

A successful response proves the process behind the listener is the expected enrollment application, not merely an arbitrary process occupying the port.

### 8. Public DNS

Delegate to `gway web`.

Validate that `register.<domain>` resolves to the intended public address. Provider credentials being syntactically valid are not enough; the live record must be checked.

DNS setup should also be delegated to Web so Wire does not duplicate GoDaddy-specific record lifecycle code for the enrollment endpoint.

### 9. Web exposure / reverse proxy

Delegate to `gway web check wire-register --nginx` (or equivalent capability).

Validate that the public site is actually enabled and routes to the enrollment loopback service.

This catches the exact failure seen in live validation where Wire reported the enrollment service active but no `register.arthexis.com` Nginx vhost existed.

### 10. TLS certificate

Delegate to Web's certificate check.

Validate:

- certificate exists;
- certificate matches `register.<domain>`;
- certificate is currently valid;
- public HTTPS presents that certificate.

This catches the fallback/expired-certificate failure observed during the live test.

### 11. Public HTTPS / health

Delegate to `gway web check` public/health checks.

From the server this should validate the complete public path as far as practical:

```text
https://register.<domain>/health
```

The result must distinguish DNS, TLS, HTTP, and application-health failures so operators know which layer to repair.

### 12. Managed peers

Keep the existing managed-peer inspection, but treat zero managed peers as valid for a fresh deployment.

Report managed peer count and configured addresses. Existing unmanaged/manual peers must not be treated as errors.

## Proposed selector surface

The current source/config/DNS/peers selectors should expand without changing the default rule that no flags means all checks.

Suggested selectors:

```text
--source
--config
--wireguard
--listener
--enrollment
--web
--dns
--tls
--public
--peers
```

`--web` may group Nginx/exposure checks, while `--public` performs end-to-end HTTPS health. The exact grouping should favor a small stable CLI over one flag per implementation detail.

## Result semantics

The command should return an aggregate readiness result plus individual checks, for example:

```python
{
    "domain": "example.com",
    "ready": False,
    "checks": [
        {"check": "wireguard-tool", "ok": True, "detail": "wireguard-tools ..."},
        {"check": "wireguard-interface", "ok": True, "detail": "gway udp/51820"},
        {"check": "enrollment-local", "ok": True, "detail": "127.0.0.1:8787"},
        {"check": "public-dns", "ok": True, "detail": "register.example.com -> ..."},
        {"check": "tls", "ok": False, "detail": "certificate expired"},
    ],
}
```

A failed diagnostic check should normally be represented in the result rather than aborting the rest of the suite, so one invocation reveals all actionable problems.

## Deploy behavior

`gway wire server deploy --domain <domain>` should converge only Wire-owned state directly. Public enrollment setup should be requested through Web:

1. deploy/validate WireGuard server and enrollment service;
2. declare/update the `wire-register` Web site;
3. ask Web to ensure public DNS;
4. ask Web to serve the site with TLS;
5. run the full readiness suite;
6. report success only when required checks pass.

This preserves existing Nginx sites such as Odoo and other hosted applications because Web owns transactional site configuration rather than Wire editing Nginx globally.

## Compatibility and safety

- Must continue to support Ubuntu 22 / Python 3.10 as the server compatibility floor.
- Checks are read-only; `server check` must never mutate DNS, certificates, Nginx, interfaces, peers, or registry state.
- `server deploy` may mutate only through explicit owning capabilities.
- Enrollment tokens must not be issued automatically as part of readiness checks.
- No check should require at least one enrolled device.
- Existing/manual WireGuard peers must be preserved.

## Acceptance criteria

The implementation following this proposal is complete when:

1. A fresh Ubuntu 22 server with WireGuard installed but no Web site fails readiness with a specific Web/public-endpoint reason.
2. Missing `wg`, missing `gway` interface, missing UDP 51820 listener, missing loopback 8787 listener, and failed local enrollment health are individually detected.
3. A valid local service with missing `register.<domain>` DNS fails the DNS/public check.
4. A correct DNS record with an expired/wrong certificate fails TLS readiness, matching the failure observed in the live test.
5. `gway web` is the owner used to provision DNS, Nginx exposure, Certbot, and public endpoint checks.
6. A fresh server with zero enrolled devices can still report ready.
7. Existing manual peers remain valid and are reported without being adopted or removed.
8. Unit tests cover each failure independently and an all-green aggregate case.
9. Ubuntu 22 / Python 3.10 CI remains green.
