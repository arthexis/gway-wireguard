# Live server readiness and public enrollment ownership

This document defines the next server-readiness increment for `gway-wire`, based on the first Ubuntu 22 / Raspberry Pi live validation.

## Goal

`gway wire server check <fqdn>` should answer the operational question: **is this gateway actually ready for a fresh remote device to enroll and establish WireGuard connectivity?**

A configuration-only success is not sufficient. The default check must cover the same prerequisites that were manually validated during the live test.

## Endpoint identity

Wire accepts the exact public enrollment hostname as an FQDN. It does not infer a base domain, prepend `register`, or split a hostname into domain/subdomain components.

The canonical CLI spelling is:

```text
gway wire server deploy --fqdn register.example.com
```

`--domain` is retained only as an alias for `--fqdn`. Both spellings feed the same internal `fqdn` value; there is no second domain value and conflicting duplicate values must be rejected.

## Ownership boundary

`gway-wire` owns the VPN/enrollment service, its lifecycle, and the decision to expose its enrollment endpoint.

`gway-web` is a dependency used by Wire to realize public HTTP(S) exposure for the exact FQDN supplied by Wire, including:

- reverse-proxy exposure to `127.0.0.1:<enrollment-port>`;
- provider-backed public DNS record provisioning;
- TLS certificate provisioning/renewal;
- Nginx/backend activation;
- public HTTPS and health validation.

`gway-wire` should not grow another Nginx/Certbot/DNS implementation. It should call Web's Python capability directly.

Web should not expose a separate user-facing `register` or `unregister` lifecycle for this operation. Wire calls Web, not the other way around, and Wire remains the owner of the enrollment endpoint lifecycle.

For an FQDN such as `register.example.com`, the desired endpoint is:

```text
https://register.example.com/v1/enroll
        -> gway-web capability
        -> 127.0.0.1:8787
        -> gway-wire enrollment service
```

The enrollment service must remain loopback-only by default. Port 8787 must not be exposed directly.

### Required `gway-web` capability

The current `gway-web` implementation can define/serve sites, manage Certbot, test Nginx, and perform public checks, but its DNS module currently targets ACME DNS-01 TXT records. Before Wire can delegate the whole public endpoint transaction, Web must expose provider-neutral ordinary record management for the site's public address (initially an A record; AAAA later where appropriate).

The dependency-facing contract should be an idempotent capability along the lines of:

```python
web.ensure(
    fqdn="register.example.com",
    upstream="http://127.0.0.1:8787",
    health_path="/health",
    certbot=True,
    dns_provider="godaddy",
)
```

The operation should validate the provider and desired external state before committing local managed state, reconcile an existing matching site safely, and leave no successful local registration if provider/public setup fails.

Wire's readiness path should use Web's read-only check capability for the same exact FQDN. No provider-specific API should leak into Wire.

## Default server checks

With no selector flags, `gway wire server check <fqdn>` should run **all** applicable checks and return a structured result for each. Selector flags should allow running one subset when diagnosing a failure.

### 1. Source / package readiness

Equivalent to the current installer `--check` preflight.

Validate that the installed Wire project/server source can be used without mutation.

### 2. Deployed configuration

Validate:

- deployed environment exists and parses;
- configured enrollment FQDN matches the requested FQDN;
- registry exists;
- required paths are present;
- selected protocol is supported.

Wire must not derive `register.<domain>` or otherwise reinterpret the supplied FQDN.

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

Delegate to `gway-web` for the supplied FQDN.

Validate that the FQDN resolves to the intended public address. Provider credentials being syntactically valid are not enough; the live record must be checked.

DNS setup should also be delegated to Web so Wire does not duplicate GoDaddy-specific record lifecycle code for the enrollment endpoint.

### 9. Web exposure / reverse proxy

Delegate to Web's check capability for the supplied FQDN.

Validate that the public site is actually enabled and routes to the enrollment loopback service.

This catches the exact failure seen in live validation where Wire reported the enrollment service active but no `register.arthexis.com` Nginx vhost existed.

### 10. TLS certificate

Delegate to Web's certificate check for the supplied FQDN.

Validate:

- certificate exists;
- certificate matches the FQDN;
- certificate is currently valid;
- public HTTPS presents that certificate.

This catches the fallback/expired-certificate failure observed during the live test.

### 11. Public HTTPS / health

Delegate to Web's public/health checks for the supplied FQDN.

From the server this should validate the complete public path as far as practical, for example:

```text
https://register.example.com/health
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
    "fqdn": "register.example.com",
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

`gway wire server deploy --fqdn <fqdn>` should converge Wire-owned state directly and request public enrollment exposure through Web as one dependency operation:

1. validate the exact FQDN and deploy the WireGuard server/enrollment service;
2. ask Web to ensure the FQDN's provider-backed DNS, reverse proxy, TLS, and public exposure transactionally;
3. run the full readiness suite, including Web's read-only checks for that FQDN;
4. report success only when required checks pass.

`--domain <fqdn>` is an alias for the same input; it does not represent a separate base domain.

Web must not expose an independent user-facing registration/unregistration workflow for this endpoint. The lifecycle remains attached to Wire's deploy/remove operations.

This preserves existing Nginx sites such as Odoo and other hosted applications because Web owns transactional site configuration rather than Wire editing Nginx globally.

## Compatibility and safety

- Must continue to support Ubuntu 22 / Python 3.10 as the server compatibility floor.
- Checks are read-only; `server check` must never mutate DNS, certificates, Nginx, interfaces, peers, or registry state.
- `server deploy` may mutate public exposure only through Web's owning capability.
- Enrollment tokens must not be issued automatically as part of readiness checks.
- No check should require at least one enrolled device.
- Existing/manual WireGuard peers must be preserved.

## Acceptance criteria

The implementation following this proposal is complete when:

1. `server deploy --fqdn register.example.com` and `server deploy --domain register.example.com` resolve to the same canonical `fqdn` input without domain/subdomain inference.
2. A fresh Ubuntu 22 server with WireGuard installed but no Web exposure fails readiness with a specific Web/public-endpoint reason.
3. Missing `wg`, missing `gway` interface, missing UDP 51820 listener, missing loopback 8787 listener, and failed local enrollment health are individually detected.
4. A valid local service with missing DNS for the supplied FQDN fails the DNS/public check.
5. A correct DNS record with an expired/wrong certificate fails TLS readiness, matching the failure observed in the live test.
6. `gway-web` is the dependency used to provision DNS, Nginx exposure, Certbot, and public endpoint checks, without a separate user-facing Web register/unregister operation.
7. A fresh server with zero enrolled devices can still report ready.
8. Existing manual peers remain valid and are reported without being adopted or removed.
9. Unit tests cover each failure independently and an all-green aggregate case.
10. Ubuntu 22 / Python 3.10 CI remains green.
