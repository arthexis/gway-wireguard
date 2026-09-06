#!/usr/bin/env bash
# Validate non-mutating Phase 2 client installer behavior.
# Usage: ./tests/client/test-install.sh

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
INSTALL="${ROOT}/install.sh"
KEY='AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA='

"${INSTALL}" --help >/dev/null

"${INSTALL}" --check \
    --device gway-004 \
    --server-public-key "${KEY}" \
    --client-address 10.90.0.4/32 \
    --server-endpoint 54.161.177.151:51820 \
    --server-tunnel-ip 10.90.0.1/32 \
    --keepalive 25 >/dev/null

if "${INSTALL}" --check \
    --device 'bad/name' \
    --server-public-key "${KEY}" \
    --client-address 10.90.0.4/32 >/dev/null 2>&1; then
    echo "expected invalid device id to fail" >&2
    exit 1
fi

if "${INSTALL}" --check \
    --device gway-004 \
    --server-public-key "${KEY}" \
    --client-address 10.90.0.999/32 >/dev/null 2>&1; then
    echo "expected invalid client address to fail" >&2
    exit 1
fi

if "${INSTALL}" --check \
    --device gway-004 \
    --server-public-key bad-key \
    --client-address 10.90.0.4/32 >/dev/null 2>&1; then
    echo "expected invalid WireGuard public key to fail" >&2
    exit 1
fi

# Real-device validation additionally exercises the mutating apply path; see
# tests/client/test-cleanup-regression.sh for the EXIT-cleanup invariant found
# during the first gway-001 deployment.
