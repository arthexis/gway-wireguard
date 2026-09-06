#!/usr/bin/env bash
# Guard against EXIT traps referencing function-local temporary variables under set -u.
# Usage: ./tests/client/test-cleanup-regression.sh

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
INSTALL="${ROOT}/install.sh"

# The installer must keep cleanup state in an initialized global so EXIT cleanup
# remains valid after apply_wireguard_config returns.
grep -q '^TMP_CONFIG=""$' "${INSTALL}"
grep -q '^trap cleanup EXIT$' "${INSTALL}"

if grep -Eq "trap .*\\$\\{?tmp\\}?" "${INSTALL}"; then
    echo "EXIT trap must not capture a function-local tmp variable" >&2
    exit 1
fi
