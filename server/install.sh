#!/usr/bin/env bash
# Server bootstrap entry point.
# Usage: sudo ./server/install.sh
#
# Phase 0 intentionally does not modify the gateway. Server installation is
# implemented after the manual WireGuard proof of concept in PLAN.md.

set -euo pipefail

printf '%s\n' "gway-wireguard server installation is not implemented yet." >&2
printf '%s\n' "See PLAN.md for the implementation phases." >&2
exit 1
