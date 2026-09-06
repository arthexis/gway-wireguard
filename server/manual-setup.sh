#!/usr/bin/env bash
# Prepare or apply the Phase 1 WireGuard gateway proof of concept.
# Usage:
#   sudo ./server/manual-setup.sh prepare
#   sudo CLIENT_PUBLIC_KEY='<gway-004-public-key>' ./server/manual-setup.sh apply
#   sudo ./server/manual-setup.sh status

set -euo pipefail

ACTION="${1:-help}"
WG_INTERFACE="${WG_INTERFACE:-gway}"
SERVER_ADDRESS="${SERVER_ADDRESS:-10.90.0.1/24}"
CLIENT_ADDRESS="${CLIENT_ADDRESS:-10.90.0.4/32}"
LISTEN_PORT="${LISTEN_PORT:-51820}"
STATE_DIR="${STATE_DIR:-/etc/gway-wireguard}"
PRIVATE_KEY="${STATE_DIR}/server.key"
PUBLIC_KEY="${STATE_DIR}/server.pub"
WG_CONFIG="/etc/wireguard/${WG_INTERFACE}.conf"

usage() {
    cat <<'EOF'
Phase 1 gateway setup

Commands:
  prepare  Install WireGuard if needed and create the gateway keypair.
  apply    Write the gateway configuration and enable the tunnel.
  status   Show the gateway public key and WireGuard status.

For apply, provide the client public key:
  sudo CLIENT_PUBLIC_KEY='<key>' ./server/manual-setup.sh apply

Optional environment variables:
  WG_INTERFACE     Interface name (default: gway)
  SERVER_ADDRESS   Gateway tunnel address (default: 10.90.0.1/24)
  CLIENT_ADDRESS   Client AllowedIPs entry (default: 10.90.0.4/32)
  LISTEN_PORT      UDP listen port (default: 51820)
  STATE_DIR        Key/state directory (default: /etc/gway-wireguard)
EOF
}

require_root() {
    if [[ ${EUID} -ne 0 ]]; then
        echo "error: run this command as root (for example with sudo)" >&2
        exit 1
    fi
}

install_wireguard() {
    if command -v wg >/dev/null 2>&1 && command -v wg-quick >/dev/null 2>&1; then
        return
    fi
    if [[ ! -f /etc/debian_version ]] || ! command -v apt-get >/dev/null 2>&1; then
        echo "error: Phase 1 currently supports Debian-family systems with apt" >&2
        exit 1
    fi
    apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get install -y wireguard
}

prepare_keys() {
    install -d -m 700 "${STATE_DIR}"
    if [[ ! -s "${PRIVATE_KEY}" ]]; then
        umask 077
        wg genkey >"${PRIVATE_KEY}"
    fi
    wg pubkey <"${PRIVATE_KEY}" >"${PUBLIC_KEY}"
    chmod 600 "${PRIVATE_KEY}"
    chmod 644 "${PUBLIC_KEY}"
}

validate_public_key() {
    local key="$1"
    if [[ ! "${key}" =~ ^[A-Za-z0-9+/]{43}=$ ]]; then
        echo "error: CLIENT_PUBLIC_KEY does not look like a WireGuard public key" >&2
        exit 1
    fi
}

case "${ACTION}" in
    -h|--help|help)
        usage
        exit 0
        ;;
    prepare)
        require_root
        install_wireguard
        prepare_keys
        echo "Gateway public key: $(cat "${PUBLIC_KEY}")"
        echo "Next: prepare the client, then rerun this script with CLIENT_PUBLIC_KEY and 'apply'."
        ;;
    apply)
        require_root
        install_wireguard
        prepare_keys
        : "${CLIENT_PUBLIC_KEY:?set CLIENT_PUBLIC_KEY to the gway-004 WireGuard public key}"
        validate_public_key "${CLIENT_PUBLIC_KEY}"
        install -d -m 700 /etc/wireguard
        tmp="$(mktemp)"
        trap 'rm -f "${tmp}"' EXIT
        cat >"${tmp}" <<EOF
[Interface]
Address = ${SERVER_ADDRESS}
ListenPort = ${LISTEN_PORT}
PrivateKey = $(cat "${PRIVATE_KEY}")

[Peer]
PublicKey = ${CLIENT_PUBLIC_KEY}
AllowedIPs = ${CLIENT_ADDRESS}
EOF
        install -m 600 "${tmp}" "${WG_CONFIG}"
        systemctl enable --now "wg-quick@${WG_INTERFACE}.service"
        echo "Gateway configured on ${WG_INTERFACE}; public key: $(cat "${PUBLIC_KEY}")"
        echo "Ensure the provider/host firewall permits inbound UDP ${LISTEN_PORT}."
        ;;
    status)
        require_root
        if [[ -s "${PUBLIC_KEY}" ]]; then
            echo "Gateway public key: $(cat "${PUBLIC_KEY}")"
        fi
        wg show "${WG_INTERFACE}"
        ;;
    *)
        echo "error: unknown command '${ACTION}'" >&2
        usage >&2
        exit 2
        ;;
esac
