#!/usr/bin/env bash
# Prepare or apply the Phase 1 WireGuard client proof of concept.
# Usage:
#   sudo ./client/manual-setup.sh prepare
#   sudo SERVER_PUBLIC_KEY='<gateway-public-key>' ./client/manual-setup.sh apply
#   sudo ./client/manual-setup.sh status

set -euo pipefail

ACTION="${1:-help}"
WG_INTERFACE="${WG_INTERFACE:-gway}"
CLIENT_ADDRESS="${CLIENT_ADDRESS:-10.90.0.4/32}"
SERVER_TUNNEL_IP="${SERVER_TUNNEL_IP:-10.90.0.1/32}"
SERVER_ENDPOINT="${SERVER_ENDPOINT:-54.161.177.151:51820}"
KEEPALIVE="${KEEPALIVE:-25}"
STATE_DIR="${STATE_DIR:-/etc/gway-wireguard}"
PRIVATE_KEY="${STATE_DIR}/private.key"
PUBLIC_KEY="${STATE_DIR}/public.key"
WG_CONFIG="/etc/wireguard/${WG_INTERFACE}.conf"

usage() {
    cat <<'EOF'
Phase 1 client setup

Commands:
  prepare  Install WireGuard if needed and create the device keypair.
  apply    Write the client configuration and enable the tunnel.
  status   Show the device public key and WireGuard status.

For apply, provide the gateway public key:
  sudo SERVER_PUBLIC_KEY='<key>' ./client/manual-setup.sh apply

Optional environment variables:
  WG_INTERFACE      Interface name (default: gway)
  CLIENT_ADDRESS    Device tunnel address (default: 10.90.0.4/32)
  SERVER_TUNNEL_IP  Allowed gateway tunnel IP (default: 10.90.0.1/32)
  SERVER_ENDPOINT   Public gateway endpoint (default: 54.161.177.151:51820)
  KEEPALIVE         PersistentKeepalive seconds (default: 25)
  STATE_DIR         Key/state directory (default: /etc/gway-wireguard)
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
        echo "error: SERVER_PUBLIC_KEY does not look like a WireGuard public key" >&2
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
        echo "Device public key: $(cat "${PUBLIC_KEY}")"
        echo "Next: give this public key to the gateway, then apply with SERVER_PUBLIC_KEY."
        ;;
    apply)
        require_root
        install_wireguard
        prepare_keys
        : "${SERVER_PUBLIC_KEY:?set SERVER_PUBLIC_KEY to the gateway WireGuard public key}"
        validate_public_key "${SERVER_PUBLIC_KEY}"
        install -d -m 700 /etc/wireguard
        tmp="$(mktemp)"
        trap 'rm -f "${tmp}"' EXIT
        cat >"${tmp}" <<EOF
[Interface]
Address = ${CLIENT_ADDRESS}
PrivateKey = $(cat "${PRIVATE_KEY}")

[Peer]
PublicKey = ${SERVER_PUBLIC_KEY}
Endpoint = ${SERVER_ENDPOINT}
AllowedIPs = ${SERVER_TUNNEL_IP}
PersistentKeepalive = ${KEEPALIVE}
EOF
        install -m 600 "${tmp}" "${WG_CONFIG}"
        systemctl enable --now "wg-quick@${WG_INTERFACE}.service"
        echo "Client configured on ${WG_INTERFACE}; public key: $(cat "${PUBLIC_KEY}")"
        echo "Test with: ping -c 3 ${SERVER_TUNNEL_IP%/*}"
        ;;
    status)
        require_root
        if [[ -s "${PUBLIC_KEY}" ]]; then
            echo "Device public key: $(cat "${PUBLIC_KEY}")"
        fi
        wg show "${WG_INTERFACE}"
        ;;
    *)
        echo "error: unknown command '${ACTION}'" >&2
        usage >&2
        exit 2
        ;;
esac
