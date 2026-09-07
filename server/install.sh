#!/usr/bin/env bash
# Install or inspect the gway-wireguard gateway services.
# Usage:
#   sudo ./server/install.sh
#   sudo ./server/install.sh --status
#   ./server/install.sh --check
#
# Existing WireGuard configuration is preserved. Managed peers and DNS records
# are reconciled without replacing unrelated host configuration.

set -euo pipefail

SOURCE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PACKAGE_DIR="${SOURCE_DIR}/../src/gway_wireguard"
STATE_DIR="${STATE_DIR:-/etc/gway-wireguard}"
INSTALL_DIR="${INSTALL_DIR:-/opt/gway-wireguard/server}"
DATA_DIR="${DATA_DIR:-/var/lib/gway-wireguard}"
WG_INTERFACE="${WG_INTERFACE:-gway}"
WG_ADDRESS="${WG_ADDRESS:-10.90.0.1/24}"
WG_NETWORK="${WG_NETWORK:-10.90.0.0/24}"
WG_PORT="${WG_PORT:-51820}"
GATEWAY_ADDRESS="${GATEWAY_ADDRESS:-10.90.0.1}"
GATEWAY_ENDPOINT="${GATEWAY_ENDPOINT:-54.161.177.151:51820}"
BASE_DOMAIN="${BASE_DOMAIN:-arthexis.com}"
HOSTS_FILE="${HOSTS_FILE:-/etc/hosts}"
ENROLL_BIND="${ENROLL_BIND:-127.0.0.1}"
ENROLL_PORT="${ENROLL_PORT:-8787}"
DNS_PROVIDER="${DNS_PROVIDER:-none}"
PUBLIC_GATEWAY_IP="${PUBLIC_GATEWAY_IP:-54.161.177.151}"
DNS_TTL="${DNS_TTL:-600}"
VPN_HOSTNAME="${VPN_HOSTNAME:-vpn.${BASE_DOMAIN}}"
REGISTER_HOSTNAME="${REGISTER_HOSTNAME:-register.${BASE_DOMAIN}}"
GODADDY_KEY_FILE="${GODADDY_KEY_FILE:-${STATE_DIR}/godaddy.key}"
GODADDY_SECRET_FILE="${GODADDY_SECRET_FILE:-${STATE_DIR}/godaddy.secret}"
WG_CONFIG="/etc/wireguard/${WG_INTERFACE}.conf"
PRIVATE_KEY="${STATE_DIR}/server.key"
PUBLIC_KEY="${STATE_DIR}/server.pub"
ENV_FILE="${STATE_DIR}/server.env"
SERVICE_NAME="gway-wireguard-enroll.service"
MODE="install"

usage() {
    cat <<'EOF'
gway-wireguard Phase 4 server installer

Usage:
  sudo ./server/install.sh
  sudo ./server/install.sh --status
  ./server/install.sh --check

Modes:
  --status   Show WireGuard, enrollment, registry, and non-secret DNS status.
  --check    Validate local server code/config defaults without changing the host.
  -h, --help

Environment defaults for a new server.env:
  STATE_DIR, INSTALL_DIR, DATA_DIR
  WG_INTERFACE, WG_ADDRESS, WG_NETWORK, WG_PORT
  GATEWAY_ADDRESS, GATEWAY_ENDPOINT
  BASE_DOMAIN, HOSTS_FILE, ENROLL_BIND, ENROLL_PORT
  DNS_PROVIDER, PUBLIC_GATEWAY_IP, DNS_TTL
  VPN_HOSTNAME, REGISTER_HOSTNAME
  GODADDY_KEY_FILE, GODADDY_SECRET_FILE

DNS_PROVIDER defaults to "none". To enable GoDaddy on an existing gateway, set
GWAY_DNS_PROVIDER=godaddy in /etc/gway-wireguard/server.env, store the API key
and secret in the configured root-readable credential files, and rerun this
installer. DNS credentials are never copied to enrolled devices.

The enrollment API binds to 127.0.0.1 by default. Expose it only through an
HTTPS reverse proxy, or explicitly configure TLS in server.env. The service
refuses cleartext HTTP on a non-loopback bind address.
EOF
}

die() {
    printf 'error: %s\n' "$*" >&2
    exit 1
}

require_root() {
    [[ "${EUID}" -eq 0 ]] || die "run this command as root (for example with sudo)"
}

install_dependencies() {
    if command -v wg >/dev/null 2>&1 \
        && command -v wg-quick >/dev/null 2>&1 \
        && command -v python3 >/dev/null 2>&1 \
        && [[ -d /etc/ssl/certs ]]; then
        return
    fi
    [[ -f /etc/debian_version ]] && command -v apt-get >/dev/null 2>&1 \
        || die "supported server installation requires Debian-family Linux with apt"
    apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get install -y wireguard python3 ca-certificates
}

prepare_keys() {
    install -d -o root -g root -m 700 "${STATE_DIR}"
    if [[ ! -s "${PRIVATE_KEY}" ]]; then
        umask 077
        wg genkey >"${PRIVATE_KEY}"
    fi
    chmod 600 "${PRIVATE_KEY}"
    wg pubkey <"${PRIVATE_KEY}" >"${PUBLIC_KEY}"
    chmod 644 "${PUBLIC_KEY}"
}

ensure_wireguard_config() {
    install -d -o root -g root -m 700 /etc/wireguard
    if [[ -e "${WG_CONFIG}" ]]; then
        return
    fi
    umask 077
    cat >"${WG_CONFIG}" <<EOF
[Interface]
Address = ${WG_ADDRESS}
ListenPort = ${WG_PORT}
PrivateKey = $(cat "${PRIVATE_KEY}")
EOF
    chmod 600 "${WG_CONFIG}"
}

install_server_files() {
    [[ -d "${PACKAGE_DIR}" ]] || die "missing packaged implementation: ${PACKAGE_DIR}"
    install -d -o root -g root -m 755 "${INSTALL_DIR}"
    install -o root -g root -m 755 \
        "${SOURCE_DIR}/enroll_api.py" \
        "${SOURCE_DIR}/admin.py" \
        "${INSTALL_DIR}/"
    install -o root -g root -m 644 \
        "${SOURCE_DIR}/registry.py" \
        "${SOURCE_DIR}/hosts_manager.py" \
        "${SOURCE_DIR}/peer_manager.py" \
        "${INSTALL_DIR}/"

    rm -rf "${INSTALL_DIR}/gway_wireguard"
    cp -a "${PACKAGE_DIR}" "${INSTALL_DIR}/gway_wireguard"
    chown -R root:root "${INSTALL_DIR}/gway_wireguard"
    find "${INSTALL_DIR}/gway_wireguard" -type d -exec chmod 755 {} +
    find "${INSTALL_DIR}/gway_wireguard" -type f -exec chmod 644 {} +

    install -d -o root -g root -m 700 "${DATA_DIR}"
    install -o root -g root -m 644 \
        "${SOURCE_DIR}/systemd/${SERVICE_NAME}" \
        "/etc/systemd/system/${SERVICE_NAME}"
}

append_env_if_missing() {
    local key="$1"
    local value="$2"
    if ! grep -q "^${key}=" "${ENV_FILE}"; then
        printf '%s=%s\n' "${key}" "${value}" >>"${ENV_FILE}"
    fi
}

ensure_environment() {
    install -d -o root -g root -m 700 "${STATE_DIR}"
    if [[ ! -e "${ENV_FILE}" ]]; then
        umask 077
        cat >"${ENV_FILE}" <<EOF
GWAY_REGISTRY_DB=${DATA_DIR}/registry.sqlite3
GWAY_WG_CONFIG=${WG_CONFIG}
GWAY_WG_INTERFACE=${WG_INTERFACE}
GWAY_WG_NETWORK=${WG_NETWORK}
GWAY_GATEWAY_ADDRESS=${GATEWAY_ADDRESS}
GWAY_GATEWAY_ENDPOINT=${GATEWAY_ENDPOINT}
GWAY_GATEWAY_PUBLIC_KEY=${PUBLIC_KEY}
GWAY_BASE_DOMAIN=${BASE_DOMAIN}
GWAY_HOSTS_FILE=${HOSTS_FILE}
GWAY_ENROLL_BIND=${ENROLL_BIND}
GWAY_ENROLL_PORT=${ENROLL_PORT}
GWAY_APPLY_RUNTIME=1
GWAY_DNS_PROVIDER=${DNS_PROVIDER}
GWAY_PUBLIC_GATEWAY_IP=${PUBLIC_GATEWAY_IP}
GWAY_DNS_TTL=${DNS_TTL}
GWAY_VPN_HOSTNAME=${VPN_HOSTNAME}
GWAY_REGISTER_HOSTNAME=${REGISTER_HOSTNAME}
GWAY_GODADDY_KEY_FILE=${GODADDY_KEY_FILE}
GWAY_GODADDY_SECRET_FILE=${GODADDY_SECRET_FILE}
EOF
    else
        append_env_if_missing GWAY_DNS_PROVIDER "${DNS_PROVIDER}"
        append_env_if_missing GWAY_PUBLIC_GATEWAY_IP "${PUBLIC_GATEWAY_IP}"
        append_env_if_missing GWAY_DNS_TTL "${DNS_TTL}"
        append_env_if_missing GWAY_VPN_HOSTNAME "${VPN_HOSTNAME}"
        append_env_if_missing GWAY_REGISTER_HOSTNAME "${REGISTER_HOSTNAME}"
        append_env_if_missing GWAY_GODADDY_KEY_FILE "${GODADDY_KEY_FILE}"
        append_env_if_missing GWAY_GODADDY_SECRET_FILE "${GODADDY_SECRET_FILE}"
    fi
    chmod 600 "${ENV_FILE}"
}

load_environment() {
    set -a
    # shellcheck disable=SC1090
    source "${ENV_FILE}"
    set +a
}

validate_dns_configuration() {
    load_environment
    case "${GWAY_DNS_PROVIDER:-none}" in
        none|disabled|"")
            return
            ;;
        godaddy)
            local key_file="${GWAY_GODADDY_KEY_FILE:-${STATE_DIR}/godaddy.key}"
            local secret_file="${GWAY_GODADDY_SECRET_FILE:-${STATE_DIR}/godaddy.secret}"
            if [[ -z "${GWAY_GODADDY_KEY:-}" ]]; then
                [[ -s "${key_file}" ]] || die "GoDaddy key file is missing or empty: ${key_file}"
                chmod 600 "${key_file}"
            fi
            if [[ -z "${GWAY_GODADDY_SECRET:-}" ]]; then
                [[ -s "${secret_file}" ]] || die "GoDaddy secret file is missing or empty: ${secret_file}"
                chmod 600 "${secret_file}"
            fi
            ;;
        *)
            die "unsupported GWAY_DNS_PROVIDER '${GWAY_DNS_PROVIDER}'"
            ;;
    esac
}

initialize_registry() {
    load_environment
    python3 "${INSTALL_DIR}/admin.py" init >/dev/null
    chmod 600 "${DATA_DIR}/registry.sqlite3"
    python3 "${INSTALL_DIR}/admin.py" sync-hosts >/dev/null
}

initialize_dns() {
    load_environment
    case "${GWAY_DNS_PROVIDER:-none}" in
        none|disabled|"")
            return
            ;;
    esac
    PYTHONPATH="${INSTALL_DIR}${PYTHONPATH:+:${PYTHONPATH}}" \
        python3 - <<'PY'
from gway_wireguard.admin_ops import sync_dns

result = sync_dns()
print(
    "DNS records updated" if result["changed"] else "DNS records already current"
)
PY
}

enable_services() {
    systemctl enable "wg-quick@${WG_INTERFACE}.service" >/dev/null
    if ! systemctl is-active --quiet "wg-quick@${WG_INTERFACE}.service"; then
        systemctl start "wg-quick@${WG_INTERFACE}.service"
    fi

    systemctl daemon-reload
    systemctl enable "${SERVICE_NAME}" >/dev/null
    if systemctl is-active --quiet "${SERVICE_NAME}"; then
        systemctl restart "${SERVICE_NAME}"
    else
        systemctl start "${SERVICE_NAME}"
    fi
}

show_status() {
    require_root
    printf 'Gateway public key: %s\n' "$(cat "${PUBLIC_KEY}" 2>/dev/null || printf 'not prepared')"
    printf 'WireGuard service:  '
    systemctl is-active "wg-quick@${WG_INTERFACE}.service" 2>/dev/null || true
    printf 'Enrollment service: '
    systemctl is-active "${SERVICE_NAME}" 2>/dev/null || true
    if [[ -r "${ENV_FILE}" && -x "${INSTALL_DIR}/admin.py" ]]; then
        printf '\n'
        load_environment
        python3 "${INSTALL_DIR}/admin.py" list
        PYTHONPATH="${INSTALL_DIR}${PYTHONPATH:+:${PYTHONPATH}}" \
            python3 - <<'PY'
from gway_wireguard.admin_ops import dns_status

status = dns_status()
print(
    f"DNS provider: {status['provider']} "
    f"(enabled={status['enabled']}, valid={status['valid']})"
)
PY
    fi
}

check_source() {
    command -v python3 >/dev/null 2>&1 || die "python3 is required for --check"
    PYTHONPATH="${SOURCE_DIR}/../src${PYTHONPATH:+:${PYTHONPATH}}" \
        python3 -m py_compile \
            "${SOURCE_DIR}/registry.py" \
            "${SOURCE_DIR}/hosts_manager.py" \
            "${SOURCE_DIR}/peer_manager.py" \
            "${SOURCE_DIR}/enroll_api.py" \
            "${SOURCE_DIR}/admin.py" \
            "${PACKAGE_DIR}/registry.py" \
            "${PACKAGE_DIR}/hosts_manager.py" \
            "${PACKAGE_DIR}/peer_manager.py" \
            "${PACKAGE_DIR}/admin_ops.py" \
            "${PACKAGE_DIR}/dns/provider.py" \
            "${PACKAGE_DIR}/dns/godaddy.py" \
            "${PACKAGE_DIR}/dns/service.py" \
            "${PACKAGE_DIR}/gway/dns.py"
    PYTHONPATH="${SOURCE_DIR}/../src${PYTHONPATH:+:${PYTHONPATH}}" \
    GWAY_REGISTRY_DB="/tmp/gway-wireguard-check.sqlite3" \
    GWAY_WG_CONFIG="/tmp/gway-wireguard-check.conf" \
    GWAY_HOSTS_FILE="/tmp/gway-wireguard-check.hosts" \
    GWAY_DNS_PROVIDER=none \
    GWAY_APPLY_RUNTIME=0 \
        python3 "${SOURCE_DIR}/enroll_api.py" check >/dev/null
    printf 'server source/configuration valid\n'
}

while (($#)); do
    case "$1" in
        --status)
            MODE="status"
            ;;
        --check)
            MODE="check"
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            die "unknown argument '$1'"
            ;;
    esac
    shift
done

case "${MODE}" in
    check)
        check_source
        ;;
    status)
        show_status
        ;;
    install)
        require_root
        install_dependencies
        prepare_keys
        ensure_wireguard_config
        install_server_files
        ensure_environment
        validate_dns_configuration
        initialize_registry
        initialize_dns
        enable_services
        load_environment
        cat <<EOF
Phase 4 gateway services installed.

Gateway public key: $(cat "${PUBLIC_KEY}")
Registry:           ${DATA_DIR}/registry.sqlite3
Private hostnames:  ${HOSTS_FILE}
Enrollment bind:    ${ENROLL_BIND}:${ENROLL_PORT}
DNS provider:       ${GWAY_DNS_PROVIDER:-none}

GWAY administrative commands include:
  sudo gway wireguard token create --device gway-004
  sudo gway wireguard dns status
  sudo gway wireguard dns sync

Compatibility enrollment/admin scripts remain installed under:
  ${INSTALL_DIR}

The enrollment endpoint must still be terminated through HTTPS. Phase 5 will
automate hostname-to-WireGuard reverse-proxy routing.
EOF
        ;;
    *)
        die "internal error: unknown mode '${MODE}'"
        ;;
esac
