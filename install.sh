#!/usr/bin/env bash
# Install, enroll, or repair the gway-wireguard client.
# Usage:
#   sudo ./install.sh --device gway-004 --token '<one-time-token>'
#   sudo ./install.sh --status
#   sudo ./install.sh --prepare [--device gway-004]
#
# Phase 3 adds authenticated enrollment while retaining the Phase 2 manual
# configuration path for recovery and staged deployments.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STATE_DIR="${STATE_DIR:-/etc/gway-wireguard}"
WG_INTERFACE="${WG_INTERFACE:-gway}"
WG_CONFIG="/etc/wireguard/${WG_INTERFACE}.conf"
DEFAULT_ENDPOINT="${DEFAULT_ENDPOINT:-54.161.177.151:51820}"
DEFAULT_SERVER_TUNNEL_IP="${DEFAULT_SERVER_TUNNEL_IP:-10.90.0.1/32}"
DEFAULT_KEEPALIVE="${DEFAULT_KEEPALIVE:-25}"
DEFAULT_ENROLL_URL="${GWAY_ENROLL_URL:-https://register.arthexis.com/v1/enroll}"

MODE="install"
DEVICE_ID=""
SERVER_PUBLIC_KEY=""
CLIENT_ADDRESS=""
SERVER_ENDPOINT=""
SERVER_TUNNEL_IP=""
KEEPALIVE=""
PUBLIC_HOSTNAME=""
ENROLL_URL="${DEFAULT_ENROLL_URL}"
TOKEN="${GWAY_ENROLL_TOKEN:-}"
TOKEN_FILE="${GWAY_ENROLL_TOKEN_FILE:-}"
TMP_CONFIG=""
TMP_ENROLL=""

cleanup() {
    [[ -z "${TMP_CONFIG}" ]] || rm -f -- "${TMP_CONFIG}"
    [[ -z "${TMP_ENROLL}" ]] || rm -f -- "${TMP_ENROLL}"
}
trap cleanup EXIT

usage() {
    cat <<'EOF'
gway-wireguard client installer

Usage:
  sudo ./install.sh --device DEVICE --token TOKEN
  sudo ./install.sh [options]
  sudo ./install.sh --prepare [--device DEVICE]
  sudo ./install.sh --status
  ./install.sh --check [options]

Fresh enrollment:
  --device DEVICE
  --token TOKEN                       One-time enrollment token.
  --token-file PATH                   Read the token from a file.
  --enroll-url HTTPS_URL              Enrollment endpoint
                                      (default: https://register.arthexis.com/v1/enroll)

Manual/recovery configuration:
  --server-public-key KEY
  --client-address CIDR
  --server-endpoint HOST:PORT         (default: 54.161.177.151:51820)
  --server-tunnel-ip CIDR             (default: 10.90.0.1/32)
  --keepalive SECONDS                 (default: 25)

Modes:
  --prepare   Install dependencies, resolve/persist identity, and generate/reuse
              the device keypair without enrolling.
  --status    Show persisted configuration and WireGuard status.
  --check     Validate supplied configuration without requiring root or
              modifying the system.
  -h, --help

Token sources:
  --token takes precedence over GWAY_ENROLL_TOKEN.
  --token-file takes precedence over GWAY_ENROLL_TOKEN_FILE when explicitly set.
  Tokens are never persisted by this installer.

Identity precedence:
  1. --device
  2. /etc/gway-wireguard/device-id
  3. current system hostname

An already configured client reuses its persisted enrollment and does not
request another VPN address or consume another token.
EOF
}

die() {
    printf 'error: %s\n' "$*" >&2
    exit 1
}

require_root() {
    [[ "${EUID}" -eq 0 ]] || die "run this command as root (for example with sudo)"
}

validate_device_id() {
    local value="$1"
    [[ "${value}" =~ ^[a-z0-9][a-z0-9-]{0,62}$ ]] \
        || die "invalid device id '${value}' (expected lowercase DNS-safe label)"
}

validate_public_key() {
    local value="$1"
    [[ "${value}" =~ ^[A-Za-z0-9+/]{43}=$ ]] \
        || die "public key does not look like a WireGuard public key"
}

validate_ipv4_cidr() {
    local value="$1"
    local ip prefix octet
    [[ "${value}" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/([0-9]|[12][0-9]|3[0-2])$ ]] \
        || die "invalid IPv4 CIDR '${value}'"
    ip="${value%/*}"
    prefix="${value#*/}"
    IFS='.' read -r -a octets <<<"${ip}"
    for octet in "${octets[@]}"; do
        (( 10#${octet} <= 255 )) || die "invalid IPv4 CIDR '${value}'"
    done
    (( prefix >= 0 && prefix <= 32 )) || die "invalid IPv4 CIDR '${value}'"
}

validate_endpoint() {
    local value="$1"
    local host port
    [[ "${value}" =~ ^[A-Za-z0-9.-]+:[0-9]{1,5}$ ]] \
        || die "invalid endpoint '${value}' (expected HOST:PORT)"
    host="${value%:*}"
    port="${value##*:}"
    [[ -n "${host}" ]] || die "invalid endpoint '${value}'"
    (( 10#${port} >= 1 && 10#${port} <= 65535 )) \
        || die "invalid endpoint port in '${value}'"
}

validate_keepalive() {
    local value="$1"
    [[ "${value}" =~ ^[0-9]{1,5}$ ]] || die "keepalive must be an integer"
    (( 10#${value} <= 65535 )) || die "keepalive must be between 0 and 65535"
}

validate_enroll_url() {
    [[ "${ENROLL_URL}" =~ ^https://[^[:space:]]+$ ]] \
        || die "enrollment URL must use HTTPS"
}

read_state() {
    local name="$1"
    local path="${STATE_DIR}/${name}"
    [[ -s "${path}" ]] && cat "${path}"
}

resolve_device_id() {
    if [[ -z "${DEVICE_ID}" ]]; then
        DEVICE_ID="$(read_state device-id || true)"
    fi
    if [[ -z "${DEVICE_ID}" ]]; then
        DEVICE_ID="$(hostname -s 2>/dev/null || true)"
        DEVICE_ID="${DEVICE_ID,,}"
    fi
    [[ -n "${DEVICE_ID}" ]] || die "could not determine device identity; use --device"
    validate_device_id "${DEVICE_ID}"
}

load_persisted_config() {
    [[ -n "${SERVER_PUBLIC_KEY}" ]] || SERVER_PUBLIC_KEY="$(read_state server-public-key || true)"
    [[ -n "${CLIENT_ADDRESS}" ]] || CLIENT_ADDRESS="$(read_state client-address || true)"
    [[ -n "${SERVER_ENDPOINT}" ]] || SERVER_ENDPOINT="$(read_state server-endpoint || true)"
    [[ -n "${SERVER_TUNNEL_IP}" ]] || SERVER_TUNNEL_IP="$(read_state server-tunnel-ip || true)"
    [[ -n "${KEEPALIVE}" ]] || KEEPALIVE="$(read_state keepalive || true)"
    [[ -n "${PUBLIC_HOSTNAME}" ]] || PUBLIC_HOSTNAME="$(read_state hostname || true)"

    SERVER_ENDPOINT="${SERVER_ENDPOINT:-${DEFAULT_ENDPOINT}}"
    SERVER_TUNNEL_IP="${SERVER_TUNNEL_IP:-${DEFAULT_SERVER_TUNNEL_IP}}"
    KEEPALIVE="${KEEPALIVE:-${DEFAULT_KEEPALIVE}}"
}

validate_install_config() {
    resolve_device_id
    load_persisted_config
    [[ -n "${SERVER_PUBLIC_KEY}" ]] || die "missing gateway public key or enrollment token"
    [[ -n "${CLIENT_ADDRESS}" ]] || die "missing client address or enrollment token"
    validate_public_key "${SERVER_PUBLIC_KEY}"
    validate_ipv4_cidr "${CLIENT_ADDRESS}"
    validate_ipv4_cidr "${SERVER_TUNNEL_IP}"
    validate_endpoint "${SERVER_ENDPOINT}"
    validate_keepalive "${KEEPALIVE}"
}

install_dependencies() {
    if command -v wg >/dev/null 2>&1 \
        && command -v wg-quick >/dev/null 2>&1 \
        && command -v python3 >/dev/null 2>&1; then
        return
    fi
    [[ -f /etc/debian_version ]] && command -v apt-get >/dev/null 2>&1 \
        || die "supported installation requires a Debian-family system with apt"
    apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get install -y wireguard python3 ca-certificates
}

ensure_state_dir() {
    install -d -o root -g root -m 700 "${STATE_DIR}"
}

write_state() {
    local name="$1"
    local value="$2"
    printf '%s\n' "${value}" >"${STATE_DIR}/${name}"
    chmod 600 "${STATE_DIR}/${name}"
}

prepare_identity_and_keys() {
    resolve_device_id
    ensure_state_dir

    local saved_id
    saved_id="$(read_state device-id || true)"
    if [[ -n "${saved_id}" && "${saved_id}" != "${DEVICE_ID}" ]]; then
        die "device already enrolled locally as '${saved_id}'; refusing identity change"
    fi
    write_state device-id "${DEVICE_ID}"

    if [[ ! -s "${STATE_DIR}/private.key" ]]; then
        umask 077
        wg genkey >"${STATE_DIR}/private.key"
    fi
    chmod 600 "${STATE_DIR}/private.key"
    wg pubkey <"${STATE_DIR}/private.key" >"${STATE_DIR}/public.key"
    chmod 644 "${STATE_DIR}/public.key"
}

load_token() {
    if [[ -n "${TOKEN_FILE}" ]]; then
        [[ -r "${TOKEN_FILE}" ]] || die "cannot read enrollment token file '${TOKEN_FILE}'"
        TOKEN="$(cat "${TOKEN_FILE}")"
    fi
    [[ -n "${TOKEN}" ]] || die "fresh enrollment requires --token, --token-file, or GWAY_ENROLL_TOKEN"
}

perform_enrollment() {
    validate_enroll_url
    load_token
    command -v python3 >/dev/null 2>&1 || die "python3 is required for enrollment"

    TMP_ENROLL="$(mktemp)"
    if ! GWAY_ENROLL_TOKEN="${TOKEN}" python3 "${SCRIPT_DIR}/client/enroll.py" \
        --url "${ENROLL_URL}" \
        --device-id "${DEVICE_ID}" \
        --public-key "$(cat "${STATE_DIR}/public.key")" \
        >"${TMP_ENROLL}"; then
        die "authenticated enrollment failed"
    fi

    local -a values
    mapfile -t values <"${TMP_ENROLL}"
    (( ${#values[@]} == 5 )) || die "invalid enrollment client output"
    SERVER_PUBLIC_KEY="${values[0]}"
    CLIENT_ADDRESS="${values[1]}"
    SERVER_ENDPOINT="${values[2]}"
    SERVER_TUNNEL_IP="${values[3]}"
    PUBLIC_HOSTNAME="${values[4]}"

    TOKEN=""
    unset GWAY_ENROLL_TOKEN || true
    rm -f -- "${TMP_ENROLL}"
    TMP_ENROLL=""
}

persist_config() {
    write_state server-public-key "${SERVER_PUBLIC_KEY}"
    write_state client-address "${CLIENT_ADDRESS}"
    write_state server-endpoint "${SERVER_ENDPOINT}"
    write_state server-tunnel-ip "${SERVER_TUNNEL_IP}"
    write_state keepalive "${KEEPALIVE}"
    if [[ -n "${PUBLIC_HOSTNAME}" ]]; then
        write_state hostname "${PUBLIC_HOSTNAME}"
    fi
}

render_wireguard_config() {
    local destination="$1"
    cat >"${destination}" <<EOF
[Interface]
Address = ${CLIENT_ADDRESS}
PrivateKey = $(cat "${STATE_DIR}/private.key")

[Peer]
PublicKey = ${SERVER_PUBLIC_KEY}
Endpoint = ${SERVER_ENDPOINT}
AllowedIPs = ${SERVER_TUNNEL_IP}
PersistentKeepalive = ${KEEPALIVE}
EOF
}

apply_wireguard_config() {
    install -d -o root -g root -m 700 /etc/wireguard
    local changed=1
    TMP_CONFIG="$(mktemp)"
    render_wireguard_config "${TMP_CONFIG}"
    chmod 600 "${TMP_CONFIG}"

    if [[ -f "${WG_CONFIG}" ]] && cmp -s "${TMP_CONFIG}" "${WG_CONFIG}"; then
        changed=0
    else
        install -o root -g root -m 600 "${TMP_CONFIG}" "${WG_CONFIG}"
    fi

    systemctl enable "wg-quick@${WG_INTERFACE}.service" >/dev/null
    if systemctl is-active --quiet "wg-quick@${WG_INTERFACE}.service"; then
        if (( changed )); then
            systemctl restart "wg-quick@${WG_INTERFACE}.service"
        fi
    else
        systemctl start "wg-quick@${WG_INTERFACE}.service"
    fi

    rm -f -- "${TMP_CONFIG}"
    TMP_CONFIG=""
}

print_prepare_summary() {
    cat <<EOF
Device:            ${DEVICE_ID}
Device public key: $(cat "${STATE_DIR}/public.key")
State directory:   ${STATE_DIR}

The device private key remains local and was not printed.
Enroll with:
  sudo ./install.sh --device ${DEVICE_ID} --token <one-time-token>
EOF
}

print_install_summary() {
    cat <<EOF
Device:            ${DEVICE_ID}
Device public key: $(cat "${STATE_DIR}/public.key")
VPN address:       ${CLIENT_ADDRESS}
Gateway endpoint:  ${SERVER_ENDPOINT}
Allowed tunnel IP: ${SERVER_TUNNEL_IP}
Public hostname:   ${PUBLIC_HOSTNAME:-not configured}
WireGuard service: wg-quick@${WG_INTERFACE}
Status:             configured

Normal Internet traffic is not routed through this tunnel.
EOF
}

show_status() {
    require_root
    resolve_device_id
    printf 'Device:            %s\n' "${DEVICE_ID}"
    if [[ -s "${STATE_DIR}/public.key" ]]; then
        printf 'Device public key: %s\n' "$(cat "${STATE_DIR}/public.key")"
    else
        printf 'Device public key: not prepared\n'
    fi
    printf 'VPN address:       %s\n' "$(read_state client-address || printf 'not configured')"
    printf 'Gateway endpoint:  %s\n' "$(read_state server-endpoint || printf 'not configured')"
    printf 'Public hostname:   %s\n' "$(read_state hostname || printf 'not configured')"
    if systemctl is-active --quiet "wg-quick@${WG_INTERFACE}.service"; then
        printf 'WireGuard service: active\n'
    else
        printf 'WireGuard service: inactive\n'
    fi
    if command -v wg >/dev/null 2>&1 && wg show "${WG_INTERFACE}" >/dev/null 2>&1; then
        printf '\n'
        wg show "${WG_INTERFACE}"
    fi
}

check_configuration() {
    resolve_device_id
    if [[ -n "${TOKEN_FILE}" ]]; then
        [[ -r "${TOKEN_FILE}" ]] || die "cannot read enrollment token file '${TOKEN_FILE}'"
        TOKEN="$(cat "${TOKEN_FILE}")"
    fi
    if [[ -n "${TOKEN}" ]]; then
        validate_enroll_url
        printf 'enrollment configuration valid for %s\n' "${DEVICE_ID}"
        return
    fi
    validate_install_config
    printf 'manual configuration valid for %s\n' "${DEVICE_ID}"
}

while (($#)); do
    case "$1" in
        --prepare)
            MODE="prepare"
            ;;
        --status)
            MODE="status"
            ;;
        --check)
            MODE="check"
            ;;
        --device)
            shift
            (($#)) || die "--device requires a value"
            DEVICE_ID="$1"
            ;;
        --token)
            shift
            (($#)) || die "--token requires a value"
            TOKEN="$1"
            ;;
        --token-file)
            shift
            (($#)) || die "--token-file requires a value"
            TOKEN_FILE="$1"
            ;;
        --enroll-url)
            shift
            (($#)) || die "--enroll-url requires a value"
            ENROLL_URL="$1"
            ;;
        --server-public-key)
            shift
            (($#)) || die "--server-public-key requires a value"
            SERVER_PUBLIC_KEY="$1"
            ;;
        --client-address)
            shift
            (($#)) || die "--client-address requires a value"
            CLIENT_ADDRESS="$1"
            ;;
        --server-endpoint)
            shift
            (($#)) || die "--server-endpoint requires a value"
            SERVER_ENDPOINT="$1"
            ;;
        --server-tunnel-ip)
            shift
            (($#)) || die "--server-tunnel-ip requires a value"
            SERVER_TUNNEL_IP="$1"
            ;;
        --keepalive)
            shift
            (($#)) || die "--keepalive requires a value"
            KEEPALIVE="$1"
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
        check_configuration
        ;;
    prepare)
        require_root
        install_dependencies
        prepare_identity_and_keys
        print_prepare_summary
        ;;
    status)
        show_status
        ;;
    install)
        require_root
        install_dependencies
        prepare_identity_and_keys
        load_persisted_config
        if [[ -z "${SERVER_PUBLIC_KEY}" || -z "${CLIENT_ADDRESS}" ]]; then
            perform_enrollment
        fi
        validate_install_config
        persist_config
        apply_wireguard_config
        print_install_summary
        ;;
    *)
        die "internal error: unknown mode '${MODE}'"
        ;;
esac
