#!/bin/sh
# mojodns-ddns.sh — dynamic DNS client for the mojodns panel.
# Plain POSIX shell: works with bash, dash and (old) FreeBSD /bin/sh.
#
# Discovers the host's public IPv4/IPv6 (curl -4 / curl -6 against
# IP4_URL/IP6_URL) and pushes A/AAAA records to the panel's DDNS endpoint.
# When a family has no connectivity, the matching record is either deleted
# (DEL_STALE_*=true) or left alone (default).
#
# Usage:
#   mojodns-ddns.sh [config-file]        (default: /usr/local/etc/mojodns-ddns.conf)
# Environment variables override config-file values; built-in defaults apply
# last. Run it from cron, e.g.:  */5 * * * * /usr/local/bin/mojodns-ddns.sh
#
# Exit code: 0 = every attempted operation succeeded, 1 = something failed.

# ---- configuration: environment > config file > defaults -------------------
e_PANEL_URL="${PANEL_URL:-}";       e_TOKEN="${TOKEN:-}"
e_RECORD="${RECORD:-}";             e_TTL="${TTL:-}"
e_UPDATE_A="${UPDATE_A:-}";         e_UPDATE_AAAA="${UPDATE_AAAA:-}"
e_DEL_STALE_A="${DEL_STALE_A:-}";   e_DEL_STALE_AAAA="${DEL_STALE_AAAA:-}"
e_IP4_URL="${IP4_URL:-}";           e_IP6_URL="${IP6_URL:-}"
e_CURL_TIMEOUT="${CURL_TIMEOUT:-}"; e_QUIET="${QUIET:-}"

CONF="${1:-/usr/local/etc/mojodns-ddns.conf}"
[ -f "$CONF" ] && . "$CONF"

PANEL_URL="${e_PANEL_URL:-${PANEL_URL:-}}"
TOKEN="${e_TOKEN:-${TOKEN:-}}"
RECORD="${e_RECORD:-${RECORD:-}}"
TTL="${e_TTL:-${TTL:-300}}"
UPDATE_A="${e_UPDATE_A:-${UPDATE_A:-true}}"
UPDATE_AAAA="${e_UPDATE_AAAA:-${UPDATE_AAAA:-false}}"
DEL_STALE_A="${e_DEL_STALE_A:-${DEL_STALE_A:-false}}"
DEL_STALE_AAAA="${e_DEL_STALE_AAAA:-${DEL_STALE_AAAA:-false}}"
IP4_URL="${e_IP4_URL:-${IP4_URL:-https://ifconfig.me}}"
IP6_URL="${e_IP6_URL:-${IP6_URL:-https://ifconfig.me}}"
CURL_TIMEOUT="${e_CURL_TIMEOUT:-${CURL_TIMEOUT:-10}}"
QUIET="${e_QUIET:-${QUIET:-false}}"

log() { [ "$QUIET" = "true" ] || echo "mojodns-ddns: $*"; }
err() { echo "mojodns-ddns: ERROR: $*" >&2; }

[ -n "$PANEL_URL" ] || { err "PANEL_URL is not set"; exit 1; }
[ -n "$TOKEN" ]     || { err "TOKEN is not set"; exit 1; }
[ -n "$RECORD" ]    || { err "RECORD is not set"; exit 1; }
PANEL_URL=$(printf '%s' "$PANEL_URL" | sed 's|/*$||')

command -v curl >/dev/null 2>&1 || { err "curl not found"; exit 1; }

# ---- helpers ----------------------------------------------------------------
valid_ip() {
    # valid_ip 4|6 <addr>
    case "$1" in
        4) printf '%s' "$2" | grep -Eq '^([0-9]{1,3}\.){3}[0-9]{1,3}$' ;;
        6) printf '%s' "$2" | grep -Eiq '^[0-9a-f:]+$' && \
           printf '%s' "$2" | grep -q ':' ;;
    esac
}

api() {
    # api <method> <query> ; echoes response, returns curl status
    curl -s --max-time "$CURL_TIMEOUT" -X "$1" \
         -H "X-API-Key: $TOKEN" \
         "$PANEL_URL/api/v1/ddns?name=$RECORD&$2"
}

api_ok() {
    printf '%s' "$1" | grep -q '"status":"ok"'
}

FAILED=0

do_family() {
    # do_family <4|6> <A|AAAA> <update?> <del_stale?> <ip_url>
    _fam=$1; _type=$2; _upd=$3; _del=$4; _url=$5

    [ "$_upd" = "true" ] || return 0

    _resp=""
    if [ "$_url" = "auto" ]; then
        # no discovery: the server records the source address of this call
        _resp=$(curl -s --max-time "$CURL_TIMEOUT" "-$_fam" -X POST \
                     -H "X-API-Key: $TOKEN" \
                     "$PANEL_URL/api/v1/ddns?name=$RECORD&type=$_type&ttl=$TTL")
        _curl_rc=$?
        _ip="(source address)"
    else
        _ip=$(curl -s --max-time "$CURL_TIMEOUT" "-$_fam" "$_url")
        _curl_rc=$?
    fi

    if [ "$_curl_rc" -ne 0 ] || { [ "$_url" != "auto" ] && ! valid_ip "$_fam" "$_ip"; }; then
        # no connectivity for this family
        if [ "$_del" = "true" ]; then
            log "no IPv$_fam connectivity — deleting stale $_type record"
            _resp=$(api DELETE "type=$_type")
            if api_ok "$_resp"; then
                log "$_type deleted"
            else
                err "delete $_type failed: ${_resp:-no response from panel}"
                FAILED=1
            fi
        else
            log "no IPv$_fam connectivity — leaving $_type record untouched"
        fi
        return 0
    fi

    if [ "$_url" != "auto" ]; then
        _resp=$(api POST "type=$_type&ip=$_ip&ttl=$TTL")
    fi

    if api_ok "$_resp"; then
        if printf '%s' "$_resp" | grep -q '"changed":true'; then
            log "$_type $RECORD -> $_ip (updated)"
        else
            log "$_type $RECORD -> $_ip (unchanged)"
        fi
    else
        err "update $_type failed: ${_resp:-no response from panel}"
        FAILED=1
    fi
}

do_family 4 A    "$UPDATE_A"    "$DEL_STALE_A"    "$IP4_URL"
do_family 6 AAAA "$UPDATE_AAAA" "$DEL_STALE_AAAA" "$IP6_URL"

exit "$FAILED"
