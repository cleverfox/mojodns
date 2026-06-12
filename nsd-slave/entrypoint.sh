#!/bin/sh
# Test/demo NSD secondary: renders nsd.conf for the catalog-consumer setup.
# MASTER_IP may be a hostname (e.g. the compose service "pdns") — NSD wants
# a literal IP in request-xfr/allow-notify, so resolve it first.
set -eu

CATALOG="$(echo "${CATALOG_ZONE:-catalog.mojodns.}" | sed 's/\.$//')"
MASTER="${MASTER_IP:?set MASTER_IP}"
MASTER_PORT="${MASTER_PORT:-1053}"   # pdns container listens on 1053
NSD_PORT="${NSD_PORT:-1053}"
# optional TSIG for zone transfers: set TSIG_NAME + TSIG_SECRET (+ TSIG_ALGO)
TSIG_NAME="${TSIG_NAME:-}"
TSIG_ALGO="${TSIG_ALGO:-hmac-sha256}"
TSIG_SECRET="${TSIG_SECRET:-}"
XFR_KEY="NOKEY"
KEY_BLOCK=""
if [ -n "$TSIG_NAME" ] && [ -n "$TSIG_SECRET" ]; then
    XFR_KEY="$TSIG_NAME"
    KEY_BLOCK="key:
    name: \"$TSIG_NAME\"
    algorithm: $TSIG_ALGO
    secret: \"$TSIG_SECRET\"
"
fi

case "$MASTER" in
  *[!0-9.:]*)
    resolved="$(getent hosts "$MASTER" | awk '{print $1; exit}')"
    [ -n "$resolved" ] || { echo "cannot resolve $MASTER" >&2; exit 1; }
    MASTER="$resolved"
    ;;
esac

cat > /etc/nsd/nsd.conf <<EOF
server:
    ip-address: 0.0.0.0
    port: ${NSD_PORT}
    hide-version: yes
    zonesdir: "/var/db/nsd"
    verbosity: 2

remote-control:
    control-enable: yes
    control-interface: /var/run/nsd.sock

${KEY_BLOCK}
# NB: when TSIG is enabled, pdns also signs NOTIFY — the allow-notify ACL
# must name the key (a NOKEY acl only matches unsigned messages)
pattern:
    name: "catalog-members"
    allow-notify: ${MASTER} ${XFR_KEY}
    request-xfr: AXFR ${MASTER}@${MASTER_PORT} ${XFR_KEY}

zone:
    name: "${CATALOG}"
    allow-notify: ${MASTER} ${XFR_KEY}
    request-xfr: AXFR ${MASTER}@${MASTER_PORT} ${XFR_KEY}
    catalog: consumer
    catalog-member-pattern: "catalog-members"
EOF

nsd-checkconf /etc/nsd/nsd.conf
exec nsd -d -c /etc/nsd/nsd.conf
