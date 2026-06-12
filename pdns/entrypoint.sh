#!/bin/sh
# Render pdns.conf from template using container env, then start pdns_server.
set -eu

# the official image runs unprivileged: /etc/powerdns is read-only, so
# render the config into a writable location instead
conf_dir=/tmp/pdns
mkdir -p "$conf_dir"
# poor man's envsubst (the pdns image has no gettext): only ${VAR} forms used
sed -e "s|\${POSTGRES_PASSWORD}|${POSTGRES_PASSWORD}|g" \
    -e "s|\${PDNS_API_KEY}|${PDNS_API_KEY}|g" \
    -e "s|\${ALSO_NOTIFY_IPS}|${ALSO_NOTIFY_IPS:-}|g" \
    -e "s|\${ALLOW_AXFR_IPS}|${ALLOW_AXFR_IPS:-}|g" \
    /pdns.conf.tpl > "$conf_dir/pdns.conf"
chmod 600 "$conf_dir/pdns.conf" || true

exec /usr/local/sbin/pdns_server --config-dir="$conf_dir" --socket-dir=/tmp/pdns --guardian=no --daemon=no --disable-syslog --write-pid=no
