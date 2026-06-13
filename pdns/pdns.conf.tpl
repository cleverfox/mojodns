# PowerDNS Authoritative — hidden primary
# Rendered to /etc/powerdns/pdns.conf by entrypoint.sh (envsubst)

launch=gpgsql
gpgsql-host=postgres
gpgsql-port=5432
gpgsql-dbname=dns
gpgsql-user=dns
gpgsql-password=${POSTGRES_PASSWORD}

# This box is a primary: send NOTIFY on zone changes.
# Serials are bumped by the per-zone SOA-EDIT-API=DEFAULT behaviour
# (YYYYMMDDnn — same convention the old panel implemented by hand).
primary=yes

# Public secondaries (NSD): always notify them and allow zone transfers.
# The catalog zone and all member zones replicate through this path.
also-notify=${ALSO_NOTIFY_IPS}
allow-axfr-ips=${ALLOW_AXFR_IPS}
# We notify the slaves explicitly; NS records point at the public boxes
# anyway, so notifying them twice is harmless. Keep default behaviour.

# REST API for the web panel (cluster-internal only — no port published)
api=yes
api-key=${PDNS_API_KEY}
webserver=yes
webserver-address=0.0.0.0
webserver-port=8081
webserver-allow-from=0.0.0.0/0,::/0

# RFC 2136 dynamic updates (DNS UPDATE). Enabled globally; per-zone access is
# gated by the TSIG-ALLOW-DNSUPDATE / ALLOW-DNSUPDATE-FROM metadata the panel
# sets — a zone with neither rejects all updates.
dnsupdate=yes

# unprivileged in-container port; docker-compose maps host ${DNS_PORT} here
local-address=0.0.0.0, ::
local-port=1053
disable-axfr=no
version-string=anonymous
loglevel=4
