# mojodns-py

Rewrite of the old `mojodns-perl` (Mojolicious) DNS management panel:

- **FastAPI + Jinja2 + HTMX** web UI (Python 3.12)
- **PowerDNS Authoritative 4.9** as *hidden primary* (gpgsql backend, managed
  exclusively through its REST API — the app never touches pdns tables)
- **NSD ≥ 4.9** public secondaries, auto-configured via **RFC 9432 catalog
  zones** (replaces the old `nsd_config_generator.sh` PTR-record hack)
- **PostgreSQL 16** holding both the pdns backend schema and the app's own
  tables (users, per-zone ACLs, history, API tokens)
- Docker Compose for the whole hidden-master stack

## Architecture

```
                 ┌────────────────────── docker compose ──────────────────────┐
                 │                                                            │
 admin browser ──┤► web (FastAPI/HTMX) ──REST──► pdns (hidden primary) ◄──┐   │
                 │        │                          │                    │   │
                 │        └──── users/ACL/history ───┤ gpgsql             │   │
                 │                                   ▼                    │   │
                 │                               postgres ────────────────┘   │
                 └──────────────────────────────────│─────────────────────────┘
                                                    │ NOTIFY + AXFR (catalog
                                                    ▼  zone + member zones)
                                     public NSD secondaries (the published NS)
```

* Every zone created in the UI becomes a `Primary` zone in PowerDNS and a
  member of the catalog zone (`CATALOG_ZONE`, default `catalog.mojodns.`).
* PowerDNS notifies the secondaries (global `also-notify`); when the catalog
  zone changes, NSD adds/removes member zones automatically — no scripts.
* SOA serials are bumped by PowerDNS itself (`SOA-EDIT-API: DEFAULT` →
  `YYYYMMDDnn`, same convention the Perl app implemented by hand).
* The hidden master is **not** listed in NS records; only the NSD boxes are.

## Quick start

```sh
cp .env.example .env          # edit secrets and slave IPs!
docker compose up -d --build
docker compose logs -f web
```

Open http://localhost:8000 — first run creates an `admin` user with the
password from `BOOTSTRAP_ADMIN_PASSWORD` (printed in the log if unset).

## Version requirements

| Component | Minimum | Why | Used here |
|---|---|---|---|
| NSD (secondaries) | **4.9.0** (2024-04-03) | catalog zone *consumer* support (RFC 9432: `catalog: consumer`, `catalog-member-pattern`) | 4.11.1 (test slave) |
| PowerDNS Auth | **4.7** | catalog zone *producer* support + `catalog` column in the gpgsql schema | 4.9.4 |
| PostgreSQL | 12+ | nothing special | 16 |

Check a secondary with `nsd -v`. Distro packages, for orientation
(repology, 2026-06): Debian 12 ships 4.6.1 and Ubuntu 24.04 ships 4.8.0 —
**both too old**; Debian 13 (4.12), Ubuntu 25.04 (4.11), FreeBSD ports
(4.14), Alpine 3.24 (4.14) and EPEL 9 (4.14) are all fine. For hosts stuck
on an older NSD, either install upstream NSD from source/backports, or use
`nsd-slave/nsd-catalog-sync.sh` — a cron script that AXFRs the catalog zone
and regenerates the slave's zone list for NSD versions without native
catalog support (verified with NSD 4.7; see `nsd-slave/README.md`).

## Configuring the NSD secondaries

On each public NSD (≥ 4.9) host, see `nsd-slave/nsd.conf.example`:

```
pattern:
  name: "catalog-members"
  allow-notify: <MASTER_IP> NOKEY
  request-xfr: AXFR <MASTER_IP> NOKEY

zone:
  name: "catalog.mojodns"
  allow-notify: <MASTER_IP> NOKEY
  request-xfr: AXFR <MASTER_IP> NOKEY
  catalog: consumer
  catalog-member-pattern: "catalog-members"
```

Then list the slave IPs in `.env` (`ALSO_NOTIFY_IPS`, `ALLOW_AXFR_IPS`) so the
hidden master notifies them and allows transfers. For TSIG-protected
transfers see `nsd-slave/README.md`.

A containerized test slave is included: `docker compose --profile slave up`
(serves on host port `${SLAVE_PORT:-15353}`). pdns (`10.89.99.10`) and the
test slave (`10.89.99.53`) have static addresses on the compose network so
NOTIFY targets survive container restarts.

Propagation timings (verified): record changes inside a zone reach the
slaves in ~1–2 s (the panel sends NOTIFY on every change); zone creation
and deletion propagate within ~60 s — catalog zone membership is notified
on PowerDNS's communicator cycle, not instantly. A log line like
`Unable to parse SOA notification answer from <slave>` on the pdns side is
a harmless pdns/NSD NOTIFY-ack interop quirk — the transfer still happens.

## Migrating from mojodns-perl

1. Restore the legacy dump into a scratch database:
   `createdb dns_legacy && psql dns_legacy < ../mojodns-perl/backup.sql`
2. Run the migration (from the `app/` dir or the web container):
   ```sh
   python -m scripts.migrate_legacy --legacy-dsn postgresql://user@host/dns_legacy
   ```
   It copies users (passwords keep working — legacy salted-SHA1 hashes are
   verified and transparently re-hashed to bcrypt on first login), creates
   every zone through the PowerDNS API (joining the legacy `prio` column into
   record content, adding trailing dots, quoting TXT), and copies per-zone
   access grants and the history log.

## Zone NS verification

The panel compares each zone's configured NS records with the live
delegation seen by a recursive resolver (`VERIFY_RESOLVERS`, default
1.1.1.1 + 8.8.8.8): green = match, yellow = partial overlap, red = moved
to another provider or abandoned (NXDOMAIN), grey = could not check.
Trigger it with **verify zones ✓** on the dashboard (status dot per zone)
or **verify NS ✓** on a zone page (each NS record marked ✓/✗). A background
re-check runs every `VERIFY_INTERVAL_HOURS` (default 24, 0 disables).

**view zone ≡** on a zone page performs a live TSIG-signed AXFR against
pdns (`PDNS_AXFR_HOST:PDNS_AXFR_PORT`) and shows the zone-file text exactly
as a secondary receives it — doubling as a transfer-path health check: if
this fails, the slaves can't transfer either. **export zone ⤓** downloads
the same text as `<zone>.zone`.

**⇪ import zone** on the dashboard creates a zone from exported text
(upload or paste). With the name field empty the zone name is taken from
the file's SOA (restore); a *different* name clones the zone — owner names
and in-zone record data are re-rooted to the new origin, out-of-zone names
are kept. DNSSEC records (RRSIG/NSEC/DNSKEY…) are skipped on import.

## ACME / Let's Encrypt (acme.sh)

The panel exposes a PowerDNS-API-compatible endpoint, so acme.sh's stock
[`dns_pdns`](https://github.com/acmesh-official/acme.sh/blob/master/dnsapi/dns_pdns.sh)
module works out of the box — no custom dnsapi script needed. Create an API
token for a user in the panel (user edit page), then:

```sh
export PDNS_Url="https://dns-panel.example.net"   # the mojodns web app URL
export PDNS_ServerId="localhost"
export PDNS_Token="<api token from the panel>"
export PDNS_Ttl=60

acme.sh --issue --dns dns_pdns -d example.com -d '*.example.com'
```

The token is scoped: it only sees zones its user owns/edits and may only
create/delete **TXT** records (everything DNS-01 needs); every change lands
in the zone history log. NOTIFY goes out to the NSD secondaries on every
challenge update, so validation is quick.

## Dynamic DNS (DDNS)

The panel has a token-authenticated DDNS endpoint (A/AAAA only, scoped to
the token's zones, idempotent — unchanged addresses don't bump serials or
send NOTIFY):

```
POST   /api/v1/ddns?name=<fqdn>&type=A|AAAA[&ip=<addr>][&ttl=300]
DELETE /api/v1/ddns?name=<fqdn>&type=A|AAAA
```

`X-API-Key` header or `?token=` parameter; omitting `ip` uses the request's
source address. A portable client (bash / FreeBSD sh) lives in
`app/mojodns/static/client/mojodns-ddns.sh` (also served by the panel at `/static/client/mojodns-ddns.sh`) with `mojodns-ddns.conf.example` next to it:

```sh
cp client/mojodns-ddns.conf.example /usr/local/etc/mojodns-ddns.conf  # edit
crontab: */5 * * * * /usr/local/bin/mojodns-ddns.sh
```

It discovers the public address per family (`curl -4` / `curl -6` against
ifconfig.me by default), updates A/AAAA according to `UPDATE_A`/`UPDATE_AAAA`,
and when a family loses connectivity either deletes the stale record
(`DEL_STALE_A`/`DEL_STALE_AAAA=true`) or leaves it untouched (default).
An IPv4 answer arriving over the v6 path (NAT64 etc.) is treated as
"no IPv6" rather than being published as AAAA.

## Development

```sh
cd app
python -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
uvicorn mojodns.main:app --reload   # needs DATABASE_URL + PDNS_* env vars
```

Run tests: `pytest`.

## Layout

```
app/                  FastAPI application (image: mojodns-web)
  mojodns/            package: routers, pdns API client, templates, static
  scripts/migrate_legacy.py
db/init/              postgres init: pdns gpgsql schema + app schema
pdns/pdns.conf.tpl    hidden-master config (envsubst'ed at container start)
nsd-slave/            example/public-secondary configuration + test container
docker-compose.yml
```
