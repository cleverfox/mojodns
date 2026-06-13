# Public NSD secondaries

Each public nameserver runs **NSD ≥ 4.9.0** (released 2024-04-03 — the
first version with catalog-zone consumer support; check with `nsd -v`) and
configures itself from the **catalog zone** produced by the hidden PowerDNS
master — this replaces the old `nsd_config_generator.sh` cron hack
(drill PTR → rewrite nsd.conf). Beware distro packages: Debian 12 (4.6.1)
and Ubuntu 24.04 (4.8.0) are too old.

How it works:

1. The web panel creates every zone in PowerDNS with
   `catalog=<CATALOG_ZONE>`; PowerDNS maintains the catalog zone's member
   PTR records itself (kind `Producer`).
2. PowerDNS notifies the slaves (`also-notify`) about the catalog zone and
   all member zones.
3. NSD consumes the catalog (`catalog: consumer`) and creates/deletes
   member zones on the fly using the `catalog-member-pattern` pattern —
   visible with `nsd-control zonestatus`.

Setup on a slave:

```sh
cp nsd.conf.example /etc/nsd/nsd.conf   # adjust master IP + catalog name
nsd-checkconf /etc/nsd/nsd.conf
systemctl restart nsd
nsd-control zonestatus                  # member zones appear after first xfr
```

## TSIG (recommended for transfers over the public internet)

Generate a key once on the master:

```sh
podman exec mojodns-py-pdns-1 pdnsutil --config-dir=/tmp/pdns \
    generate-tsig-key mojodns-xfr hmac-sha256
```

Then set in the stack's `.env` and restart:

```
TSIG_KEY=mojodns-xfr
TSIG_ALGO=hmac-sha256
TSIG_SECRET=<base64 secret printed above>
ALLOW_AXFR_IPS=""        # empty ⇒ transfers possible ONLY with a valid TSIG
```

The panel automatically marks every zone (incl. the catalog and future
zones) with the key via the pdns API (`master_tsig_key_ids`, the API
equivalent of `TSIG-ALLOW-AXFR`) — no per-zone pdnsutil commands needed.

On the slaves:

```
key:
    name: "mojodns-xfr"
    algorithm: hmac-sha256
    secret: "<base64 secret>"

pattern:
    name: "catalog-members"
    allow-notify: <MASTER_IP> mojodns-xfr
    request-xfr: AXFR <MASTER_IP> mojodns-xfr

zone:
    name: "catalog.mojodns"
    allow-notify: <MASTER_IP> mojodns-xfr
    request-xfr: AXFR <MASTER_IP> mojodns-xfr
    catalog: consumer
    catalog-member-pattern: "catalog-members"
```

**Pitfall (verified the hard way):** once the key is active, PowerDNS signs
its NOTIFY messages too. An `allow-notify: <ip> NOKEY` ACL matches only
*unsigned* messages, so NSD will refuse every notify with
`refused, no acl matches` — the `allow-notify` ACL must name the key, as
above. Debug checks:

```sh
# refused (unsigned), then accepted (signed):
dig @master -p 1053 example.com AXFR
dig @master -p 1053 example.com AXFR -y "hmac-sha256:mojodns-xfr:<secret>"
# slave side — look for: "TSIG verified with key mojodns-xfr"
nsd-control zonestatus ; journalctl -u nsd | grep TSIG
```

## Old NSD (< 4.9.0) without catalog support

For slaves that cannot be upgraded yet, `nsd-catalog-sync.sh` provides the
same autoconfiguration without native catalog support (verified down to
NSD 4.7.0). Instead of `catalog: consumer`, a cron job AXFRs the catalog
zone with dig/drill, parses the RFC 9432 member PTR records, regenerates an
include file with one secondary-zone stanza per member, and runs
`nsd-control reconfig` — only when the zone list actually changed. The
spiritual successor of the old `nsd_config_generator.sh`, reading the
standard catalog instead of the old PTR-view hack.

Setup:

```sh
install -m 755 nsd-catalog-sync.sh /usr/local/bin/
cp nsd-catalog-sync.conf.example /usr/local/etc/nsd-catalog-sync.conf  # edit

# nsd.conf: add the key: block (for TSIG) and
#     include: "/etc/nsd/zones.catalog.conf"
touch /etc/nsd/zones.catalog.conf && service nsd restart

/usr/local/bin/nsd-catalog-sync.sh        # first run, then:
# */5 * * * * /usr/local/bin/nsd-catalog-sync.sh
```

Notes: needs `dig` (bind-tools) or `drill`, and a remote-control socket for
`nsd-control` (`control-interface: /run/nsd.sock` works without certs).
Old slaves learn about new/removed zones on the cron schedule (≤ 5 min with
the example crontab) rather than via NOTIFY-triggered catalog updates;
record changes inside existing zones still propagate instantly via NOTIFY.
On failed transfers (bad TSIG, master down) the script keeps the existing
config untouched and exits non-zero.

## Sharing one NSD across several mojodns installations

NSD natively allows **only a single catalog consumer zone** — configuring
two makes NSD *ignore all of them* (catalog processing is disabled
entirely). So a shared NSD that must follow more than one mojodns
installation cannot use native `catalog: consumer`; use
`nsd-catalog-sync.sh` in **multi-source mode** instead, which aggregates
several catalogs into one generated include file.

Drop one config file per installation into `SOURCES_DIR`
(default `/usr/local/etc/nsd-catalog-sync.d/`, see
`nsd-catalog-sync.d/example.conf.example`):

```sh
mkdir -p /usr/local/etc/nsd-catalog-sync.d
cp site-a.conf site-b.conf /usr/local/etc/nsd-catalog-sync.d/   # MASTER/CATALOG/TSIG_* each
# nsd.conf needs one key: block per distinct TSIG key used by the sources
*/5 * * * * /usr/local/bin/nsd-catalog-sync.sh
```

Each source's zones get `request-xfr`/`allow-notify` pointed at *that*
installation's master and key, so per-record NOTIFY still flows from the
owning master. Behaviour:

* **Disjoint zone names are required** — if two installations advertise the
  same zone, the first source processed wins and the collision is logged.
* **Fail-safe**: if *any* source's transfer fails, the whole update is
  aborted and the existing config is kept untouched — a single unreachable
  master never drops another installation's zones from NSD.

(Single-source mode — one `MASTER`/`CATALOG` in the main config, no
`SOURCES_DIR` — keeps working unchanged.)

Firewall note: the hidden master only needs 53/tcp+udp open **towards the
slave IPs**; nothing else should reach it. The slaves are the published NS.
