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

Firewall note: the hidden master only needs 53/tcp+udp open **towards the
slave IPs**; nothing else should reach it. The slaves are the published NS.
