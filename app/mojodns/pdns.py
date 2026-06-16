"""Thin client for the PowerDNS Authoritative REST API.

All zone names handled here are canonical: lowercase ASCII (punycode for
IDN) with a trailing dot.
"""

import ipaddress
import re
from typing import Any

import httpx

from .config import settings


def parse_update_cidrs(text: str) -> list[str]:
    """Parse a comma/space-separated allow-list into canonical CIDR strings.

    Accepts bare IPs (treated as /32 or /128) and v4/v6 CIDR ranges. Raises
    ValueError naming the first bad token. Used for the RFC 2136
    ALLOW-DNSUPDATE-FROM metadata."""
    out: list[str] = []
    for tok in re.split(r"[\s,]+", text.strip()):
        if not tok:
            continue
        try:
            net = str(ipaddress.ip_network(tok, strict=False))
        except ValueError:
            raise ValueError(tok)
        if net not in out:
            out.append(net)
    return out


class PdnsError(Exception):
    def __init__(self, status: int, message: str):
        self.status = status
        super().__init__(message)


def canonical(name: str) -> str:
    name = name.strip().strip(".").lower()
    return name + "."


# DS/CDS digest types (3rd field of the rdata) → (label, advice, recommended)
_DS_DIGESTS = {
    "1": ("SHA-1", "deprecated — most registries reject it", False),
    "2": ("SHA-256", "recommended — submit this one", True),
    "4": ("SHA-384", "optional, stronger", False),
}


def _ds_entry(rdata: str) -> dict:
    """Annotate a DS/CDS rdata ('<keytag> <algo> <digesttype> <digest>')."""
    parts = rdata.split()
    dtype = parts[2] if len(parts) >= 3 else ""
    label, advice, recommended = _DS_DIGESTS.get(dtype, (f"digest type {dtype}", "", False))
    comment = f"{label} digest" + (f" — {advice}" if advice else "")
    return {"rdata": rdata, "comment": comment, "recommended": recommended}


def _dnskey_entry(rdata: str) -> dict:
    """Annotate a DNSKEY rdata ('<flags> <proto> <algo> <pubkey>')."""
    flags = rdata.split()[0] if rdata.split() else ""
    role = {"257": "CSK / key-signing", "256": "zone-signing"}.get(flags, "key")
    return {"rdata": rdata,
            "comment": f"DNSKEY ({role}) — registrars want the DS above, not this"}


class PdnsClient:
    def __init__(self) -> None:
        s = settings()
        self._base = f"{s.pdns_api_url}/servers/{s.pdns_server_id}"
        self._client = httpx.Client(
            headers={"X-API-Key": s.pdns_api_key},
            timeout=15.0,
        )

    def _req(self, method: str, path: str, **kw) -> Any:
        resp = self._client.request(method, self._base + path, **kw)
        if resp.status_code >= 400:
            try:
                msg = resp.json().get("error", resp.text)
            except Exception:
                msg = resp.text
            raise PdnsError(resp.status_code, f"PowerDNS API: {msg}")
        if resp.status_code == 204 or not resp.content:
            return None
        return resp.json()

    # -- zones --------------------------------------------------------------

    def list_zones(self) -> list[dict]:
        return self._req("GET", "/zones")

    def get_zone(self, zone: str) -> dict:
        return self._req("GET", f"/zones/{canonical(zone)}", params={"rrsets": "true"})

    def zone_exists(self, zone: str) -> bool:
        try:
            self._req("GET", f"/zones/{canonical(zone)}", params={"rrsets": "false"})
            return True
        except PdnsError as e:
            if e.status == 404:
                return False
            raise

    def create_zone(
        self,
        zone: str,
        *,
        kind: str = "Master",
        catalog: str | None = None,
        rrsets: list[dict] | None = None,
        masters: list[str] | None = None,
    ) -> dict:
        payload: dict[str, Any] = {"name": canonical(zone), "kind": kind}
        if catalog:
            payload["catalog"] = canonical(catalog)
        if rrsets:
            payload["rrsets"] = rrsets
        if masters:
            payload["masters"] = masters
        return self._req("POST", "/zones", json=payload)

    def delete_zone(self, zone: str) -> None:
        self._req("DELETE", f"/zones/{canonical(zone)}")

    def notify(self, zone: str) -> None:
        self._req("PUT", f"/zones/{canonical(zone)}/notify")

    def patch_rrsets(self, zone: str, rrsets: list[dict]) -> None:
        self._req("PATCH", f"/zones/{canonical(zone)}", json={"rrsets": rrsets})

    def replace_rrset(self, zone: str, name: str, rtype: str, ttl: int, contents: list[dict]) -> None:
        """contents: [{"content": ..., "disabled": bool}, ...]; empty list deletes."""
        if contents:
            rrset = {
                "name": canonical(name),
                "type": rtype,
                "ttl": ttl,
                "changetype": "REPLACE",
                "records": contents,
            }
        else:
            rrset = {"name": canonical(name), "type": rtype, "changetype": "DELETE"}
        self.patch_rrsets(zone, [rrset])

    def set_zone_catalog(self, zone: str, catalog: str | None) -> None:
        """Add the zone to a catalog (canonical name) or remove it (None/'')."""
        self._req(
            "PUT",
            f"/zones/{canonical(zone)}",
            json={"catalog": canonical(catalog) if catalog else ""},
        )

    def set_zone_kind(self, zone: str, kind: str) -> None:
        """Master/Native/etc. Native suppresses pdns's own NOTIFY entirely."""
        self._req("PUT", f"/zones/{canonical(zone)}", json={"kind": kind})

    # -- DNSSEC --------------------------------------------------------------
    #
    # PowerDNS live-signs; the NSD secondaries serve the pre-signed zone over the
    # normal AXFR. A zone is secured with a single CSK (ECDSA P-256) + NSEC3 that
    # is NON-narrow (so the chain materialises and can transfer) with 0 iterations
    # and an empty salt (RFC 9276). API-RECTIFY keeps the NSEC3 chain valid on
    # every later rrset edit. DS/DNSKEY/CDS are public — safe to display anytime.

    def zone_cryptokeys(self, zone: str) -> list[dict]:
        """All DNSSEC keys for the zone (id/keytype/active/flags/dnskey/ds/cds),
        or [] when the zone is insecure."""
        return self._req("GET", f"/zones/{canonical(zone)}/cryptokeys") or []

    def rectify_zone(self, zone: str) -> None:
        self._req("PUT", f"/zones/{canonical(zone)}/rectify")

    def secure_zone(self, zone: str) -> None:
        """Enable DNSSEC: add an active CSK if none, switch on non-narrow NSEC3,
        and rectify once. Ongoing API edits auto-rectify via the global
        default-api-rectify=yes (API-RECTIFY isn't settable per-zone via the API)."""
        if not self.zone_cryptokeys(zone):
            self._req("POST", f"/zones/{canonical(zone)}/cryptokeys",
                      json={"keytype": "csk", "active": True, "algorithm": "ecdsa256"})
        self._req("PUT", f"/zones/{canonical(zone)}",
                  json={"nsec3param": "1 0 0 -", "nsec3narrow": False})
        self.rectify_zone(zone)

    def unsecure_zone(self, zone: str) -> None:
        """Disable DNSSEC: clear NSEC3, then remove every key."""
        keys = self.zone_cryptokeys(zone)
        if keys:
            self._req("PUT", f"/zones/{canonical(zone)}", json={"nsec3param": ""})
            for k in keys:
                self._req("DELETE", f"/zones/{canonical(zone)}/cryptokeys/{k['id']}")

    def zone_dnssec_info(self, zone: str) -> dict:
        """UI summary from the active keys. ds/cds/dnskey are annotated entries
        ({rdata, comment, recommended?}); the recommended DS (SHA-256) sorts first."""
        keys = self.zone_cryptokeys(zone)
        ds: list[dict] = []
        cds: list[dict] = []
        dnskey: list[dict] = []
        algorithm = None
        for k in keys:
            if not k.get("active"):
                continue
            ds += [_ds_entry(d) for d in (k.get("ds") or [])]
            cds += [_ds_entry(c) for c in (k.get("cds") or [])]
            if k.get("dnskey"):
                dnskey.append(_dnskey_entry(k["dnskey"]))
            algorithm = algorithm or k.get("algorithm")
        ds.sort(key=lambda e: (not e["recommended"], e["rdata"]))  # recommended first
        cds.sort(key=lambda e: (not e["recommended"], e["rdata"]))
        return {"secured": bool(keys), "ds": ds, "cds": cds,
                "dnskey": dnskey, "algorithm": algorithm}

    # -- metadata / TSIG ------------------------------------------------------

    def set_zone_metadata(self, zone: str, kind: str, values: list[str]) -> None:
        self._req(
            "PUT",
            f"/zones/{canonical(zone)}/metadata/{kind}",
            json={"kind": kind, "metadata": values},
        )

    def get_zone_metadata(self, zone: str, kind: str) -> list[str]:
        try:
            r = self._req("GET", f"/zones/{canonical(zone)}/metadata/{kind}")
        except PdnsError as e:
            if e.status == 404:
                return []
            raise
        return (r or {}).get("metadata", [])

    def delete_zone_metadata(self, zone: str, kind: str) -> None:
        try:
            self._req("DELETE", f"/zones/{canonical(zone)}/metadata/{kind}")
        except PdnsError as e:
            if e.status != 404:
                raise

    def get_zone_also_notify(self, zone: str) -> list[str]:
        """Per-zone NOTIFY targets (ip / ip:port / [v6]:port), empty if none."""
        return self.get_zone_metadata(zone, "ALSO-NOTIFY")

    def set_zone_also_notify(self, zone: str, targets: list[str]) -> None:
        if targets:
            self.set_zone_metadata(zone, "ALSO-NOTIFY", targets)
        else:
            self.delete_zone_metadata(zone, "ALSO-NOTIFY")

    # -- RFC 2136 dynamic update permissions --------------------------------
    #
    # pdns gates every DNS UPDATE on TWO independent checks, ANDed together:
    #   1. source IP must match ALLOW-DNSUPDATE-FROM (per-zone) or the global
    #      allow-dnsupdate-from (default 127.0.0.0/8);
    #   2. if TSIG-ALLOW-DNSUPDATE is set, the packet must be signed by a listed
    #      key. TSIG ALONE NEVER AUTHORISES — the IP gate is always required.
    # So to get "signed updates from anywhere" we open the IP gate to all
    # (UPDATE_ANY) while keeping a TSIG key mandatory; a narrower list further
    # restricts. We never write ALLOW-DNSUPDATE-FROM without a TSIG key, which
    # would otherwise be an open, unauthenticated update relay.

    UPDATE_ANY = ["0.0.0.0/0", "::/0"]

    def get_zone_update_keys(self, zone: str) -> list[str]:
        """TSIG key names allowed to DNS-UPDATE the zone (no trailing dot)."""
        return [k.rstrip(".") for k in self.get_zone_metadata(zone, "TSIG-ALLOW-DNSUPDATE")]

    def get_zone_update_ips(self, zone: str) -> list[str]:
        """User-facing source-IP restriction; the open catch-all reads back as
        [] (meaning 'any source, TSIG still required')."""
        ips = self.get_zone_metadata(zone, "ALLOW-DNSUPDATE-FROM")
        return [] if set(ips) == set(self.UPDATE_ANY) else ips

    def _write_update_access(self, zone: str, keys: list[str], cidrs: list[str]) -> None:
        if keys:
            # pdns matches TSIG-ALLOW-DNSUPDATE against the bare tsigkey name (no
            # trailing dot — as `pdnsutil set-meta ... TSIG-ALLOW-DNSUPDATE <name>`),
            # NOT the dotted form used for master_tsig_key_ids; a trailing dot
            # silently fails to match and every update is REFUSED.
            self.set_zone_metadata(zone, "TSIG-ALLOW-DNSUPDATE",
                                   [k.rstrip(".").lower() for k in keys])
            self.set_zone_metadata(zone, "ALLOW-DNSUPDATE-FROM",
                                   cidrs if cidrs else self.UPDATE_ANY)
        else:
            # no key -> updates fully off (and never leave an open IP allow-list)
            self.delete_zone_metadata(zone, "TSIG-ALLOW-DNSUPDATE")
            self.delete_zone_metadata(zone, "ALLOW-DNSUPDATE-FROM")

    def set_zone_update_keys(self, zone: str, names: list[str]) -> None:
        # preserve the user's explicit IP restriction across key changes
        self._write_update_access(zone, names, self.get_zone_update_ips(zone))

    def set_zone_update_ips(self, zone: str, cidrs: list[str]) -> None:
        # only meaningful alongside a key; with no key this stays off
        self._write_update_access(zone, self.get_zone_update_keys(zone), cidrs)

    def set_zone_tsig_keys(self, zone: str, names: list[str]) -> None:
        """Set exactly which TSIG keys may AXFR the zone.

        The API forbids writing TSIG-ALLOW-AXFR via the metadata endpoint;
        the equivalent zone field is master_tsig_key_ids (key id = canonical
        key name). Any listed key may transfer the zone — one key per trust
        domain."""
        self._req(
            "PUT",
            f"/zones/{canonical(zone)}",
            json={"master_tsig_key_ids": [canonical(n) for n in names]},
        )

    def ensure_tsig_allow_axfr(self, zone: str) -> None:
        """Allow AXFR of the zone with every globally-configured TSIG key."""
        names = settings().tsig_key_names
        if names:
            self.set_zone_tsig_keys(zone, names)

    def zone_tsig_keys(self, zone: str) -> list[str]:
        """Names (no trailing dot) of TSIG keys currently allowed for the zone."""
        zdata = self.get_zone(zone)
        return [k.rstrip(".") for k in zdata.get("master_tsig_key_ids", [])]

    # -- TSIG key lifecycle (pdns tsigkeys API) -----------------------------

    def list_tsig_keys(self) -> list[dict]:
        return self._req("GET", "/tsigkeys") or []

    def get_tsig_key(self, name: str) -> dict | None:
        """Returns the key incl. its secret ('key' field), or None if absent."""
        try:
            return self._req("GET", f"/tsigkeys/{canonical(name)}")
        except PdnsError as e:
            if e.status == 404:
                return None
            raise

    def create_tsig_key(self, name: str, algorithm: str = "hmac-sha256",
                        secret: str | None = None) -> dict:
        """Generate a key (secret omitted) or import one (secret provided)."""
        payload: dict[str, Any] = {"name": name.rstrip("."), "algorithm": algorithm}
        if secret:
            payload["key"] = secret
        return self._req("POST", "/tsigkeys", json=payload)

    def delete_tsig_key(self, name: str) -> None:
        self._req("DELETE", f"/tsigkeys/{canonical(name)}")

    def tsig_key_in_use(self, name: str, *, except_zone: str | None = None) -> bool:
        """True if any zone (other than except_zone) references this key — for
        AXFR (master_tsig_key_ids) or for RFC2136 updates (TSIG-ALLOW-DNSUPDATE).

        Per-zone detail/metadata is fetched individually (rare op: key delete /
        mode switch), so we only delete a tsig key when truly unreferenced."""
        cname = canonical(name)
        bare = name.rstrip(".")
        skip = canonical(except_zone) if except_zone else None
        for z in self.list_zones():
            if z["name"] == skip:
                continue
            if cname in (self.get_zone(z["name"]).get("master_tsig_key_ids") or []):
                return True
            if bare in self.get_zone_update_keys(z["name"]):
                return True
        return False

    # -- catalog ------------------------------------------------------------

    def ensure_catalog_zone(self) -> None:
        cat = settings().catalog_zone
        if not self.zone_exists(cat):
            self.create_zone(cat, kind="Producer", catalog=None)
        self.ensure_tsig_allow_axfr(cat)


def is_custom_zone(zdata: dict, catalog_zone: str) -> bool:
    """A zone is 'custom' when it is neither the catalog producer nor a
    catalog member — i.e. served by manually-configured secondaries."""
    if zdata.get("kind") == "Producer":
        return False
    if zdata.get("name") == canonical(catalog_zone):
        return False
    return not (zdata.get("catalog") or "").strip()


pdns = PdnsClient()
