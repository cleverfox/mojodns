"""Thin client for the PowerDNS Authoritative REST API.

All zone names handled here are canonical: lowercase ASCII (punycode for
IDN) with a trailing dot.
"""

from typing import Any

import httpx

from .config import settings


class PdnsError(Exception):
    def __init__(self, status: int, message: str):
        self.status = status
        super().__init__(message)


def canonical(name: str) -> str:
    name = name.strip().strip(".").lower()
    return name + "."


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
        """True if any zone (other than except_zone) lists this key for AXFR.

        master_tsig_key_ids only appears in the per-zone detail, not the list,
        so each zone is fetched individually (rare op: key delete / mode switch)."""
        cname = canonical(name)
        skip = canonical(except_zone) if except_zone else None
        for z in self.list_zones():
            if z["name"] == skip:
                continue
            if cname in (self.get_zone(z["name"]).get("master_tsig_key_ids") or []):
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
