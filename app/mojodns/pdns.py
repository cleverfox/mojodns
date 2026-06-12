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

    # -- metadata / TSIG ------------------------------------------------------

    def set_zone_metadata(self, zone: str, kind: str, values: list[str]) -> None:
        self._req(
            "PUT",
            f"/zones/{canonical(zone)}/metadata/{kind}",
            json={"kind": kind, "metadata": values},
        )

    def ensure_tsig_allow_axfr(self, zone: str) -> None:
        """Mark the zone as transferable with the configured TSIG key.

        The API forbids writing TSIG-ALLOW-AXFR via the metadata endpoint;
        the equivalent zone field is master_tsig_key_ids (key id = canonical
        key name)."""
        key = settings().tsig_key
        if key:
            self._req(
                "PUT",
                f"/zones/{canonical(zone)}",
                json={"master_tsig_key_ids": [canonical(key)]},
            )

    # -- catalog ------------------------------------------------------------

    def ensure_catalog_zone(self) -> None:
        cat = settings().catalog_zone
        if not self.zone_exists(cat):
            self.create_zone(cat, kind="Producer", catalog=None)
        self.ensure_tsig_allow_axfr(cat)


pdns = PdnsClient()
