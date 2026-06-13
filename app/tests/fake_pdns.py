"""In-memory stand-in for the PowerDNS REST API — enough surface for the
panel and the migration script. Run: uvicorn tests.fake_pdns:app --port 18081
"""

import base64
import hashlib

from fastapi import FastAPI, HTTPException, Request

app = FastAPI()
ZONES: dict[str, dict] = {}
TSIGKEYS: dict[str, dict] = {}  # id (canonical name) -> key dict


def _summary(z: dict) -> dict:
    # mimic the real list endpoint: no master_tsig_key_ids / rrsets
    return {k: z[k] for k in ("id", "name", "kind", "serial", "catalog")}


def _bump_serial(z: dict) -> None:
    z["serial"] += 1


@app.get("/api/v1/servers/localhost/zones")
def list_zones():
    return [_summary(z) for z in ZONES.values()]


@app.post("/api/v1/servers/localhost/zones", status_code=201)
async def create_zone(req: Request):
    body = await req.json()
    name = body["name"]
    if name in ZONES:
        raise HTTPException(409, detail={"error": f"Domain '{name}' already exists"})
    zone = {
        "id": name,
        "name": name,
        "kind": body.get("kind", "Native"),
        "catalog": body.get("catalog", ""),
        "master_tsig_key_ids": body.get("master_tsig_key_ids", []),
        "serial": 2026010100,
        "rrsets": [],
    }
    for rr in body.get("rrsets", []):
        rr.pop("changetype", None)
        zone["rrsets"].append(rr)
    ZONES[name] = zone
    return zone


@app.get("/api/v1/servers/localhost/zones/{zid}")
def get_zone(zid: str):
    z = ZONES.get(zid)
    if not z:
        raise HTTPException(404, detail={"error": "Not Found"})
    return z


@app.delete("/api/v1/servers/localhost/zones/{zid}", status_code=204)
def delete_zone(zid: str):
    if zid not in ZONES:
        raise HTTPException(404, detail={"error": "Not Found"})
    del ZONES[zid]


@app.patch("/api/v1/servers/localhost/zones/{zid}", status_code=204)
async def patch_zone(zid: str, req: Request):
    z = ZONES.get(zid)
    if not z:
        raise HTTPException(404, detail={"error": "Not Found"})
    body = await req.json()
    for change in body.get("rrsets", []):
        key = (change["name"], change["type"])
        z["rrsets"] = [rr for rr in z["rrsets"] if (rr["name"], rr["type"]) != key]
        if change.get("changetype", "REPLACE") == "REPLACE":
            z["rrsets"].append(
                {"name": change["name"], "type": change["type"],
                 "ttl": change.get("ttl", 3600), "records": change.get("records", [])}
            )
    _bump_serial(z)


@app.put("/api/v1/servers/localhost/zones/{zid}", status_code=204)
async def put_zone(zid: str, req: Request):
    z = ZONES.get(zid)
    if not z:
        raise HTTPException(404, detail={"error": "Not Found"})
    body = await req.json()
    if "catalog" in body:
        z["catalog"] = body["catalog"]
    if "master_tsig_key_ids" in body:
        z["master_tsig_key_ids"] = body["master_tsig_key_ids"]
    if "kind" in body:
        z["kind"] = body["kind"]


# -- per-zone metadata (ALSO-NOTIFY etc.) -----------------------------------

@app.get("/api/v1/servers/localhost/zones/{zid}/metadata/{kind}")
def get_metadata(zid: str, kind: str):
    z = ZONES.get(zid)
    if not z:
        raise HTTPException(404, detail={"error": "Not Found"})
    return {"kind": kind, "metadata": z.setdefault("_meta", {}).get(kind, [])}


@app.put("/api/v1/servers/localhost/zones/{zid}/metadata/{kind}", status_code=200)
async def put_metadata(zid: str, kind: str, req: Request):
    z = ZONES.get(zid)
    if not z:
        raise HTTPException(404, detail={"error": "Not Found"})
    body = await req.json()
    z.setdefault("_meta", {})[kind] = body.get("metadata", [])
    return {"kind": kind, "metadata": z["_meta"][kind]}


@app.delete("/api/v1/servers/localhost/zones/{zid}/metadata/{kind}", status_code=204)
def delete_metadata(zid: str, kind: str):
    z = ZONES.get(zid)
    if not z:
        raise HTTPException(404, detail={"error": "Not Found"})
    z.setdefault("_meta", {}).pop(kind, None)


@app.put("/api/v1/servers/localhost/zones/{zid}/notify", status_code=200)
def notify(zid: str):
    if zid not in ZONES:
        raise HTTPException(404, detail={"error": "Not Found"})
    return {"result": "Notification queued"}


# -- TSIG keys --------------------------------------------------------------

@app.get("/api/v1/servers/localhost/tsigkeys")
def list_tsigkeys():
    return [{k: v for k, v in t.items() if k != "key"} for t in TSIGKEYS.values()]


@app.get("/api/v1/servers/localhost/tsigkeys/{kid}")
def get_tsigkey(kid: str):
    t = TSIGKEYS.get(kid)
    if not t:
        raise HTTPException(404, detail={"error": "Not Found"})
    return t  # detail includes the secret ("key")


@app.post("/api/v1/servers/localhost/tsigkeys", status_code=201)
async def create_tsigkey(req: Request):
    body = await req.json()
    name = body["name"].rstrip(".")
    kid = name + "."
    if kid in TSIGKEYS:
        raise HTTPException(409, detail={"error": f"TSIG key '{name}' already exists"})
    secret = body.get("key") or base64.b64encode(
        hashlib.sha256(name.encode()).digest()).decode()
    TSIGKEYS[kid] = {"id": kid, "name": name, "type": "TSIGKey",
                     "algorithm": body.get("algorithm", "hmac-sha256"), "key": secret}
    return TSIGKEYS[kid]


@app.delete("/api/v1/servers/localhost/tsigkeys/{kid}", status_code=204)
def delete_tsigkey(kid: str):
    if kid not in TSIGKEYS:
        raise HTTPException(404, detail={"error": "Not Found"})
    del TSIGKEYS[kid]
