"""In-memory stand-in for the PowerDNS REST API — enough surface for the
panel and the migration script. Run: uvicorn tests.fake_pdns:app --port 18081
"""

from fastapi import FastAPI, HTTPException, Request

app = FastAPI()
ZONES: dict[str, dict] = {}


def _summary(z: dict) -> dict:
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


@app.put("/api/v1/servers/localhost/zones/{zid}/notify", status_code=200)
def notify(zid: str):
    if zid not in ZONES:
        raise HTTPException(404, detail={"error": "Not Found"})
    return {"result": "Notification queued"}
