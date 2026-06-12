"""PowerDNS-API-compatible endpoints for acme.sh's `dns_pdns` module.

acme.sh thinks it is talking to PowerDNS directly, but requests are
authenticated with mojodns api_tokens (X-API-Key header), scoped to the
zones the token's user may manage, and writes are limited to TXT rrsets
(all DNS-01 challenges are TXT). See README for client setup.

Implements exactly the surface dns_pdns.sh uses:
    GET   /api/v1/servers/{sid}/zones            (zone discovery)
    GET   /api/v1/servers/{sid}/zones/{zone}     (read existing challenges)
    PATCH /api/v1/servers/{sid}/zones/{zone}     (REPLACE/DELETE TXT rrsets)
    PUT   /api/v1/servers/{sid}/zones/{zone}/notify
"""

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Header, HTTPException, Request, Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db import ApiToken, User, get_db, log_history
from ..deps import can_access_zone, user_zones
from ..pdns import PdnsError, canonical, pdns

router = APIRouter(prefix="/api/v1/servers/{server_id}")


def header_token_user(
    x_api_key: str = Header(..., alias="X-API-Key"),
    db: Session = Depends(get_db),
) -> User:
    row = db.execute(select(ApiToken).where(ApiToken.token == x_api_key)).scalar_one_or_none()
    if not row or (row.expires_at and row.expires_at < datetime.now(timezone.utc)):
        raise HTTPException(status_code=401, detail={"error": "Unauthorized"})
    user = db.get(User, row.user_id)
    if not user or user.state != "active":
        raise HTTPException(status_code=401, detail={"error": "Unauthorized"})
    return user


def _guard(db: Session, user: User, zone: str) -> str:
    czone = canonical(zone)
    if not can_access_zone(db, user, czone):
        # same shape pdns gives for unknown zones
        raise HTTPException(status_code=404, detail={"error": "Not Found"})
    return czone


@router.get("/zones")
def zones_list(server_id: str, user: User = Depends(header_token_user),
               db: Session = Depends(get_db)):
    zones = pdns.list_zones()
    if user.is_admin:
        return zones
    allowed = user_zones(db, user)
    return [z for z in zones if z["name"] in allowed]


@router.get("/zones/{zone_id}")
def zone_get(server_id: str, zone_id: str, user: User = Depends(header_token_user),
             db: Session = Depends(get_db)):
    czone = _guard(db, user, zone_id)
    try:
        return pdns.get_zone(czone)
    except PdnsError as e:
        raise HTTPException(status_code=e.status, detail={"error": str(e)})


@router.patch("/zones/{zone_id}", status_code=204)
async def zone_patch(server_id: str, zone_id: str, request: Request,
                     user: User = Depends(header_token_user),
                     db: Session = Depends(get_db)):
    czone = _guard(db, user, zone_id)
    body = await request.json()
    rrsets = body.get("rrsets") or []
    if not rrsets:
        raise HTTPException(status_code=422, detail={"error": "no rrsets in request"})

    for rr in rrsets:
        name = canonical(rr.get("name", ""))
        rtype = (rr.get("type") or "").upper()
        change = (rr.get("changetype") or "").upper()
        if rtype != "TXT":
            raise HTTPException(
                status_code=403,
                detail={"error": "this token may only manage TXT records"},
            )
        if change not in ("REPLACE", "DELETE"):
            raise HTTPException(status_code=422, detail={"error": f"bad changetype {change}"})
        if name != czone and not name.endswith("." + czone):
            raise HTTPException(
                status_code=422,
                detail={"error": f"rrset {name} is outside zone {czone}"},
            )

    try:
        pdns.patch_rrsets(czone, rrsets)
    except PdnsError as e:
        raise HTTPException(status_code=e.status, detail={"error": str(e)})

    for rr in rrsets:
        contents = ", ".join(r.get("content", "") for r in rr.get("records", []))
        log_history(
            db, user.id, "zone", czone,
            f"ACME API {rr['changetype'].upper()} TXT {rr['name']}"
            + (f" -> {contents}" if contents else ""),
        )
    return Response(status_code=204)


@router.put("/zones/{zone_id}/notify")
def zone_notify(server_id: str, zone_id: str, user: User = Depends(header_token_user),
                db: Session = Depends(get_db)):
    czone = _guard(db, user, zone_id)
    try:
        pdns.notify(czone)
    except PdnsError as e:
        raise HTTPException(status_code=e.status, detail={"error": str(e)})
    return {"result": "Notification queued"}
