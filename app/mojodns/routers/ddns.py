"""Dynamic DNS endpoint for the ddns client script (client/mojodns-ddns.sh).

    POST   /api/v1/ddns?name=<fqdn>&type=A[&ip=<addr>][&ttl=300][&token=…]
    DELETE /api/v1/ddns?name=<fqdn>&type=AAAA[&token=…]

Auth: X-API-Key header or ?token= query parameter (api_tokens table).
Only A and AAAA records, only inside zones the token's user may manage.
If `ip` is omitted on POST, the request's source address is used (handy
behind NAT when the client cannot learn its own public address). A POST
that matches the currently published address is a no-op: serial untouched,
no NOTIFY — safe to run from cron every minute.
"""

import ipaddress
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db import ApiToken, User, get_db, log_history
from ..deps import can_access_zone
from ..idn import to_ascii
from ..pdns import PdnsError, canonical, pdns
from ..notifier import notify_zone

router = APIRouter(prefix="/api/v1/ddns")


def ddns_user(
    request: Request,
    token: str | None = Query(None),
    x_api_key: str | None = Header(None, alias="X-API-Key"),
    db: Session = Depends(get_db),
) -> User:
    key = x_api_key or token
    if not key:
        raise HTTPException(status_code=401, detail={"error": "missing token"})
    row = db.execute(select(ApiToken).where(ApiToken.token == key)).scalar_one_or_none()
    if not row or (row.expires_at and row.expires_at < datetime.now(timezone.utc)):
        raise HTTPException(status_code=401, detail={"error": "invalid token"})
    user = db.get(User, row.user_id)
    if not user or user.state != "active":
        raise HTTPException(status_code=401, detail={"error": "invalid token"})
    return user


def _find_zone(db: Session, user: User, fqdn: str) -> str:
    """Longest-suffix zone of `fqdn` that the user may manage, or 404."""
    labels = fqdn.rstrip(".").split(".")
    for i in range(len(labels)):
        candidate = canonical(".".join(labels[i:]))
        if can_access_zone(db, user, candidate) and pdns.zone_exists(candidate):
            return candidate
    raise HTTPException(status_code=404, detail={"error": f"no managed zone covers {fqdn}"})


def _check(name: str, rtype: str) -> tuple[str, str]:
    rtype = rtype.upper()
    if rtype not in ("A", "AAAA"):
        raise HTTPException(status_code=403, detail={"error": "only A and AAAA allowed"})
    fqdn = canonical(to_ascii(name))
    return fqdn, rtype


def _current(zone: str, fqdn: str, rtype: str) -> tuple[int | None, list[str]]:
    zdata = pdns.get_zone(zone)
    for rr in zdata["rrsets"]:
        if rr["name"] == fqdn and rr["type"] == rtype:
            return rr["ttl"], [r["content"] for r in rr["records"]]
    return None, []


@router.post("")
def ddns_update(
    request: Request,
    name: str = Query(...),
    type: str = Query(...),
    ip: str | None = Query(None),
    ttl: int = Query(300, ge=10, le=86400),
    user: User = Depends(ddns_user),
    db: Session = Depends(get_db),
):
    fqdn, rtype = _check(name, type)
    zone = _find_zone(db, user, fqdn)

    addr_str = ip or (request.client.host if request.client else None)
    try:
        addr = ipaddress.ip_address(addr_str)
    except (ValueError, TypeError):
        raise HTTPException(status_code=422, detail={"error": f"bad address {addr_str!r}"})
    if (rtype == "A") != (addr.version == 4):
        raise HTTPException(
            status_code=422,
            detail={"error": f"{addr} is not an {'IPv4' if rtype == 'A' else 'IPv6'} address"},
        )
    content = str(addr)  # normalized (compressed IPv6 etc.)

    try:
        cur_ttl, cur = _current(zone, fqdn, rtype)
        if cur == [content] and cur_ttl == ttl:
            return {"status": "ok", "name": fqdn, "type": rtype, "ip": content, "changed": False}
        pdns.replace_rrset(zone, fqdn, rtype, ttl, [{"content": content, "disabled": False}])
        notify_zone(zone)
    except PdnsError as e:
        raise HTTPException(status_code=e.status, detail={"error": str(e)})

    log_history(db, user.id, "zone", zone, f"DDNS {rtype} {fqdn} -> {content}")
    return {"status": "ok", "name": fqdn, "type": rtype, "ip": content, "changed": True}


@router.delete("")
def ddns_delete(
    name: str = Query(...),
    type: str = Query(...),
    user: User = Depends(ddns_user),
    db: Session = Depends(get_db),
):
    fqdn, rtype = _check(name, type)
    zone = _find_zone(db, user, fqdn)
    try:
        _, cur = _current(zone, fqdn, rtype)
        if not cur:
            return {"status": "ok", "name": fqdn, "type": rtype, "changed": False}
        pdns.replace_rrset(zone, fqdn, rtype, 300, [])
        notify_zone(zone)
    except PdnsError as e:
        raise HTTPException(status_code=e.status, detail={"error": str(e)})

    log_history(db, user.id, "zone", zone, f"DDNS delete {rtype} {fqdn}")
    return {"status": "ok", "name": fqdn, "type": rtype, "changed": True}
