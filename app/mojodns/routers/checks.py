"""Per-record reachability checks (TCP/HTTP/HTTPS) + a certificate overview.

Checks are bound to a real A/AAAA record in a zone the user can access — the
panel only ever probes the user's own record targets (anti-SSRF)."""

import re
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db import CertObservation, User, ZoneAccess, get_db, log_history
from ..deps import current_user, zone_guard
from ..httpcheck import check_http, check_https, check_tcp
from ..idn import to_unicode
from ..pdns import PdnsError, canonical, pdns
from ..templating import render

router = APIRouter()


def _record_ips(zone: str, host: str) -> set[str]:
    """A + AAAA contents for `host` in `zone` (the only legal check targets)."""
    fqdn = canonical(host)
    ips: set[str] = set()
    try:
        zdata = pdns.get_zone(zone)
    except PdnsError:
        return ips
    for rr in zdata["rrsets"]:
        if rr["name"] == fqdn and rr["type"] in ("A", "AAAA"):
            ips |= {r["content"] for r in rr["records"]}
    return ips


def _slug(*parts: str) -> str:
    return "cr-" + re.sub(r"[^a-z0-9]+", "-", "-".join(parts).lower()).strip("-")


@router.get("/zones/{zone}/checks")
def check_panel(request: Request, host: str = Query(...), ip: str = Query(...),
                zone: str = Depends(zone_guard), user: User = Depends(current_user)):
    if ip not in _record_ips(zone, host):
        raise HTTPException(status_code=404)
    return render(request, "partials/check_panel.html", user=user, zone=zone,
                  host=host, hostdisp=to_unicode(host.rstrip(".")), ip=ip,
                  slug=_slug(host, ip))


@router.get("/zones/{zone}/check")
def run_check(request: Request, kind: str = Query(...), host: str = Query(...),
              ip: str = Query(...), port: int = Query(443, ge=1, le=65535),
              zone: str = Depends(zone_guard), user: User = Depends(current_user),
              db: Session = Depends(get_db)):
    if ip not in _record_ips(zone, host):
        raise HTTPException(status_code=404)

    if kind == "tcp":
        result = check_tcp(ip, port)
    elif kind == "http":
        result = check_http(ip, host)
    elif kind == "https":
        result = check_https(ip, host)
        _store_cert(db, zone, host, ip, result)
        log_history(db, user.id, "zone", zone,
                    f"HTTPS check {host} ({ip}): {result['status']}"
                    + (f", cert {result['cert'].get('days_left')}d left"
                       if isinstance(result.get("cert"), dict) and result["cert"].get("days_left") is not None else ""))
    else:
        raise HTTPException(status_code=400, detail="unknown check kind")

    return render(request, "partials/check_result.html", user=user, zone=zone,
                  host=host, ip=ip, result=result)


def _store_cert(db: Session, zone: str, host: str, ip: str, result: dict) -> None:
    cert = result.get("cert") if isinstance(result.get("cert"), dict) else None
    row = db.execute(
        select(CertObservation).where(
            CertObservation.host == canonical(host), CertObservation.ip == ip,
            CertObservation.port == 443)
    ).scalar_one_or_none()
    if not row:
        row = CertObservation(host=canonical(host), ip=ip, port=443)
        db.add(row)
    row.zone = zone
    row.checked_at = datetime.now(timezone.utc)
    if cert and "not_after" in cert:
        row.subject = (cert.get("subject") or "")[:255]
        row.issuer = (cert.get("issuer") or "")[:255]
        row.not_after = cert.get("not_after")
        row.days_left = cert.get("days_left")
        row.hostname_match = cert.get("hostname_match")
        row.self_signed = cert.get("self_signed")
        row.trusted = cert.get("trusted")
        row.error = None
    else:
        row.error = (result.get("detail") or (cert or {}).get("error") or "no certificate")[:255]
        row.not_after = None
        row.days_left = None


@router.get("/certs")
def certs_overview(request: Request, user: User = Depends(current_user),
                   db: Session = Depends(get_db)):
    q = select(CertObservation)
    if not user.is_admin:
        mine = select(ZoneAccess.zone).where(ZoneAccess.user_id == user.id)
        q = q.where(CertObservation.zone.in_(mine))
    # soonest expiry first; errored/unknown (NULL not_after) last
    rows = db.execute(q).scalars().all()
    rows.sort(key=lambda c: (c.not_after is None, c.not_after or datetime.max.replace(tzinfo=timezone.utc)))
    return render(request, "certs.html", user=user, rows=rows)
