"""Per-record reachability checks (TCP/HTTP/HTTPS) + a certificate overview.

Checks are bound to a real A/AAAA record in a zone the user can access — the
panel only ever probes the user's own record targets (anti-SSRF)."""

import re
from datetime import datetime, timezone

import dns.resolver
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..config import settings
from ..db import CertObservation, User, ZoneAccess, get_db, log_history
from ..deps import current_user, zone_guard
from ..httpcheck import check_http, check_https, check_tcp
from ..idn import to_unicode
from ..pdns import PdnsError, canonical, pdns
from ..templating import render

router = APIRouter()


def _resolve_ips(name: str) -> list[str]:
    """Recursively resolve a CNAME target's A + AAAA via the verify resolvers."""
    r = dns.resolver.Resolver(configure=False)
    r.nameservers = settings().verify_resolver_list
    r.timeout, r.lifetime = 3.0, 6.0
    out: list[str] = []
    for rtype in ("A", "AAAA"):
        try:
            for rr in r.resolve(name.rstrip(".") + ".", rtype):
                if rr.address not in out:
                    out.append(rr.address)
        except Exception:
            pass
    return out


def _check_targets(zone: str, host: str) -> list[str]:
    """IPs the panel may probe for `host`: its own A/AAAA, or — for a CNAME —
    the resolved A/AAAA of the CNAME target (the only legal check targets)."""
    fqdn = canonical(host)
    ips: list[str] = []
    cname: str | None = None
    try:
        zdata = pdns.get_zone(zone)
    except PdnsError:
        return ips
    for rr in zdata["rrsets"]:
        if rr["name"] != fqdn:
            continue
        if rr["type"] in ("A", "AAAA"):
            for r in rr["records"]:
                if r["content"] not in ips:
                    ips.append(r["content"])
        elif rr["type"] == "CNAME" and rr["records"]:
            cname = rr["records"][0]["content"]
    if not ips and cname:
        ips = _resolve_ips(cname)
    return ips


def _slug(*parts: str) -> str:
    return "cr-" + re.sub(r"[^a-z0-9]+", "-", "-".join(parts).lower()).strip("-")


@router.get("/zones/{zone}/checks")
def check_panel(request: Request, host: str = Query(...), ip: str = Query(None),
                zone: str = Depends(zone_guard), user: User = Depends(current_user)):
    ips = _check_targets(zone, host)
    sel = ip if ip in ips else (ips[0] if ips else None)
    return render(request, "partials/check_panel.html", user=user, zone=zone,
                  host=host, hostdisp=to_unicode(host.rstrip(".")), ips=ips,
                  sel=sel, slug=_slug(host))


@router.get("/zones/{zone}/check")
def run_check(request: Request, kind: str = Query(...), host: str = Query(...),
              ip: str = Query(...), port: int = Query(443, ge=1, le=65535),
              zone: str = Depends(zone_guard), user: User = Depends(current_user),
              db: Session = Depends(get_db)):
    if ip not in _check_targets(zone, host):
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
