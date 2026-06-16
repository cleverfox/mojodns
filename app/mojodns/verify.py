"""Zone NS-delegation verification.

For each zone, the configured apex NS records are compared with the NS set
obtained from a *recursive* resolver (i.e. what the world actually sees):

    ok        all configured NS match the resolved set exactly
    partial   some overlap — delegation partially points elsewhere
    mismatch  no overlap, NXDOMAIN or no NS at all — moved or abandoned
    error     could not check (timeout / SERVFAIL on the resolver side)
"""

import logging
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timezone

import dns.flags
import dns.message
import dns.query
import dns.rcode
import dns.rdatatype
import dns.resolver
from sqlalchemy import select
from sqlalchemy.orm import Session

from .config import settings
from .db import ZoneCheck
from .pdns import canonical, pdns

log = logging.getLogger("mojodns.verify")


@dataclass
class CheckResult:
    zone: str
    status: str
    configured: set[str] = field(default_factory=set)
    resolved: set[str] = field(default_factory=set)
    detail: str | None = None
    dnssec: str | None = None


def _resolver() -> dns.resolver.Resolver:
    r = dns.resolver.Resolver(configure=False)
    r.nameservers = settings().verify_resolver_list
    r.timeout = 3.0
    r.lifetime = 6.0
    return r


def resolve_ns(zone: str) -> tuple[set[str], str | None]:
    """Recursive NS lookup -> (set of canonical NS names, error string)."""
    try:
        answer = _resolver().resolve(zone.rstrip(".") + ".", "NS")
        return {canonical(str(rr.target)) for rr in answer}, None
    except dns.resolver.NXDOMAIN:
        return set(), "NXDOMAIN"
    except dns.resolver.NoAnswer:
        return set(), "no NS records"
    except dns.resolver.NoNameservers:
        return set(), "SERVFAIL"
    except (dns.resolver.LifetimeTimeout, dns.exception.Timeout):
        return set(), "timeout"
    except Exception as e:  # resolver misconfiguration etc.
        return set(), f"error: {e}"


def classify(configured: set[str], resolved: set[str], error: str | None) -> str:
    if error in ("timeout", "SERVFAIL") or (error or "").startswith("error:"):
        return "error"
    if not resolved or not (configured & resolved):
        return "mismatch"  # NXDOMAIN / no NS / fully delegated elsewhere
    if configured == resolved:
        return "ok"
    return "partial"


def configured_ns(zdata: dict, zone: str) -> set[str]:
    return {
        canonical(rec["content"])
        for rr in zdata["rrsets"]
        if rr["type"] == "NS" and canonical(rr["name"]) == canonical(zone)
        for rec in rr["records"]
    }


def dnssec_status(zone: str) -> str:
    """What validating resolvers make of this (locally-signed) zone:
        secure   — AD bit set: full chain of trust (DS at parent + valid sigs)
        insecure — answers, but not authenticated: DS not published at the parent
        bogus    — SERVFAIL from a validator: DS present but signatures don't verify
        error    — couldn't ask any resolver
    """
    q = dns.message.make_query(canonical(zone), dns.rdatatype.SOA, want_dnssec=True)
    q.flags |= dns.flags.RD | dns.flags.AD
    for ip in settings().verify_resolver_list:
        try:
            r = dns.query.udp(q, ip, timeout=4.0)
        except Exception:
            continue
        if r.rcode() == dns.rcode.SERVFAIL:
            return "bogus"
        if r.rcode() != dns.rcode.NOERROR:
            continue
        return "secure" if (r.flags & dns.flags.AD) else "insecure"
    return "error"


def check_zone(zone: str) -> CheckResult:
    zone = canonical(zone)
    try:
        zdata = pdns.get_zone(zone)
        conf = configured_ns(zdata, zone)
    except Exception as e:
        return CheckResult(zone, "error", detail=f"pdns: {e}")
    resolved, err = resolve_ns(zone)
    sec = dnssec_status(zone) if zdata.get("dnssec") else "unsigned"
    return CheckResult(zone, classify(conf, resolved, err), conf, resolved, err, dnssec=sec)


def check_zones(zones: list[str], workers: int = 10) -> list[CheckResult]:
    with ThreadPoolExecutor(max_workers=workers) as pool:
        return list(pool.map(check_zone, zones))


def store_results(db: Session, results: list[CheckResult]) -> None:
    for r in results:
        row = db.execute(select(ZoneCheck).where(ZoneCheck.zone == r.zone)).scalar_one_or_none()
        if not row:
            row = ZoneCheck(zone=r.zone, status=r.status)
            db.add(row)
        row.status = r.status
        row.resolved_ns = " ".join(sorted(r.resolved)) or None
        row.detail = r.detail
        row.dnssec = r.dnssec
        row.checked_at = datetime.now(timezone.utc)
    db.flush()


def load_checks(db: Session) -> dict[str, ZoneCheck]:
    return {c.zone: c for c in db.execute(select(ZoneCheck)).scalars()}


def summarize(results: list[CheckResult]) -> str:
    counts: dict[str, int] = {}
    for r in results:
        counts[r.status] = counts.get(r.status, 0) + 1
    parts = [f"{counts[s]} {s}" for s in ("ok", "partial", "mismatch", "error") if s in counts]
    return ", ".join(parts) or "nothing to check"
