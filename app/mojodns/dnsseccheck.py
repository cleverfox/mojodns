"""Rich on-demand DNSSEC diagnostic for a zone.

Beyond the AD-bit verdict (verify.dnssec_status) it answers the two questions a
resolver's verdict hides: does the parent's DS actually match our active key(s),
and are the secondaries' RRSIGs about to expire? Read-only; nothing is stored.
"""

import logging
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

import dns.exception
import dns.flags
import dns.message
import dns.query
import dns.rcode
import dns.rdatatype
import dns.resolver

from .config import settings
from .pdns import canonical, pdns
from .slaves import _a_records, _addr_ok, apex_ns
from .verify import _resolver, dnssec_status

log = logging.getLogger("mojodns.dnsseccheck")


def _ds_tuple(rdata: str) -> tuple | None:
    """Normalise a DS rdata '<keytag> <algo> <digesttype> <digest>' for comparison."""
    p = rdata.split()
    if len(p) < 4:
        return None
    try:
        return (int(p[0]), int(p[1]), int(p[2]), "".join(p[3:]).lower())
    except ValueError:
        return None


def classify_parent(parent: set, ours: set) -> tuple[str, set, set]:
    """(state, matched, extra) — state is absent | ok | mismatch; `extra` is parent
    DS that match no active key (stale after a rollover, or simply wrong)."""
    if not parent:
        return "absent", set(), set()
    matched = parent & ours
    extra = parent - ours
    if matched:
        return "ok", matched, extra
    return "mismatch", set(), extra


def _classify_ns(signed: bool | None, days_left: int | None, warn_days: int) -> str:
    if signed is None:
        return "down"
    if not signed:
        return "unsigned"
    if days_left is not None and days_left < warn_days:
        return "expiring"
    return "ok"


def _parent_ds(zone: str) -> tuple[set, str | None]:
    """DS tuples published by the parent (via a validating resolver); empty set =
    no DS (insecure)."""
    try:
        ans = _resolver().resolve(canonical(zone), "DS")
        return {t for t in (_ds_tuple(rr.to_text()) for rr in ans) if t}, None
    except dns.resolver.NoAnswer:
        return set(), None
    except dns.resolver.NXDOMAIN:
        return set(), "NXDOMAIN"
    except dns.resolver.NoNameservers:
        return set(), "SERVFAIL"
    except (dns.resolver.LifetimeTimeout, dns.exception.Timeout):
        return set(), "timeout"
    except Exception as e:
        return set(), f"error: {e}"


def _ns_signature(ip: str, zone: str) -> tuple[bool | None, int | None, str | None]:
    """Ask one nameserver (no recursion, DO=1) for the apex DNSKEY and read its
    RRSIG. Returns (signed, soonest_rrsig_expiry_epoch, error)."""
    q = dns.message.make_query(canonical(zone), dns.rdatatype.DNSKEY, want_dnssec=True)
    q.flags &= ~dns.flags.RD
    last = "timeout"
    for proto in (dns.query.udp, dns.query.tcp):
        try:
            resp = proto(q, ip, timeout=4.0)
        except dns.exception.Timeout:
            last = "timeout"
            continue
        except Exception as e:
            return None, None, f"error: {e}"
        if resp.rcode() != dns.rcode.NOERROR:
            return None, None, dns.rcode.to_text(resp.rcode()).lower()
        exp = None
        for rrset in resp.answer:
            if rrset.rdtype == dns.rdatatype.RRSIG:
                for rr in rrset:
                    if rr.type_covered == dns.rdatatype.DNSKEY:
                        exp = rr.expiration if exp is None else min(exp, rr.expiration)
        return (exp is not None), exp, None
    return None, None, last


def check_dnssec(zone: str) -> dict:
    """Full diagnostic. `secured=False` when the zone has no active keys — but we
    still query the parent: a leftover DS on an unsigned zone is a hard outage."""
    zone = canonical(zone)
    active = [k for k in pdns.zone_cryptokeys(zone) if k.get("active")]
    parent, perr = _parent_ds(zone)

    if not active:
        # Not signed here. If the parent still publishes a DS, validating resolvers
        # are told to authenticate answers that carry no signatures → BOGUS /
        # SERVFAIL: the zone is effectively down for everyone who validates.
        warnings = []
        if parent:
            warnings.append(
                "CRITICAL: the parent publishes a DS record but this zone is NOT "
                "signed — validating resolvers treat every answer as BOGUS (SERVFAIL), "
                "so the zone is effectively DOWN for anyone who validates. Remove the "
                "DS at the registrar, or re-enable DNSSEC.")
        return {"secured": False, "dangling_ds": bool(parent),
                "parent": {"state": "dangling" if parent else "absent",
                           "ds": sorted(parent), "matched": [], "extra": sorted(parent),
                           "error": perr},
                "warnings": warnings}

    ours = {t for k in active for d in (k.get("ds") or []) if (t := _ds_tuple(d))}
    verdict = dnssec_status(zone)
    pstate, matched, extra = classify_parent(parent, ours)

    warn_days = settings().dnssec_rrsig_warn_days
    now_ts = datetime.now(timezone.utc).timestamp()

    targets, rows = [], []
    for ns in apex_ns(zone):
        addrs = [a for a in _a_records(ns) if _addr_ok(a)]
        if not addrs:
            rows.append({"ns": ns, "addr": None, "status": "down",
                         "expires_at": None, "days_left": None,
                         "detail": "no IPv4 / unresolvable"})
        else:
            targets += [(ns, a) for a in addrs]

    def run(t):
        ns, addr = t
        signed, exp, err = _ns_signature(addr, zone)
        days = int((exp - now_ts) // 86400) if exp is not None else None
        return {"ns": ns, "addr": addr, "status": _classify_ns(signed, days, warn_days),
                "expires_at": datetime.fromtimestamp(exp, timezone.utc) if exp else None,
                "days_left": days, "detail": err}

    if targets:
        with ThreadPoolExecutor(max_workers=8) as pool:
            rows += list(pool.map(run, targets))
    rows.sort(key=lambda r: (r["ns"], r["addr"] or ""))

    days = [r["days_left"] for r in rows if r["days_left"] is not None]
    soonest = min(days) if days else None

    warnings = []
    if pstate == "absent":
        warnings.append("No DS at the parent — submit the DS at your registrar to "
                        "activate the chain of trust.")
    elif pstate == "mismatch":
        warnings.append("The parent's DS matches no active key — validating resolvers "
                        "will FAIL (bogus). Fix the DS at the registrar.")
    if extra:
        tags = ", ".join(str(t[0]) for t in sorted(extra))
        warnings.append(f"Parent also publishes DS for key tag(s) {tags} not active "
                        f"here — stale; remove after a completed rollover.")
    if any(r["status"] == "unsigned" for r in rows):
        warnings.append("A nameserver is not serving signed data for this zone.")
    if soonest is not None and soonest < warn_days:
        warnings.append(f"A secondary's RRSIGs expire in {soonest}d — the re-sign / "
                        f"transfer path may be stalled.")

    return {"secured": True, "verdict": verdict,
            "parent": {"state": pstate, "ds": sorted(parent), "matched": sorted(matched),
                       "extra": sorted(extra), "error": perr},
            "nameservers": rows, "soonest_days": soonest, "warnings": warnings}
