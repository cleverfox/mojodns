"""On-demand secondary (slave) monitoring for a zone.

Polls each published apex NS for the zone's SOA and compares the serial
against the master's. Status per nameserver address:

    ok     responds, serial >= master  (in sync)
    stale  responds, serial <  master  (lagging behind)
    down   no answer / refused / not serving this zone

Queries are over IPv4 — the panel has no IPv6 egress on the docker network,
so AAAA-only nameservers are reported as not pollable rather than down.
"""

import logging
from concurrent.futures import ThreadPoolExecutor

import dns.exception
import dns.flags
import dns.message
import dns.query
import dns.rcode
import dns.rdatatype
import dns.resolver

from .config import settings
from .pdns import canonical, pdns

log = logging.getLogger("mojodns.slaves")


def _resolver() -> dns.resolver.Resolver:
    r = dns.resolver.Resolver(configure=False)
    r.nameservers = settings().verify_resolver_list
    r.timeout = 3.0
    r.lifetime = 6.0
    return r


def apex_ns(zone: str) -> list[str]:
    zone = canonical(zone)
    zdata = pdns.get_zone(zone)
    for rr in zdata["rrsets"]:
        if rr["type"] == "NS" and canonical(rr["name"]) == zone:
            return sorted(canonical(r["content"]) for r in rr["records"])
    return []


def _a_records(name: str) -> list[str]:
    try:
        ans = _resolver().resolve(name.rstrip(".") + ".", "A")
        return sorted(str(r) for r in ans)
    except Exception:
        return []


def _soa_serial(addr: str, zone: str) -> tuple[int | None, str | None]:
    """Query one nameserver address directly for the zone SOA serial."""
    q = dns.message.make_query(canonical(zone), dns.rdatatype.SOA)
    q.flags &= ~dns.flags.RD  # we want the authoritative answer, not recursion
    last = "timeout"
    for proto in (dns.query.udp, dns.query.tcp):  # TCP fallback if UDP is filtered
        try:
            resp = proto(q, addr, timeout=4.0)
            if resp.rcode() != dns.rcode.NOERROR:
                return None, dns.rcode.to_text(resp.rcode()).lower()
            for rrset in resp.answer:
                if rrset.rdtype == dns.rdatatype.SOA:
                    return rrset[0].serial, None
            return None, "no SOA"
        except dns.exception.Timeout:
            last = "timeout"
            continue
        except Exception as e:
            return None, f"error: {e}"
    return None, last


def check_slaves(zone: str, master_serial: int | None, workers: int = 8) -> list[dict]:
    zone = canonical(zone)
    rows: list[dict] = []
    targets: list[tuple[str, str]] = []
    for ns in apex_ns(zone):
        addrs = _a_records(ns)
        if not addrs:
            rows.append({"ns": ns, "addr": None, "serial": None,
                         "status": "down", "detail": "no IPv4 / unresolvable"})
        else:
            targets += [(ns, a) for a in addrs]

    def run(t: tuple[str, str]) -> dict:
        ns, addr = t
        serial, err = _soa_serial(addr, zone)
        if serial is None:
            status, detail = "down", err
        elif master_serial is not None and serial < master_serial:
            status, detail = "stale", f"{master_serial - serial} behind"
        else:
            status, detail = "ok", None
        return {"ns": ns, "addr": addr, "serial": serial, "status": status, "detail": detail}

    if targets:
        with ThreadPoolExecutor(max_workers=workers) as pool:
            rows += list(pool.map(run, targets))
    rows.sort(key=lambda r: (r["ns"], r["addr"] or ""))
    return rows


def summarize(rows: list[dict]) -> str:
    c: dict[str, int] = {}
    for r in rows:
        c[r["status"]] = c.get(r["status"], 0) + 1
    return ", ".join(f"{c[s]} {s}" for s in ("ok", "stale", "down") if s in c) or "no nameservers"
