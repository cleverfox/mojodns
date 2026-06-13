"""Zone NOTIFY orchestration.

For most zones we let PowerDNS send NOTIFY (global also-notify + the zone's
NS records). But a *custom DNS* zone can carry an explicit notify list
(stored as the zone's ALSO-NOTIFY metadata); when set, NOTIFY must go to
*exactly* those servers and nobody else.

PowerDNS can't scope NOTIFY to a per-zone list — its global also-notify and
NS-based notify always apply, and the primary communicator auto-notifies
Master zones on serial change. So custom-with-list zones are kept `Native`
(pdns never notifies them) and the panel sends NOTIFY itself, here, to
exactly the list. Sending is best-effort over IPv4 (the panel has no IPv6
egress); secondaries also poll on their SOA refresh as a backstop.
"""

import ipaddress
import logging
import re

import dns.flags
import dns.message
import dns.opcode
import dns.query
import dns.rdatatype
import dns.resolver

from .config import settings
from .pdns import canonical, pdns

log = logging.getLogger("mojodns.notify")

# one DNS label .. dotted hostname (trailing dot allowed), <=253 chars
_HOST_RE = re.compile(
    r"^(?=.{1,253}\.?$)(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))*\.?$",
    re.IGNORECASE,
)


def split_host_port(token: str) -> tuple[str, int]:
    token = token.strip()
    if token.startswith("["):           # [v6]:port  or  [v6]
        host, _, rest = token[1:].partition("]")
        port = rest.lstrip(":")
    elif token.count(":") == 1:          # v4:port  or  host:port
        host, _, port = token.partition(":")
    else:                                # bare v4, bare v6, or bare hostname
        host, port = token, ""
    return host, int(port) if port else 53


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def parse_targets(raw: str) -> list[str]:
    """Split/validate a notify list into ip / ip:port / hostname[:port] tokens.

    Raises ValueError on a malformed entry."""
    out: list[str] = []
    for tok in re.split(r"[,\s]+", (raw or "").strip()):
        if not tok:
            continue
        host, _ = split_host_port(tok)
        if not (_is_ip(host) or _HOST_RE.match(host)):
            raise ValueError(f"invalid notify target: {tok}")
        if tok not in out:
            out.append(tok)
    return out


def _resolver() -> dns.resolver.Resolver:
    r = dns.resolver.Resolver(configure=False)
    r.nameservers = settings().verify_resolver_list
    r.timeout = 3.0
    r.lifetime = 6.0
    return r


def _resolve(host: str) -> list[str]:
    """Resolve a notify target to IP literal(s); IPs pass through unchanged.

    Hostnames resolve to IPv4 only — the panel sends over IPv4 (no IPv6 egress
    here), same as the slave-check. An explicit IPv6 *literal* is still passed
    through for deployments that do have v6 egress."""
    if _is_ip(host):
        return [host]
    try:
        return [str(r) for r in _resolver().resolve(host.rstrip(".") + ".", "A")]
    except Exception:
        return []


def send_notify(zone: str, targets: list[str]) -> None:
    """Send a DNS NOTIFY for `zone` to each target (best-effort, fire-and-forget).

    Hostnames are resolved to IPs first (dnspython needs an IP literal). A
    target that replies — even with a NOTIFY ack dnspython considers a
    "mismatched" response — counts as delivered."""
    m = dns.message.make_query(canonical(zone), dns.rdatatype.SOA)
    m.set_opcode(dns.opcode.NOTIFY)
    m.flags &= ~dns.flags.RD
    m.flags |= dns.flags.AA
    for t in targets:
        host, port = split_host_port(t)
        ips = _resolve(host)
        if not ips:
            log.warning("NOTIFY %s -> %s: could not resolve", zone, t)
            continue
        for ip in ips:
            try:
                dns.query.udp(m, ip, port=port, timeout=3)
                log.info("NOTIFY %s -> %s (%s)", zone, t, ip)
            except dns.query.BadResponse:
                # target answered (NOTIFY ack); dnspython just dislikes the
                # response shape — the NOTIFY was delivered
                log.info("NOTIFY %s -> %s (%s) delivered", zone, t, ip)
            except Exception as e:  # timeout, unreachable, etc.
                log.warning("NOTIFY %s -> %s (%s) failed: %s", zone, t, ip, e)


def notify_zone(zone: str) -> None:
    """Notify a zone's secondaries.

    Custom zone with an explicit notify list → send to exactly that list.
    Otherwise → let PowerDNS notify (global also-notify + NS records)."""
    targets = pdns.get_zone_also_notify(zone)
    if targets:
        send_notify(zone, targets)
    else:
        pdns.notify(zone)
