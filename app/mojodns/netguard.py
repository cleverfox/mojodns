"""Network-target safety guard.

The reachability checks (and the DNS-server poll) connect to addresses derived
from user-controlled records. Without a guard a user could point a record at a
loopback / link-local / RFC1918 / cloud-metadata address and turn the panel into
an internal port-scanner (SSRF). `is_public_ip` allows only global unicast.
"""

import ipaddress


def is_public_ip(ip: str) -> bool:
    """True only for a global-unicast, internet-routable address.

    Rejects unparseable input, loopback, link-local, private, reserved,
    multicast, unspecified — and IPv4-mapped IPv6 (`::ffff:a.b.c.d`) whose
    embedded v4 address is itself non-public (a common SSRF bypass)."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    # unwrap IPv4-mapped IPv6 so the v4 checks apply to the real destination
    mapped = getattr(addr, "ipv4_mapped", None)
    if mapped is not None:
        addr = mapped
    if (addr.is_loopback or addr.is_link_local or addr.is_private
            or addr.is_reserved or addr.is_multicast or addr.is_unspecified):
        return False
    return addr.is_global
