"""Zone transfer (AXFR) from the pdns DNS listener — used by the "view
zone" feature to show a zone exactly as a secondary receives it. Goes over
the real DNS transfer path (TSIG and all), so a failure here means the
secondaries cannot transfer either."""

import socket

import dns.exception
import dns.name
import dns.query
import dns.tsigkeyring
import dns.xfr
import dns.zone

from .config import settings


class AxfrError(Exception):
    pass


def axfr_text(zone: str) -> tuple[str, int]:
    """Transfer `zone` and return (zone file text, record count)."""
    s = settings()
    try:
        addr = socket.getaddrinfo(s.pdns_axfr_host, None)[0][4][0]
    except socket.gaierror as e:
        raise AxfrError(f"cannot resolve {s.pdns_axfr_host}: {e}")

    kw = {}
    if s.tsig_key and s.tsig_secret:
        kw = {
            "keyring": dns.tsigkeyring.from_text({s.tsig_key: s.tsig_secret}),
            "keyname": dns.name.from_text(s.tsig_key),
            "keyalgorithm": dns.name.from_text(s.tsig_algo),
        }
    try:
        xfr = dns.query.xfr(addr, zone, port=s.pdns_axfr_port, timeout=10, lifetime=30,
                            relativize=False, **kw)
        z = dns.zone.from_xfr(xfr, relativize=False)
    except dns.xfr.TransferError as e:
        raise AxfrError(f"transfer refused: {e}")
    except dns.exception.FormError as e:
        raise AxfrError(f"malformed transfer: {e}")
    except (dns.exception.Timeout, OSError) as e:
        raise AxfrError(f"cannot reach {addr}:{s.pdns_axfr_port}: {e}")
    except Exception as e:  # tsig errors etc.
        raise AxfrError(str(e))

    text = z.to_text(sorted=True, relativize=False)
    count = sum(len(rds) for _, rds in z.iterate_rdatasets())
    return text, count
