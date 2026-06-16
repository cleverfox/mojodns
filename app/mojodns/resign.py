"""DNSSEC signature-freshness scheduler.

PowerDNS live-signs, but the NSD secondaries are "dumb" — they only re-AXFR when
the SOA serial changes, so a signed zone that never changes would eventually serve
expired RRSIGs (→ SERVFAIL for validating resolvers). This sweep bumps each signed
zone's serial ~24h after its last change so the secondaries pull freshly-signed
records well within the RRSIG validity window.

The clock is driven off the serial itself: any change (panel, API, ACME, RFC2136)
moves the serial and resets the 24h timer, so we never instrument individual write
paths and never double-bump a zone that just changed. Bumps are jittered per zone
and capped per sweep so a bulk-enable cohort can't all fire at once.
"""

import hashlib
import logging
import math
from datetime import datetime, timedelta, timezone

from sqlalchemy import select

from .config import settings
from .db import SessionLocal, ZoneSigning
from .notifier import notify_zone
from .pdns import pdns

log = logging.getLogger("mojodns.resign")

# at most ~1 bump per this many signed zones, per sweep (hard peak ceiling)
_CAP_DIVISOR = 40


def jitter_seconds(zone: str, max_secs: int) -> int:
    """Stable per-zone offset in [0, max_secs) — spreads a cohort that all came
    due at the same time. Uses a content hash (process `hash()` isn't stable)."""
    if max_secs <= 0:
        return 0
    h = int(hashlib.sha256(zone.encode()).hexdigest(), 16)
    return h % max_secs


def next_due(now: datetime, zone: str, quiet_secs: int, jitter_max_secs: int) -> datetime:
    return now + timedelta(seconds=quiet_secs + jitter_seconds(zone, jitter_max_secs))


def classify(serial: int, last_serial: int | None, due_at: datetime | None,
             now: datetime) -> str:
    """One of: 'reset' (serial moved since last sweep — restart the timer),
    'bump' (quiet and due — re-sign now), 'wait' (not yet)."""
    if last_serial is None or serial != last_serial:
        return "reset"
    if due_at is None or now >= due_at:
        return "bump"
    return "wait"


def _bump_serial(zone: str) -> None:
    """Re-write the SOA (SOA-EDIT-API=DEFAULT recomputes a higher serial) and
    NOTIFY, so the secondaries re-AXFR a freshly-signed copy."""
    zdata = pdns.get_zone(zone)
    for rr in zdata["rrsets"]:
        if rr["type"] == "SOA" and rr["records"]:
            pdns.replace_rrset(zone, zone, "SOA", rr["ttl"],
                               [{"content": rr["records"][0]["content"], "disabled": False}])
            break
    notify_zone(zone)


def resign_due_zones() -> dict:
    """One sweep: reset timers for changed zones, bump the due ones (capped)."""
    s = settings()
    quiet = int(s.dnssec_resign_quiet_hours * 3600)
    jit = int(s.dnssec_resign_jitter_hours * 3600)
    now = datetime.now(timezone.utc)

    signed = [(z["name"], z.get("serial")) for z in pdns.list_zones() if z.get("dnssec")]
    cap = max(1, math.ceil(len(signed) / _CAP_DIVISOR))
    bumped: list[str] = []

    with SessionLocal() as db:
        rows = {r.zone: r for r in db.execute(select(ZoneSigning)).scalars()}
        signed_names = set()
        for name, serial in signed:
            signed_names.add(name)
            r = rows.get(name)
            if r is None:
                db.add(ZoneSigning(zone=name, last_serial=serial,
                                   due_at=next_due(now, name, quiet, jit)))
                continue
            action = classify(serial, r.last_serial, r.due_at, now)
            if action == "reset":
                r.last_serial = serial
                r.due_at = next_due(now, name, quiet, jit)
            elif action == "bump":
                if len(bumped) >= cap:
                    continue  # backstop; the rest catch the next sweep
                try:
                    _bump_serial(name)
                    bumped.append(name)
                    r.last_serial = (pdns.get_zone(name).get("serial")) or serial
                    r.due_at = next_due(now, name, quiet, jit)
                except Exception as e:
                    log.warning("re-sign bump failed for %s: %s", name, e)
        # forget zones that are no longer signed
        for zname, r in rows.items():
            if zname not in signed_names:
                db.delete(r)
        db.commit()

    if bumped:
        log.info("DNSSEC re-sign: bumped %d/%d signed zones: %s",
                 len(bumped), len(signed), ", ".join(bumped))
    return {"signed": len(signed), "bumped": bumped}
