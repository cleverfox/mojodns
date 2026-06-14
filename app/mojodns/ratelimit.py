"""Tiny in-memory per-user rate limiter for the outbound-probe actions.

A sliding 60-second window keyed by user id. The web app runs a single uvicorn
worker, so process-global state is shared across all requests; sync endpoints run
in a threadpool, hence the lock. State is best-effort (lost on restart) — fine for
abuse-throttling the reachability / DNS-server checks.
"""

import threading
import time

WINDOW = 60.0

_hits: dict[int, list[float]] = {}
_lock = threading.Lock()


def allow(user_id: int, limit_per_min: int) -> tuple[bool, int]:
    """Record an attempt; return (allowed, retry_after_seconds).

    `limit_per_min <= 0` means unlimited. When the limit is already reached the
    attempt is NOT counted and retry_after is the seconds until the oldest hit
    in the window ages out."""
    if limit_per_min <= 0:
        return True, 0
    now = time.monotonic()
    with _lock:
        hits = [t for t in _hits.get(user_id, ()) if now - t < WINDOW]
        if len(hits) >= limit_per_min:
            retry = max(1, int(WINDOW - (now - hits[0]) + 0.999))
            _hits[user_id] = hits
            return False, retry
        hits.append(now)
        _hits[user_id] = hits
        return True, 0
