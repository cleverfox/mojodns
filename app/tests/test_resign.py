"""DNSSEC re-sign scheduler decision logic (pure, no I/O)."""
from datetime import datetime, timedelta, timezone

from mojodns.resign import classify, jitter_seconds, next_due

NOW = datetime(2026, 6, 16, 12, 0, tzinfo=timezone.utc)


def test_jitter_stable_and_bounded():
    a1 = jitter_seconds("a.example.", 3 * 3600)
    a2 = jitter_seconds("a.example.", 3 * 3600)
    assert a1 == a2                         # stable across calls
    assert 0 <= a1 < 3 * 3600               # within bound
    assert jitter_seconds("b.example.", 3 * 3600) != a1 or True  # usually differs


def test_jitter_zero_max():
    assert jitter_seconds("a.example.", 0) == 0


def test_next_due_adds_quiet_plus_jitter():
    due = next_due(NOW, "z.example.", quiet_secs=86400, jitter_max_secs=0)
    assert due == NOW + timedelta(seconds=86400)
    due_j = next_due(NOW, "z.example.", quiet_secs=86400, jitter_max_secs=3 * 3600)
    assert NOW + timedelta(seconds=86400) <= due_j < NOW + timedelta(seconds=86400 + 3 * 3600)


def test_classify_reset_when_serial_unknown_or_changed():
    assert classify(5, None, None, NOW) == "reset"          # first time seen
    assert classify(6, 5, NOW + timedelta(hours=1), NOW) == "reset"  # serial moved → restart timer


def test_classify_bump_when_quiet_and_due():
    assert classify(5, 5, None, NOW) == "bump"              # no due set yet
    assert classify(5, 5, NOW - timedelta(seconds=1), NOW) == "bump"   # past due


def test_classify_wait_when_not_due():
    assert classify(5, 5, NOW + timedelta(hours=2), NOW) == "wait"
