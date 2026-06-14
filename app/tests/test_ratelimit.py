from mojodns import ratelimit


def test_allows_up_to_limit_then_blocks():
    uid = 1001
    assert ratelimit.allow(uid, 2)[0] is True
    assert ratelimit.allow(uid, 2)[0] is True
    ok, retry = ratelimit.allow(uid, 2)
    assert ok is False
    assert retry >= 1   # seconds until the window frees a slot


def test_zero_or_negative_limit_is_unlimited():
    uid = 1002
    for _ in range(50):
        assert ratelimit.allow(uid, 0)[0] is True


def test_per_user_independent():
    a, b = 1003, 1004
    assert ratelimit.allow(a, 1)[0] is True
    assert ratelimit.allow(a, 1)[0] is False   # a exhausted
    assert ratelimit.allow(b, 1)[0] is True    # b unaffected


def test_non_int_keys_supported_and_independent():
    # login throttling keys by ("login", ip) — tuples/strings must work
    assert ratelimit.allow(("login", "203.0.113.5"), 1)[0] is True
    assert ratelimit.allow(("login", "203.0.113.5"), 1)[0] is False
    assert ratelimit.allow(("login", "203.0.113.6"), 1)[0] is True  # other IP unaffected


def test_window_expiry_reallows(monkeypatch):
    uid = 1005
    clock = {"t": 1000.0}
    monkeypatch.setattr(ratelimit.time, "monotonic", lambda: clock["t"])
    assert ratelimit.allow(uid, 1)[0] is True
    assert ratelimit.allow(uid, 1)[0] is False
    clock["t"] += ratelimit.WINDOW + 1       # let the hit age out
    assert ratelimit.allow(uid, 1)[0] is True
