"""Pure helpers of the rich DNSSEC checker (no network)."""
from mojodns import dnsseccheck
from mojodns.dnsseccheck import _classify_ns, _ds_tuple, classify_parent


def test_ds_tuple_normalises():
    assert _ds_tuple("26238 13 2 ABCD") == (26238, 13, 2, "abcd")
    assert _ds_tuple("bad") is None
    assert _ds_tuple("x 13 2 ab") is None   # non-numeric key tag


def test_classify_parent_absent():
    state, matched, extra = classify_parent(set(), {(1, 13, 2, "aa")})
    assert state == "absent" and not matched and not extra


def test_classify_parent_ok_exact():
    ours = {(1, 13, 2, "aa")}
    state, matched, extra = classify_parent({(1, 13, 2, "aa")}, ours)
    assert state == "ok" and matched == ours and not extra


def test_classify_parent_ok_with_stale_extra():
    ours = {(1, 13, 2, "aa")}
    parent = {(1, 13, 2, "aa"), (9, 13, 2, "bb")}   # an old key's DS lingers
    state, matched, extra = classify_parent(parent, ours)
    assert state == "ok" and matched == {(1, 13, 2, "aa")} and extra == {(9, 13, 2, "bb")}


def test_classify_parent_mismatch():
    state, matched, extra = classify_parent({(9, 13, 2, "bb")}, {(1, 13, 2, "aa")})
    assert state == "mismatch" and not matched and extra == {(9, 13, 2, "bb")}


def test_classify_ns_thresholds():
    assert _classify_ns(None, None, 3) == "down"
    assert _classify_ns(False, None, 3) == "unsigned"
    assert _classify_ns(True, 10, 3) == "ok"
    assert _classify_ns(True, 2, 3) == "expiring"
    assert _classify_ns(True, -1, 3) == "expiring"   # already expired


def test_unsigned_with_dangling_ds_is_critical(monkeypatch):
    # zone not signed locally, but the parent still has a DS → hard outage
    monkeypatch.setattr(dnsseccheck.pdns, "zone_cryptokeys", lambda z: [])
    monkeypatch.setattr(dnsseccheck, "_parent_ds", lambda z: ({(1, 13, 2, "aa")}, None))
    rep = dnsseccheck.check_dnssec("example.test.")
    assert rep["secured"] is False
    assert rep["dangling_ds"] is True
    assert rep["parent"]["state"] == "dangling"
    assert rep["warnings"] and "CRITICAL" in rep["warnings"][0]


def test_unsigned_without_ds_is_clean(monkeypatch):
    monkeypatch.setattr(dnsseccheck.pdns, "zone_cryptokeys", lambda z: [])
    monkeypatch.setattr(dnsseccheck, "_parent_ds", lambda z: (set(), None))
    rep = dnsseccheck.check_dnssec("example.test.")
    assert rep["secured"] is False
    assert rep["dangling_ds"] is False
    assert not rep["warnings"]
