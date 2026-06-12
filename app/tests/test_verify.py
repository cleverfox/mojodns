from mojodns.verify import classify

NS1, NS2, CF1, CF2 = "ns1.example.net.", "ns2.example.net.", "a.ns.cloudflare.com.", "b.ns.cloudflare.com."


def test_all_match_is_ok():
    assert classify({NS1, NS2}, {NS1, NS2}, None) == "ok"


def test_partial_overlap_is_partial():
    assert classify({NS1, NS2}, {NS1, CF1}, None) == "partial"
    # extra NS in delegation also counts as partial
    assert classify({NS1}, {NS1, NS2}, None) == "partial"


def test_moved_to_cloudflare_is_mismatch():
    assert classify({NS1, NS2}, {CF1, CF2}, None) == "mismatch"


def test_abandoned_is_mismatch():
    assert classify({NS1, NS2}, set(), "NXDOMAIN") == "mismatch"
    assert classify({NS1, NS2}, set(), "no NS records") == "mismatch"


def test_resolver_trouble_is_error():
    assert classify({NS1}, set(), "timeout") == "error"
    assert classify({NS1}, set(), "SERVFAIL") == "error"
