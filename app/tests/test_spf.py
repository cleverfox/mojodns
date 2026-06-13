from mojodns.spf import build_spf, is_spf, parse_spf, render_term, strip_txt


def test_is_spf_and_strip():
    assert is_spf('"v=spf1 -all"')
    assert is_spf("v=spf1 ~all")
    assert not is_spf('"v=DMARC1; p=none"')
    assert strip_txt('"v=spf1 " "include:x -all"') == "v=spf1 include:x -all"


def test_parse_valid_roundtrip():
    c = "v=spf1 include:_spf.google.com ip4:195.3.252.0/24 a mx ~all"
    r = parse_spf(c)
    assert r["valid"] and not r["errors"]
    kinds = [t["kind"] for t in r["terms"]]
    assert kinds == ["include", "ip4", "a", "mx", "all"]
    assert build_spf(r["terms"]) == c


def test_a_mx_value_forms():
    r = parse_spf("v=spf1 a:mail.example.com/24 mx/16 -all")
    assert r["valid"], r["errors"]
    assert build_spf(r["terms"]) == "v=spf1 a:mail.example.com/24 mx/16 -all"


def test_modifiers():
    r = parse_spf("v=spf1 ip4:1.2.3.4 redirect=_spf.example.com")
    assert r["valid"]
    assert any(t["kind"] == "redirect" and t["value"] == "_spf.example.com" for t in r["terms"])


def test_errors_collected():
    r = parse_spf("v=spf1 ip4:999.1.1.1 include: bogusmech ~all")
    assert not r["valid"]
    joined = " ".join(r["errors"])
    assert "invalid IPv4" in joined
    assert "requires a domain" in joined
    assert "unknown mechanism" in joined


def test_missing_version_is_error():
    r = parse_spf("include:x -all")
    assert not r["valid"]
    assert "v=spf1" in r["errors"][0]


def test_warnings():
    after_all = parse_spf("v=spf1 -all include:late.example.com")
    assert any("after 'all'" in w for w in after_all["warnings"])
    # >10 lookups
    many = parse_spf("v=spf1 " + " ".join(f"include:h{i}.example.com" for i in range(11)) + " ~all")
    assert any("limit of 10" in w for w in many["warnings"])


def test_ip6_validation():
    assert parse_spf("v=spf1 ip6:2001:db8::/32 -all")["valid"]
    assert not parse_spf("v=spf1 ip6:nonsense -all")["valid"]


def test_render_term_qualifier_and_modifier():
    assert render_term({"qualifier": "~", "kind": "all", "value": ""}) == "~all"
    assert render_term({"qualifier": "", "kind": "redirect", "value": "x.example"}) == "redirect=x.example"
    assert render_term({"qualifier": "-", "kind": "include", "value": "x.example"}) == "-include:x.example"
