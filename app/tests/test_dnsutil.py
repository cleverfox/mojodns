from mojodns.dnsutil import Soa, build_content, email_to_rname, flatten_rrsets, split_prio
from mojodns.idn import to_ascii, to_unicode


def test_build_content_hostname_types():
    assert build_content("CNAME", "www.example.com") == "www.example.com."
    assert build_content("NS", "ns1.example.net.") == "ns1.example.net."
    assert build_content("A", "192.0.2.1") == "192.0.2.1"


def test_build_content_prio_types():
    assert build_content("MX", "mail.example.com", 10) == "10 mail.example.com."
    assert build_content("SRV", "5 5060 sip.example.com", 20) == "20 5 5060 sip.example.com."


def test_build_content_txt_quoting():
    assert build_content("TXT", "v=spf1 -all") == '"v=spf1 -all"'
    assert build_content("TXT", '"already quoted"') == '"already quoted"'


def test_split_prio_roundtrip():
    assert split_prio("MX", "10 mail.example.com.") == (10, "mail.example.com.")
    assert split_prio("A", "192.0.2.1") == (None, "192.0.2.1")


def test_soa_parse_email():
    soa = Soa.parse("ns1.example.net. hostmaster.example.net. 2026061201 10800 3600 604800 3600")
    assert soa.serial == 2026061201
    assert soa.email == "hostmaster@example.net"
    assert soa.content().startswith("ns1.example.net. hostmaster.example.net. 2026061201")


def test_email_to_rname():
    assert email_to_rname("hostmaster@example.net") == "hostmaster.example.net."
    assert email_to_rname("john.doe@example.net") == "john\\.doe.example.net."


def test_flatten_rrsets():
    soa, rows = flatten_rrsets(
        [
            {"name": "example.com.", "type": "SOA", "ttl": 86400,
             "records": [{"content": "ns1.example.net. hostmaster.example.net. 1 2 3 4 5"}]},
            {"name": "example.com.", "type": "MX", "ttl": 3600,
             "records": [{"content": "10 mail.example.com.", "disabled": False}]},
        ]
    )
    assert soa.mname == "ns1.example.net."
    assert rows[0]["prio"] == 10 and rows[0]["data"] == "mail.example.com."


def test_idn_roundtrip():
    assert to_ascii("пример.рф") == "xn--e1afmkfd.xn--p1ai"
    assert to_unicode("xn--e1afmkfd.xn--p1ai") == "пример.рф"
    assert to_ascii("*.example.com") == "*.example.com"
    assert to_ascii("_dmarc.example.com.") == "_dmarc.example.com."
