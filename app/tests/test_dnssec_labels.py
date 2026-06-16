"""DS / DNSKEY rdata annotation for the zone-settings DNSSEC section."""
from mojodns.pdns import _ds_entry, _dnskey_entry


def test_ds_sha256_recommended():
    e = _ds_entry("26238 13 2 " + "ab" * 32)
    assert e["recommended"] is True
    assert "SHA-256" in e["comment"] and "recommended" in e["comment"]
    assert e["rdata"].startswith("26238 13 2 ")


def test_ds_sha1_deprecated():
    e = _ds_entry("26238 13 1 " + "ab" * 20)
    assert e["recommended"] is False
    assert "SHA-1" in e["comment"] and "deprecated" in e["comment"]


def test_ds_sha384_optional():
    e = _ds_entry("26238 13 4 " + "ab" * 48)
    assert e["recommended"] is False
    assert "SHA-384" in e["comment"]


def test_dnskey_csk_comment():
    e = _dnskey_entry("257 3 13 Bu49rpOL")
    assert "CSK" in e["comment"]
    assert e["rdata"].startswith("257 3 13 ")
