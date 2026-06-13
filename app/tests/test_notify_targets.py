import pytest

from mojodns.notifier import parse_targets, split_host_port


def test_parse_plain_ipv4():
    assert parse_targets("192.0.2.10") == ["192.0.2.10"]


def test_parse_mixed_separators_and_port():
    assert parse_targets("192.0.2.10, 198.51.100.4:5353  203.0.113.7") == \
        ["192.0.2.10", "198.51.100.4:5353", "203.0.113.7"]


def test_parse_ipv6_and_bracketed_port():
    assert parse_targets("2001:db8::1") == ["2001:db8::1"]
    assert parse_targets("[2001:db8::1]:5353") == ["[2001:db8::1]:5353"]


def test_parse_empty_is_empty_list():
    assert parse_targets("") == []
    assert parse_targets("   ") == []


def test_parse_dedup():
    assert parse_targets("192.0.2.10, 192.0.2.10") == ["192.0.2.10"]


def test_parse_hostnames():
    assert parse_targets("ns.example.com") == ["ns.example.com"]
    assert parse_targets("ns1.example.com:5353, 192.0.2.10") == \
        ["ns1.example.com:5353", "192.0.2.10"]
    assert parse_targets("slave.dns.he.net") == ["slave.dns.he.net"]


def test_parse_invalid_raises():
    with pytest.raises(ValueError):
        parse_targets("bad_host!")            # underscore/bang not allowed
    with pytest.raises(ValueError):
        parse_targets("192.0.2.10, bad..dots")  # empty label
    with pytest.raises(ValueError):
        parse_targets("-bad.example.com")     # label starting with hyphen


def test_split_host_port():
    assert split_host_port("192.0.2.10") == ("192.0.2.10", 53)
    assert split_host_port("192.0.2.10:5353") == ("192.0.2.10", 5353)
    assert split_host_port("2001:db8::1") == ("2001:db8::1", 53)
    assert split_host_port("[2001:db8::1]:5353") == ("2001:db8::1", 5353)
