import pytest

from mojodns.pdns import parse_update_cidrs


def test_bare_ipv4_becomes_host_route():
    assert parse_update_cidrs("198.51.100.10") == ["198.51.100.10/32"]


def test_bare_ipv6_becomes_host_route():
    assert parse_update_cidrs("2001:db8::1") == ["2001:db8::1/128"]


def test_cidr_ranges_kept():
    assert parse_update_cidrs("198.51.100.0/24, 2001:db8::/48") == \
        ["198.51.100.0/24", "2001:db8::/48"]


def test_non_strict_host_bits_normalised():
    # strict=False: host bits are masked off to the network address
    assert parse_update_cidrs("198.51.100.10/24") == ["198.51.100.0/24"]


def test_mixed_separators():
    assert parse_update_cidrs("10.0.0.0/8  172.16.0.0/12,192.168.0.0/16") == \
        ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]


def test_empty_is_empty_list():
    assert parse_update_cidrs("") == []
    assert parse_update_cidrs("   ") == []


def test_dedup():
    assert parse_update_cidrs("198.51.100.0/24, 198.51.100.0/24") == ["198.51.100.0/24"]


def test_invalid_raises_with_token():
    with pytest.raises(ValueError) as e:
        parse_update_cidrs("198.51.100.0/24, not-an-ip")
    assert str(e.value) == "not-an-ip"
    with pytest.raises(ValueError):
        parse_update_cidrs("198.51.100.0/33")  # bad prefix length
