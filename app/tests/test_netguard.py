from mojodns.netguard import is_public_ip


def test_public_addresses_allowed():
    for ip in ("1.1.1.1", "8.8.8.8", "9.9.9.9", "2606:4700:4700::1111"):
        assert is_public_ip(ip) is True


def test_loopback_blocked():
    assert not is_public_ip("127.0.0.1")
    assert not is_public_ip("::1")


def test_link_local_and_metadata_blocked():
    assert not is_public_ip("169.254.169.254")   # cloud metadata
    assert not is_public_ip("fe80::1")


def test_private_ranges_blocked():
    for ip in ("10.0.0.1", "172.16.5.5", "192.168.1.1", "fd00::1"):
        assert not is_public_ip(ip)


def test_reserved_unspecified_multicast_blocked():
    assert not is_public_ip("0.0.0.0")
    assert not is_public_ip("224.0.0.1")
    assert not is_public_ip("240.0.0.1")


def test_ipv4_mapped_ipv6_bypass_blocked():
    # ::ffff:127.0.0.1 must be unwrapped and judged on the embedded v4 address
    assert not is_public_ip("::ffff:127.0.0.1")
    assert not is_public_ip("::ffff:169.254.169.254")
    assert is_public_ip("::ffff:1.1.1.1")


def test_garbage_blocked():
    for bad in ("", "not-an-ip", "999.999.999.999", "1.1.1.1; rm -rf"):
        assert not is_public_ip(bad)
