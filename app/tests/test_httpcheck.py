import datetime as dt

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID

from mojodns import httpcheck


def _make_cert(cn="www.example.com", sans=("www.example.com", "example.com"),
               not_before=None, not_after=None, issuer_cn=None):
    now = dt.datetime.now(dt.timezone.utc)
    not_before = not_before or now - dt.timedelta(days=1)
    not_after = not_after or now + dt.timedelta(days=30)
    key = ec.generate_private_key(ec.SECP256R1())
    subj = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    iss = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_cn or cn)])
    b = (x509.CertificateBuilder().subject_name(subj).issuer_name(iss)
         .public_key(key.public_key()).serial_number(x509.random_serial_number())
         .not_valid_before(not_before).not_valid_after(not_after))
    if sans:
        b = b.add_extension(x509.SubjectAlternativeName([x509.DNSName(s) for s in sans]), critical=False)
    cert = b.sign(key, hashes.SHA256())
    return cert.public_bytes(Encoding.DER)


def test_cert_analysis_valid():
    der = _make_cert()
    c = httpcheck._analyze_cert(der, "www.example.com")
    assert c["self_signed"] is True            # CN==issuer in this test cert
    assert c["hostname_match"] is True
    assert c["expired"] is False and c["not_yet_valid"] is False
    assert c["days_left"] > 0
    assert "example.com" in c["sans"]


def test_cert_analysis_expired():
    now = dt.datetime.now(dt.timezone.utc)
    der = _make_cert(not_before=now - dt.timedelta(days=400),
                     not_after=now - dt.timedelta(days=5))
    c = httpcheck._analyze_cert(der, "www.example.com")
    assert c["expired"] is True
    assert c["days_left"] < 0


def test_cert_hostname_mismatch_and_wildcard():
    der = _make_cert(cn="*.example.com", sans=("*.example.com",))
    c = httpcheck._analyze_cert(der, "api.example.com")
    assert c["hostname_match"] is True          # wildcard covers api.example.com
    c2 = httpcheck._analyze_cert(der, "other.org")
    assert c2["hostname_match"] is False


def test_host_matches_helper():
    assert httpcheck._host_matches("www.example.com", ["www.example.com"])
    assert httpcheck._host_matches("a.example.com", ["*.example.com"])
    assert not httpcheck._host_matches("example.com", ["*.example.com"])  # wildcard is one label
    assert not httpcheck._host_matches("evil.com", ["www.example.com"])


def test_family_detection():
    import socket
    assert httpcheck._family("1.2.3.4") == socket.AF_INET
    assert httpcheck._family("2001:db8::1") == socket.AF_INET6


def test_tcp_localhost_blocked_by_guard():
    # the SSRF guard rejects non-public targets before any socket is opened
    r = httpcheck.check_tcp("127.0.0.1", 59999)
    assert r["status"] == "blocked"


def test_tcp_private_and_metadata_blocked():
    for ip in ("169.254.169.254", "10.0.0.1", "192.168.1.1", "::1"):
        assert httpcheck.check_tcp(ip, 80)["status"] == "blocked"
        assert httpcheck.check_http(ip, "example.com")["status"] == "blocked"
        assert httpcheck.check_https(ip, "example.com")["status"] == "blocked"
