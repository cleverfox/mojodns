import hashlib

from mojodns.security import hash_password, needs_rehash, verify_password


def test_bcrypt_roundtrip():
    h = hash_password("s3cret")
    assert h.startswith("bcrypt$")
    assert verify_password("s3cret", h)
    assert not verify_password("wrong", h)
    assert not needs_rehash(h)


def test_legacy_sha1_scheme():
    # mojodns-perl: sha1_hex("--$salt--$password--")
    salt = "ab" * 20
    digest = hashlib.sha1(f"--{salt}--hunter2--".encode()).hexdigest()
    stored = f"legacysha1${salt}${digest}"
    assert verify_password("hunter2", stored)
    assert not verify_password("hunter3", stored)
    assert needs_rehash(stored)


def test_garbage_hash_rejected():
    assert not verify_password("x", "md5$whatever")
    assert not verify_password("x", "")
