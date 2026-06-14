"""API-token hashing/lookup/expiry and the password-age policy."""
import types
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from mojodns.apitokens import (DEFAULT_INTERVAL, TOKEN_INTERVALS, interval_expiry,
                               lookup_token)
from mojodns.db import ApiToken, Base, User
from mojodns.deps import needs_password_change
from mojodns.security import hash_token


def test_hash_token_is_deterministic_sha256():
    assert hash_token("abc") == hash_token("abc")
    assert len(hash_token("abc")) == 64
    assert hash_token("abc") != hash_token("abd")


def test_default_interval_is_one_year():
    assert DEFAULT_INTERVAL == "1 year"
    exp = interval_expiry(DEFAULT_INTERVAL)
    assert 364 <= (exp - datetime.now(timezone.utc)).days <= 365


def test_unknown_interval_falls_back_to_default():
    assert interval_expiry("bogus").date() == interval_expiry(DEFAULT_INTERVAL).date()


@pytest.fixture
def db():
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    s = sessionmaker(bind=engine)()
    s.add(User(id=1, login="u", password_hash="x", role="owner", state="active", enabled=True))
    s.add(User(id=2, login="off", password_hash="x", role="owner", state="active", enabled=False))
    future = datetime.now(timezone.utc) + timedelta(days=30)
    past = datetime.now(timezone.utc) - timedelta(days=1)
    s.add(ApiToken(id=1, user_id=1, token_hash=hash_token("good"), name="t", expires_at=future))
    s.add(ApiToken(id=2, user_id=1, token_hash=hash_token("old"), name="t", expires_at=past))
    s.add(ApiToken(id=3, user_id=2, token_hash=hash_token("disabled-user"), name="t", expires_at=future))
    s.commit()
    yield s
    s.close()


def test_valid_token(db):
    user, err = lookup_token(db, "good")
    assert err is None and user.login == "u"


def test_unknown_token_invalid(db):
    assert lookup_token(db, "nope") == (None, "invalid")
    assert lookup_token(db, "") == (None, "invalid")


def test_expired_token(db):
    assert lookup_token(db, "old") == (None, "expired")


def test_token_of_disabled_user_invalid(db):
    assert lookup_token(db, "disabled-user") == (None, "invalid")


# -- password age policy ----------------------------------------------------

def test_must_change_flag_forces_change():
    u = types.SimpleNamespace(must_change_password=True, last_pwd_change=datetime.now(timezone.utc))
    assert needs_password_change(u) is True


def test_recent_password_ok():
    u = types.SimpleNamespace(must_change_password=False, last_pwd_change=datetime.now(timezone.utc))
    assert needs_password_change(u) is False


def test_old_password_expires():
    old = datetime.now(timezone.utc) - timedelta(days=400)   # > default 365
    u = types.SimpleNamespace(must_change_password=False, last_pwd_change=old)
    assert needs_password_change(u) is True


def test_null_pwd_change_forces_change():
    u = types.SimpleNamespace(must_change_password=False, last_pwd_change=None)
    assert needs_password_change(u) is True
