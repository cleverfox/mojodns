"""Proxy visibility rules and connection-spec mapping."""
import types

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from mojodns.db import Base, Proxy
from mojodns.routers.proxies import proxy_spec, visible_proxies


@pytest.fixture
def db():
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    # explicit ids: sqlite only autoincrements INTEGER PKs, not BIGINT (prod is BIGSERIAL)
    session.add_all([
        Proxy(id=1, name="direct", is_direct=True, enabled=True, public_available=True),
        Proxy(id=2, name="pub", host="p.example", port=1080, enabled=True, public_available=True),
        Proxy(id=3, name="priv", host="q.example", port=1080, enabled=True, public_available=False),
        Proxy(id=4, name="off", host="r.example", port=1080, enabled=False, public_available=True),
    ])
    session.commit()
    yield session
    session.close()


ADMIN = types.SimpleNamespace(is_admin=True)
USER = types.SimpleNamespace(is_admin=False)


def test_admin_sees_all_enabled(db):
    names = [p.name for p in visible_proxies(db, ADMIN)]
    assert names == ["direct", "priv", "pub"]   # direct first, then by name


def test_non_admin_sees_only_public_enabled(db):
    names = [p.name for p in visible_proxies(db, USER)]
    assert names == ["direct", "pub"]            # priv hidden, off hidden


def test_disabled_hidden_from_everyone(db):
    assert "off" not in [p.name for p in visible_proxies(db, ADMIN)]
    assert "off" not in [p.name for p in visible_proxies(db, USER)]


def test_proxy_spec_direct_is_none(db):
    direct = db.query(Proxy).filter_by(name="direct").one()
    assert proxy_spec(direct) is None


def test_proxy_spec_socks5(db):
    pub = db.query(Proxy).filter_by(name="pub").one()
    spec = proxy_spec(pub)
    assert (spec.host, spec.port) == ("p.example", 1080)
