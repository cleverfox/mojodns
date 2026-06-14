"""CSRF middleware behaviour, exercised on a minimal Starlette app (no DB)."""
import pytest
from starlette.applications import Starlette
from starlette.middleware.sessions import SessionMiddleware
from starlette.responses import PlainTextResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from mojodns.csrf import CSRFMiddleware


def _seed(request):
    request.session["csrf"] = "tok123"
    return PlainTextResponse("seeded")


def _ok(request):
    return PlainTextResponse("ok")


@pytest.fixture
def client():
    routes = [
        Route("/seed", _seed),
        Route("/do", _ok, methods=["GET", "POST"]),
        Route("/login", _ok, methods=["POST"]),
        Route("/api/v1/x", _ok, methods=["POST"]),
    ]
    app = Starlette(routes=routes)
    # add CSRF first so it sits INNER to SessionMiddleware (needs scope session)
    app.add_middleware(CSRFMiddleware)
    app.add_middleware(SessionMiddleware, secret_key="test-secret", same_site="lax")
    c = TestClient(app)
    c.get("/seed")  # mint a session with csrf=tok123
    return c


def test_safe_get_allowed(client):
    assert client.get("/do").status_code == 200


def test_post_without_token_rejected(client):
    assert client.post("/do").status_code == 403


def test_post_with_header_token_ok(client):
    r = client.post("/do", headers={"X-CSRF-Token": "tok123"})
    assert r.status_code == 200


def test_post_with_wrong_header_rejected(client):
    assert client.post("/do", headers={"X-CSRF-Token": "nope"}).status_code == 403


def test_post_with_form_field_ok(client):
    r = client.post("/do", data={"csrf_token": "tok123", "other": "x"})
    assert r.status_code == 200


def test_login_exempt(client):
    assert client.post("/login").status_code == 200


def test_api_prefix_exempt(client):
    assert client.post("/api/v1/x").status_code == 200
