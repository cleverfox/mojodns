"""CSRF protection for cookie-authenticated (browser) requests.

A per-session token is minted in `templating.csrf_token` and surfaced to the
browser as a `<meta name="csrf-token">` tag. HTMX sends it back on every request
via the `X-CSRF-Token` header (a global `htmx:configRequest` hook); plain HTML
forms carry it in a hidden `csrf_token` field. This middleware enforces, on every
unsafe method, that the request presents the session's token.

Pure-ASGI (not BaseHTTPMiddleware) so it can buffer-and-replay the request body
without breaking downstream form parsing. Must be installed INNER to
SessionMiddleware so `scope["session"]` is populated when this runs.

Exemptions:
  - safe methods (GET/HEAD/OPTIONS/TRACE) — no state change;
  - `/api/v1/*` — machine APIs authenticated by token, not the session cookie;
  - `POST /login` — no session yet (and protected by SameSite=lax).
"""

import hmac

from starlette.responses import PlainTextResponse

SAFE_METHODS = {"GET", "HEAD", "OPTIONS", "TRACE"}
EXEMPT_PATHS = {"/login"}
EXEMPT_PREFIXES = ("/api/v1",)


class CSRFMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)

        method = scope["method"]
        path = scope["path"]
        if (method in SAFE_METHODS or path in EXEMPT_PATHS
                or any(path.startswith(p) for p in EXEMPT_PREFIXES)):
            return await self.app(scope, receive, send)

        expected = (scope.get("session") or {}).get("csrf")

        # 1) header path (HTMX) — no body read needed
        header_token = ""
        for k, v in scope["headers"]:
            if k == b"x-csrf-token":
                header_token = v.decode("latin-1")
                break
        if expected and header_token and hmac.compare_digest(header_token, expected):
            return await self.app(scope, receive, send)

        # 2) plain form: buffer the body, accept if the (high-entropy, secret)
        #    session token appears in it (the hidden csrf_token field), then
        #    replay the buffered body so the route still parses the form.
        body = b""
        while True:
            message = await receive()
            body += message.get("body", b"")
            if not message.get("more_body"):
                break

        if not (expected and expected.encode() in body):
            return await PlainTextResponse(
                "CSRF token missing or invalid", status_code=403)(scope, receive, send)

        sent = False

        async def replay():
            nonlocal sent
            if not sent:
                sent = True
                return {"type": "http.request", "body": body, "more_body": False}
            return {"type": "http.disconnect"}

        await self.app(scope, replay, send)
