import secrets
from pathlib import Path

from fastapi import Request
from fastapi.templating import Jinja2Templates

from .config import settings
from .dnsutil import RECORD_TYPES
from .idn import to_unicode

templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))

templates.env.filters["unicode_name"] = to_unicode
templates.env.filters["bare"] = lambda name: name.rstrip(".")
templates.env.globals["record_types"] = RECORD_TYPES
templates.env.globals["catalog_zone"] = lambda: settings().catalog_zone


def flash(request: Request, message: str, level: str = "ok") -> None:
    request.session.setdefault("flash", []).append({"message": message, "level": level})


def pop_flashes(request: Request) -> list[dict]:
    return request.session.pop("flash", [])


def csrf_token(request: Request) -> str:
    """Per-session CSRF token; minted lazily and stored in the session. The
    CSRF middleware compares submitted tokens against this value."""
    token = request.session.get("csrf")
    if not token:
        token = secrets.token_urlsafe(32)
        request.session["csrf"] = token
    return token


def render(request: Request, name: str, **ctx):
    ctx.setdefault("flashes", pop_flashes(request))
    ctx.setdefault("csrf_token", csrf_token(request))
    return templates.TemplateResponse(request, name, ctx)
