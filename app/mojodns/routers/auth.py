from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from datetime import datetime, timezone

from ..config import settings
from ..db import User, get_db, log_history
from ..deps import current_user, needs_password_change
from ..security import DUMMY_PASSWORD_HASH, hash_password, needs_rehash, verify_password
from ..templating import flash, render
from .. import ratelimit

router = APIRouter()


@router.get("/")
def root(request: Request):
    if request.session.get("user_id"):
        return RedirectResponse("/zones", status_code=303)
    return RedirectResponse("/login", status_code=303)


@router.get("/login")
def login_form(request: Request):
    if request.session.get("user_id"):
        return RedirectResponse("/zones", status_code=303)
    return render(request, "login.html")


@router.post("/login")
def login(
    request: Request,
    user: str = Form(...),
    password: str = Form(..., alias="pass"),
    db: Session = Depends(get_db),
):
    # throttle brute-force by source IP (client.host is the real client once
    # FORWARDED_ALLOW_IPS scopes the trusted proxy)
    src = request.client.host if request.client else "unknown"
    ok, retry = ratelimit.allow(("login", src), settings().login_rate_limit)
    if not ok:
        flash(request, f"Too many login attempts — wait {retry}s", "error")
        return RedirectResponse("/login", status_code=303)

    account = db.execute(select(User).where(User.login == user)).scalar_one_or_none()
    # always run one bcrypt verify (dummy hash when the user is missing) so the
    # response time doesn't reveal whether the account exists
    valid = verify_password(password, account.password_hash if account else DUMMY_PASSWORD_HASH)
    if not account or not account.enabled or account.state != "active" or not valid:
        flash(request, "Login incorrect", "error")
        return RedirectResponse("/login", status_code=303)

    if needs_rehash(account.password_hash):
        account.password_hash = hash_password(password)

    account.last_login = datetime.now(timezone.utc)
    request.session["user_id"] = account.id
    log_history(db, account.id, "user", account.login, "Signed in")
    # a temporary / expired password sends them straight to the change page
    if needs_password_change(account):
        return RedirectResponse("/account/password", status_code=303)
    return RedirectResponse("/zones", status_code=303)


@router.post("/logout")
def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/login", status_code=303)


@router.get("/howto")
def howto(request: Request, user: User = Depends(current_user)):
    base = str(request.base_url).rstrip("/")
    return render(request, "howto.html", user=user, base=base,
                  master_host=settings().master_host)
