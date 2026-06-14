"""Self-service account page: change your own password and manage your own
API tokens (create with a name + expiry, secret shown once, revoke)."""

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..apitokens import DEFAULT_INTERVAL, TOKEN_INTERVALS, interval_expiry
from ..db import ApiToken, User, get_db, log_history
from ..deps import current_user, needs_password_change
from ..security import hash_password, hash_token, make_token, verify_password
from ..templating import flash, render

router = APIRouter(prefix="/account")


def _my_tokens(db: Session, user: User) -> list[ApiToken]:
    return db.execute(
        select(ApiToken).where(ApiToken.user_id == user.id).order_by(ApiToken.created_at.desc())
    ).scalars().all()


@router.get("")
def account(request: Request, user: User = Depends(current_user), db: Session = Depends(get_db),
            new_token: str | None = None):
    return render(request, "account.html", user=user, tokens=_my_tokens(db, user),
                  intervals=list(TOKEN_INTERVALS), default_interval=DEFAULT_INTERVAL,
                  now=datetime.now(timezone.utc), new_token=new_token)


# -- forced / voluntary password change ------------------------------------

@router.get("/password")
def password_form(request: Request, user: User = Depends(current_user)):
    return render(request, "password.html", user=user,
                  forced=needs_password_change(user))


@router.post("/password")
def password_change(request: Request, current: str = Form(...), new: str = Form(...),
                    confirm: str = Form(...), user: User = Depends(current_user),
                    db: Session = Depends(get_db)):
    forced = needs_password_change(user)
    if not verify_password(current, user.password_hash):
        flash(request, "Current password is incorrect", "error")
        return RedirectResponse("/account/password", status_code=303)
    if len(new) < 8:
        flash(request, "New password must be at least 8 characters", "error")
        return RedirectResponse("/account/password", status_code=303)
    if new != confirm:
        flash(request, "New password and confirmation do not match", "error")
        return RedirectResponse("/account/password", status_code=303)
    user.password_hash = hash_password(new)
    user.must_change_password = False
    user.last_pwd_change = datetime.now(timezone.utc)
    log_history(db, user.id, "user", user.login, "Changed own password")
    flash(request, "Password changed")
    return RedirectResponse("/zones" if forced else "/account", status_code=303)


# -- self-service API tokens -----------------------------------------------

@router.post("/tokens")
def token_create(request: Request, name: str = Form(...),
                 interval: str = Form(DEFAULT_INTERVAL),
                 user: User = Depends(current_user), db: Session = Depends(get_db)):
    name = name.strip()
    if not name:
        flash(request, "Give the token a name", "error")
        return RedirectResponse("/account", status_code=303)
    if interval not in TOKEN_INTERVALS:
        interval = DEFAULT_INTERVAL
    secret = make_token()
    db.add(ApiToken(user_id=user.id, token_hash=hash_token(secret), name=name[:255],
                    expires_at=interval_expiry(interval)))
    log_history(db, user.id, "user", user.login, f"Create API token '{name}' ({interval})")
    flash(request, f"Token '{name}' created — copy it now, it won't be shown again")
    # render directly (no redirect) so the one-time secret is shown exactly once
    return render(request, "account.html", user=user, tokens=_my_tokens(db, user),
                  intervals=list(TOKEN_INTERVALS), default_interval=DEFAULT_INTERVAL,
                  now=datetime.now(timezone.utc), new_token=secret)


@router.post("/tokens/{tid}/delete")
def token_delete(request: Request, tid: int, user: User = Depends(current_user),
                 db: Session = Depends(get_db)):
    row = db.get(ApiToken, tid)
    if not row or row.user_id != user.id:   # only your own tokens
        raise HTTPException(status_code=404)
    name = row.name
    db.delete(row)
    log_history(db, user.id, "user", user.login, f"Revoke API token '{name}'")
    flash(request, f"Token '{name}' revoked")
    return RedirectResponse("/account", status_code=303)
