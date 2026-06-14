from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..config import settings
from ..db import ApiToken, User, get_db, log_history
from ..deps import current_user
from ..security import hash_password, needs_rehash, verify_password
from ..templating import flash, render

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
    account = db.execute(select(User).where(User.login == user)).scalar_one_or_none()
    if not account or account.state != "active" or not verify_password(password, account.password_hash):
        flash(request, "Login incorrect", "error")
        return RedirectResponse("/login", status_code=303)

    if needs_rehash(account.password_hash):
        account.password_hash = hash_password(password)

    request.session["user_id"] = account.id
    log_history(db, account.id, "user", account.login, "Signed in")
    return RedirectResponse("/zones", status_code=303)


@router.post("/logout")
def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/login", status_code=303)


@router.get("/howto")
def howto(request: Request, user: User = Depends(current_user),
          db: Session = Depends(get_db)):
    tokens = db.execute(select(ApiToken).where(ApiToken.user_id == user.id)).scalars().all()
    base = str(request.base_url).rstrip("/")
    return render(request, "howto.html", user=user, tokens=tokens, base=base,
                  master_host=settings().master_host)
