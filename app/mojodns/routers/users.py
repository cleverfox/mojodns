from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db import ApiToken, HistoryEntry, User, ZoneAccess, get_db, log_history
from ..deps import require_admin
from ..security import hash_password, make_token
from ..templating import flash, render

router = APIRouter(prefix="/users")


@router.get("")
def users_index(request: Request, admin: User = Depends(require_admin),
                db: Session = Depends(get_db)):
    users = db.execute(select(User).order_by(User.login)).scalars().all()
    counts: dict[int, int] = {}
    for za in db.execute(select(ZoneAccess)).scalars():
        counts[za.user_id] = counts.get(za.user_id, 0) + 1
    return render(request, "users.html", user=admin, users=users, zone_counts=counts)


@router.post("")
def user_create(
    request: Request,
    login: str = Form(...),
    email: str = Form(""),
    password: str = Form(...),
    role: str = Form("owner"),
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    login = login.strip()
    if db.execute(select(User.id).where(User.login == login)).first():
        flash(request, f"User {login} already exists", "error")
        return RedirectResponse("/users", status_code=303)
    user = User(
        login=login,
        email=email.strip() or None,
        password_hash=hash_password(password),
        role="admin" if role == "admin" else "owner",
        state="active",
    )
    db.add(user)
    db.flush()
    log_history(db, admin.id, "user", login, f"Create user {login} ({user.role})")
    flash(request, f"User {login} created")
    return RedirectResponse("/users", status_code=303)


def _load_user(db: Session, uid: int) -> User:
    user = db.get(User, uid)
    if not user:
        raise HTTPException(status_code=404)
    return user


@router.get("/{uid}")
def user_edit(request: Request, uid: int, admin: User = Depends(require_admin),
              db: Session = Depends(get_db)):
    target = _load_user(db, uid)
    grants = db.execute(select(ZoneAccess).where(ZoneAccess.user_id == uid)).scalars().all()
    tokens = db.execute(select(ApiToken).where(ApiToken.user_id == uid)).scalars().all()
    return render(request, "user_edit.html", user=admin, target=target,
                  owned=[g.zone for g in grants if g.is_owner],
                  granted=[g.zone for g in grants if not g.is_owner],
                  tokens=tokens)


@router.post("/{uid}")
def user_update(
    request: Request,
    uid: int,
    email: str = Form(""),
    role: str = Form("owner"),
    password: str = Form(""),
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    target = _load_user(db, uid)
    target.email = email.strip() or None
    target.role = "admin" if role == "admin" else "owner"
    log_history(db, admin.id, "user", target.login, "Update user profile")
    if password:
        target.password_hash = hash_password(password)
        log_history(db, admin.id, "user", target.login, "Update user password")
    flash(request, "User updated")
    return RedirectResponse(f"/users/{uid}", status_code=303)


@router.post("/{uid}/delete")
def user_delete(request: Request, uid: int, admin: User = Depends(require_admin),
                db: Session = Depends(get_db)):
    target = _load_user(db, uid)
    if target.id == admin.id:
        flash(request, "You cannot delete yourself", "error")
        return RedirectResponse(f"/users/{uid}", status_code=303)
    log_history(db, admin.id, "user", target.login, f"Delete user {target.login}")
    db.delete(target)
    flash(request, f"User {target.login} deleted")
    return RedirectResponse("/users", status_code=303)


@router.get("/{uid}/history")
def user_history(request: Request, uid: int, admin: User = Depends(require_admin),
                 db: Session = Depends(get_db)):
    target = _load_user(db, uid)
    entries = db.execute(
        select(HistoryEntry, User.login)
        .outerjoin(User, User.id == HistoryEntry.user_id)
        .where(
            (HistoryEntry.user_id == uid)
            | ((HistoryEntry.target_type == "user") & (HistoryEntry.target == target.login))
        )
        .order_by(HistoryEntry.created_at.desc())
        .limit(500)
    ).all()
    return render(request, "history.html", user=admin, title=f"History · {target.login}",
                  back=f"/users/{uid}", entries=entries)


@router.post("/{uid}/tokens")
def token_create(request: Request, uid: int, note: str = Form(""),
                 admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    target = _load_user(db, uid)
    db.add(ApiToken(user_id=uid, token=make_token(), note=note.strip() or None))
    log_history(db, admin.id, "user", target.login, "Create API token")
    return RedirectResponse(f"/users/{uid}", status_code=303)


@router.post("/{uid}/tokens/{tid}/delete")
def token_delete(request: Request, uid: int, tid: int,
                 admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    token = db.get(ApiToken, tid)
    if token and token.user_id == uid:
        db.delete(token)
        log_history(db, admin.id, "user", _load_user(db, uid).login, "Delete API token")
    return RedirectResponse(f"/users/{uid}", status_code=303)
