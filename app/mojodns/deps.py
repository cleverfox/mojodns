from datetime import datetime, timedelta, timezone

from fastapi import Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from .config import settings
from .db import User, ZoneAccess, get_db
from .pdns import canonical

# paths a must-change-password user may still reach (to actually change it / leave)
_PWCHANGE_EXEMPT = {"/account/password", "/logout"}


def _redirect(path: str) -> HTTPException:
    return HTTPException(status_code=303, headers={"Location": path})


def _redirect_login() -> HTTPException:
    return _redirect("/login")


def needs_password_change(user: User) -> bool:
    """True if the user must set a new password before doing anything else:
    a temporary (new / admin-reset) password, or one older than the max age."""
    if user.must_change_password:
        return True
    max_days = settings().password_max_age_days
    if max_days <= 0:
        return False
    if user.last_pwd_change is None:
        return True
    return datetime.now(timezone.utc) - user.last_pwd_change > timedelta(days=max_days)


def current_user(request: Request, db: Session = Depends(get_db)) -> User:
    uid = request.session.get("user_id")
    if not uid:
        raise _redirect_login()
    user = db.get(User, uid)
    if not user or not user.enabled or user.state != "active":
        request.session.clear()
        raise _redirect_login()
    if needs_password_change(user) and request.url.path not in _PWCHANGE_EXEMPT:
        raise _redirect("/account/password")
    return user


def require_admin(user: User = Depends(current_user)) -> User:
    if not user.is_admin:
        raise HTTPException(status_code=404)
    return user


def user_zones(db: Session, user: User) -> dict[str, bool]:
    """zone name -> is_owner for zones this user may manage."""
    rows = db.execute(select(ZoneAccess).where(ZoneAccess.user_id == user.id)).scalars()
    return {a.zone: a.is_owner for a in rows}


def can_access_zone(db: Session, user: User, zone: str) -> bool:
    if user.is_admin:
        return True
    return (
        db.execute(
            select(ZoneAccess.id).where(
                ZoneAccess.user_id == user.id, ZoneAccess.zone == canonical(zone)
            )
        ).first()
        is not None
    )


def is_zone_owner(db: Session, user: User, zone: str) -> bool:
    """True if the user owns the zone (or is an admin). Owning is required to
    manage the zone's access list."""
    if user.is_admin:
        return True
    return (
        db.execute(
            select(ZoneAccess.id).where(
                ZoneAccess.user_id == user.id, ZoneAccess.zone == canonical(zone),
                ZoneAccess.is_owner.is_(True),
            )
        ).first()
        is not None
    )


def zone_guard(zone: str, user: User = Depends(current_user), db: Session = Depends(get_db)) -> str:
    """Path-param dependency: returns the canonical zone name or 404s."""
    czone = canonical(zone)
    if not can_access_zone(db, user, czone):
        raise HTTPException(status_code=404)
    return czone
