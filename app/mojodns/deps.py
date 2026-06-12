from fastapi import Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from .db import User, ZoneAccess, get_db
from .pdns import canonical


def _redirect_login() -> HTTPException:
    return HTTPException(status_code=303, headers={"Location": "/login"})


def current_user(request: Request, db: Session = Depends(get_db)) -> User:
    uid = request.session.get("user_id")
    if not uid:
        raise _redirect_login()
    user = db.get(User, uid)
    if not user or user.state != "active":
        request.session.clear()
        raise _redirect_login()
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


def zone_guard(zone: str, user: User = Depends(current_user), db: Session = Depends(get_db)) -> str:
    """Path-param dependency: returns the canonical zone name or 404s."""
    czone = canonical(zone)
    if not can_access_zone(db, user, czone):
        raise HTTPException(status_code=404)
    return czone
