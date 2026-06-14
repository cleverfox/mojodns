"""Token-authenticated JSON API (successor of the old /api endpoint)."""

from fastapi import APIRouter, Depends, Header, HTTPException, Query
from sqlalchemy.orm import Session

from ..apitokens import lookup_token
from ..db import User, get_db
from ..deps import user_zones
from ..idn import to_unicode

router = APIRouter(prefix="/api/v1")


def token_user(x_api_key: str | None = Header(None, alias="X-API-Key"),
               token: str | None = Query(None), db: Session = Depends(get_db)) -> User:
    # Prefer the X-API-Key header; the ?token= query form is kept for backward
    # compatibility but leaks into proxy logs / Referer, so it's discouraged.
    user, err = lookup_token(db, x_api_key or token or "")
    if err == "expired":
        raise HTTPException(status_code=401, detail="token expired")
    if err:
        raise HTTPException(status_code=401, detail="invalid token")
    return user


@router.get("/zones")
def zones(user: User = Depends(token_user), db: Session = Depends(get_db)):
    access = user_zones(db, user)
    return {
        "zones": [
            {"name": z, "display": to_unicode(z.rstrip(".")), "owner": is_owner}
            for z, is_owner in sorted(access.items())
        ]
    }
