"""API-token helpers: creation intervals and authenticated lookup.

Tokens are stored hashed (see security.hash_token); we never compare plaintext.
Lookup distinguishes an unknown token ("invalid") from a known-but-expired one
("expired") so the API can return a clear "token expired" error.
"""

from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from .db import ApiToken, User
from .security import hash_token

# offered expiry intervals (label -> days); default = 1 year
TOKEN_INTERVALS: dict[str, int] = {
    "1 day": 1,
    "1 week": 7,
    "1 month": 30,
    "1 year": 365,
    "2 years": 730,
    "3 years": 1095,
    "5 years": 1825,
}
DEFAULT_INTERVAL = "1 year"


def interval_expiry(label: str) -> datetime:
    """Absolute expiry for a chosen interval label (falls back to the default)."""
    days = TOKEN_INTERVALS.get(label, TOKEN_INTERVALS[DEFAULT_INTERVAL])
    return datetime.now(timezone.utc) + timedelta(days=days)


def lookup_token(db: Session, key: str) -> tuple[User | None, str | None]:
    """Resolve a presented token to its (active, enabled) owner.

    Returns (user, None) on success, else (None, "expired") or (None, "invalid").
    """
    if not key:
        return None, "invalid"
    row = db.execute(
        select(ApiToken).where(ApiToken.token_hash == hash_token(key))
    ).scalar_one_or_none()
    if not row:
        return None, "invalid"
    exp = row.expires_at
    if exp is not None and exp.tzinfo is None:   # be robust to naive timestamps
        exp = exp.replace(tzinfo=timezone.utc)
    if exp and exp < datetime.now(timezone.utc):
        return None, "expired"
    user = db.get(User, row.user_id)
    if not user or not user.enabled or user.state != "active":
        return None, "invalid"
    return user, None
