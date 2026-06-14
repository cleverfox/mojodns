import asyncio
import logging
import secrets
import time
from contextlib import asynccontextmanager
from pathlib import Path

import anyio
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from sqlalchemy import select, text
from starlette.middleware.sessions import SessionMiddleware

from .config import settings
from .csrf import CSRFMiddleware
from .db import Base, Proxy, SessionLocal, User, engine
from .pdns import canonical, is_custom_zone, pdns
from .routers import account, api, auth, checks, ddns, pdns_compat, proxies, users, zones
from .security import hash_password, hash_token
from .verify import check_zones, store_results, summarize

log = logging.getLogger("mojodns")
logging.basicConfig(level=logging.INFO)


def _migrate() -> None:
    """Lightweight additive migrations for existing DBs — create_all only makes
    missing *tables*, not new columns. Each statement is idempotent."""
    with engine.begin() as conn:
        conn.execute(text(
            "ALTER TABLE app_users ADD COLUMN IF NOT EXISTS check_rate_limit integer"))
        # account lifecycle columns
        conn.execute(text(
            "ALTER TABLE app_users ADD COLUMN IF NOT EXISTS enabled boolean NOT NULL DEFAULT true"))
        conn.execute(text(
            "ALTER TABLE app_users ADD COLUMN IF NOT EXISTS must_change_password boolean NOT NULL DEFAULT false"))
        conn.execute(text("ALTER TABLE app_users ADD COLUMN IF NOT EXISTS last_login timestamptz"))
        conn.execute(text("ALTER TABLE app_users ADD COLUMN IF NOT EXISTS last_pwd_change timestamptz"))
        # existing users: start the password-age clock at upgrade time so we
        # don't force everyone to rotate immediately
        conn.execute(text(
            "UPDATE app_users SET last_pwd_change = now() WHERE last_pwd_change IS NULL"))
        _migrate_api_tokens(conn)


def _migrate_api_tokens(conn) -> None:
    """Hash-at-rest migration for api_tokens: add token_hash + name, hash any
    existing plaintext tokens, then drop the plaintext column."""
    conn.execute(text("ALTER TABLE api_tokens ADD COLUMN IF NOT EXISTS token_hash varchar(64)"))
    conn.execute(text("ALTER TABLE api_tokens ADD COLUMN IF NOT EXISTS name varchar(255)"))
    cols = set(conn.execute(text(
        "SELECT column_name FROM information_schema.columns WHERE table_name = 'api_tokens'"
    )).scalars())
    if "token" in cols:  # legacy plaintext column present → migrate then drop it
        for row in conn.execute(text(
                "SELECT id, token, note FROM api_tokens WHERE token_hash IS NULL")).all():
            conn.execute(
                text("UPDATE api_tokens SET token_hash = :h, name = COALESCE(name, :n) WHERE id = :i"),
                {"h": hash_token(row.token), "n": (row.note or "imported")[:255], "i": row.id})
        conn.execute(text("ALTER TABLE api_tokens DROP COLUMN token"))
    conn.execute(text("UPDATE api_tokens SET name = COALESCE(name, 'token')"))
    conn.execute(text(
        "CREATE UNIQUE INDEX IF NOT EXISTS api_tokens_token_hash_uq ON api_tokens(token_hash)"))


def bootstrap() -> None:
    """Create the first admin and the catalog producer zone."""
    Base.metadata.create_all(bind=engine)  # additive only; init.sql covers fresh DBs
    _migrate()
    with SessionLocal() as db:
        if not db.execute(select(User.id).limit(1)).first():
            password = settings().bootstrap_admin_password or secrets.token_urlsafe(12)
            db.add(User(login="admin", password_hash=hash_password(password), role="admin"))
            db.commit()
            if settings().bootstrap_admin_password:
                log.info("Bootstrap: created user 'admin' with password from BOOTSTRAP_ADMIN_PASSWORD")
            else:
                log.warning("Bootstrap: created user 'admin' with password: %s", password)
        # ensure the 'direct' pseudo-proxy exists (enabled + public, i.e. the
        # current "check from the panel" behaviour available to everyone)
        if not db.execute(select(Proxy.id).where(Proxy.is_direct.is_(True))).first():
            db.add(Proxy(name="direct", is_direct=True, enabled=True, public_available=True))
            db.commit()
            log.info("Bootstrap: created the 'direct' proxy")

    for attempt in range(30):
        try:
            pdns.ensure_catalog_zone()
            log.info("Catalog zone %s present", settings().catalog_zone)
            if settings().tsig_key_names:
                cat = settings().catalog_zone
                n = 0
                for z in pdns.list_zones():
                    # leave custom zones alone — they carry their own per-zone
                    # keys that the global stamp would otherwise clobber
                    if is_custom_zone(z, cat):
                        continue
                    pdns.ensure_tsig_allow_axfr(z["name"])
                    n += 1
                log.info("TSIG-ALLOW-AXFR keys %s ensured on %d catalog/producer zones",
                         ",".join(settings().tsig_key_names), n)
            return
        except Exception as e:  # pdns may still be starting
            log.info("Waiting for PowerDNS API (%s)", e)
            time.sleep(2)
    log.error("Could not reach the PowerDNS API; catalog zone not verified")


def verify_all_zones() -> None:
    catalog = canonical(settings().catalog_zone)
    names = [z["name"] for z in pdns.list_zones()
             if z["name"] != catalog and z.get("kind") != "Producer"]
    results = check_zones(names)
    with SessionLocal() as db:
        store_results(db, results)
        db.commit()
    log.info("Periodic NS verification of %d zones: %s", len(names), summarize(results))


async def periodic_verify() -> None:
    hours = settings().verify_interval_hours
    if not hours:
        return
    while True:
        await asyncio.sleep(hours * 3600)
        try:
            await anyio.to_thread.run_sync(verify_all_zones)
        except Exception as e:
            log.warning("Periodic NS verification failed: %s", e)


@asynccontextmanager
async def lifespan(app: FastAPI):
    await anyio.to_thread.run_sync(bootstrap)
    task = asyncio.create_task(periodic_verify())
    yield
    task.cancel()


app = FastAPI(title="mojodns", lifespan=lifespan)
# Middleware order: the LAST added is outermost. Add CSRF first so it sits
# INNER to SessionMiddleware (it needs scope["session"] populated).
app.add_middleware(CSRFMiddleware)
app.add_middleware(
    SessionMiddleware,
    secret_key=settings().session_secret,
    same_site="lax",
    https_only=settings().cookie_secure,
)

app.mount("/static", StaticFiles(directory=str(Path(__file__).parent / "static")), name="static")

app.include_router(auth.router)
app.include_router(zones.router)
app.include_router(users.router)
app.include_router(api.router)
app.include_router(pdns_compat.router)
app.include_router(ddns.router)
app.include_router(checks.router)
app.include_router(proxies.router)
app.include_router(account.router)
