import asyncio
import logging
import secrets
import time
from contextlib import asynccontextmanager
from pathlib import Path

import anyio
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from sqlalchemy import select
from starlette.middleware.sessions import SessionMiddleware

from .config import settings
from .db import Base, SessionLocal, User, engine
from .pdns import canonical, pdns
from .routers import api, auth, ddns, pdns_compat, users, zones
from .security import hash_password
from .verify import check_zones, store_results, summarize

log = logging.getLogger("mojodns")
logging.basicConfig(level=logging.INFO)


def bootstrap() -> None:
    """Create the first admin and the catalog producer zone."""
    Base.metadata.create_all(bind=engine)  # additive only; init.sql covers fresh DBs
    with SessionLocal() as db:
        if not db.execute(select(User.id).limit(1)).first():
            password = settings().bootstrap_admin_password or secrets.token_urlsafe(12)
            db.add(User(login="admin", password_hash=hash_password(password), role="admin"))
            db.commit()
            if settings().bootstrap_admin_password:
                log.info("Bootstrap: created user 'admin' with password from BOOTSTRAP_ADMIN_PASSWORD")
            else:
                log.warning("Bootstrap: created user 'admin' with password: %s", password)

    for attempt in range(30):
        try:
            pdns.ensure_catalog_zone()
            log.info("Catalog zone %s present", settings().catalog_zone)
            if settings().tsig_key:
                for z in pdns.list_zones():
                    pdns.ensure_tsig_allow_axfr(z["name"])
                log.info("TSIG-ALLOW-AXFR=%s ensured on all zones", settings().tsig_key)
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
app.add_middleware(
    SessionMiddleware,
    secret_key=settings().session_secret,
    same_site="lax",
    https_only=False,
)

app.mount("/static", StaticFiles(directory=str(Path(__file__).parent / "static")), name="static")

app.include_router(auth.router)
app.include_router(zones.router)
app.include_router(users.router)
app.include_router(api.router)
app.include_router(pdns_compat.router)
app.include_router(ddns.router)
