"""Admin management of SOCKS5 check proxies (+ the 'direct' pseudo-proxy).

Visibility rules (used by the check panel):
  - disabled proxies are shown to nobody;
  - enabled + public_available → everybody;
  - enabled + not public_available → admins only.

The proxy password is stored (needed to authenticate to the proxy) but is
never rendered back; the edit form treats it as change-only (blank = keep).
"""

import re

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db import Proxy, User, get_db, log_history
from ..deps import require_admin
from ..httpcheck import ProxySpec
from ..templating import flash, render

router = APIRouter(prefix="/proxies")

NAME_RE = re.compile(r"[a-z0-9]([a-z0-9-]*[a-z0-9])?$")


def visible_proxies(db: Session, user: User) -> list[Proxy]:
    """Proxies this user may pick as a check location (direct first, then name)."""
    q = select(Proxy).where(Proxy.enabled.is_(True))
    if not user.is_admin:
        q = q.where(Proxy.public_available.is_(True))
    rows = db.execute(q).scalars().all()
    return sorted(rows, key=lambda p: (not p.is_direct, p.name))


def proxy_spec(p: Proxy) -> ProxySpec | None:
    """Connection spec for httpcheck; None for the direct pseudo-proxy."""
    if p.is_direct or not p.host:
        return None
    return ProxySpec(host=p.host, port=p.port or 1080,
                     username=p.username or None, password=p.password or None)


def _flag(v: str) -> bool:
    return v.strip().lower() in ("1", "true", "on", "yes")


@router.get("")
def proxies_index(request: Request, admin: User = Depends(require_admin),
                  db: Session = Depends(get_db)):
    proxies = db.execute(select(Proxy)).scalars().all()
    proxies.sort(key=lambda p: (not p.is_direct, p.name))
    return render(request, "proxies.html", user=admin, proxies=proxies)


@router.post("")
def proxy_create(request: Request, name: str = Form(...), host: str = Form(""),
                 port: str = Form(""), username: str = Form(""), password: str = Form(""),
                 enabled: str = Form(""), public_available: str = Form(""),
                 admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    name = name.strip().lower()
    if not NAME_RE.fullmatch(name):
        flash(request, f"'{name}' is not a valid proxy name (a-z, 0-9, -)", "error")
        return RedirectResponse("/proxies", status_code=303)
    if name == "direct" or db.execute(select(Proxy.id).where(Proxy.name == name)).first():
        flash(request, f"A proxy named '{name}' already exists", "error")
        return RedirectResponse("/proxies", status_code=303)
    if not host.strip():
        flash(request, "SOCKS5 host is required", "error")
        return RedirectResponse("/proxies", status_code=303)
    try:
        portn = int(port)
        if not 1 <= portn <= 65535:
            raise ValueError
    except ValueError:
        flash(request, "Port must be 1–65535", "error")
        return RedirectResponse("/proxies", status_code=303)
    db.add(Proxy(name=name, is_direct=False, host=host.strip(), port=portn,
                 username=username.strip() or None, password=password or None,
                 enabled=_flag(enabled), public_available=_flag(public_available)))
    log_history(db, admin.id, "proxy", name, "Create SOCKS5 proxy")
    flash(request, f"Proxy {name} created")
    return RedirectResponse("/proxies", status_code=303)


@router.post("/{pid}")
def proxy_update(request: Request, pid: int, host: str = Form(""), port: str = Form(""),
                 username: str = Form(""), password: str = Form(""),
                 enabled: str = Form(""), public_available: str = Form(""),
                 admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    p = db.get(Proxy, pid)
    if not p:
        raise HTTPException(status_code=404)
    p.enabled = _flag(enabled)
    p.public_available = _flag(public_available)
    if not p.is_direct:
        if host.strip():
            p.host = host.strip()
        if port.strip():
            try:
                portn = int(port)
                if not 1 <= portn <= 65535:
                    raise ValueError
                p.port = portn
            except ValueError:
                flash(request, "Port must be 1–65535", "error")
                return RedirectResponse(f"/proxies/{pid}", status_code=303)
        p.username = username.strip() or None
        if password:                      # change-only: blank leaves it untouched
            p.password = password
    log_history(db, admin.id, "proxy", p.name, "Update proxy")
    flash(request, f"Proxy {p.name} updated")
    return RedirectResponse(f"/proxies/{pid}", status_code=303)


@router.get("/{pid}")
def proxy_edit(request: Request, pid: int, admin: User = Depends(require_admin),
               db: Session = Depends(get_db)):
    p = db.get(Proxy, pid)
    if not p:
        raise HTTPException(status_code=404)
    return render(request, "proxy_edit.html", user=admin, proxy=p)


@router.post("/{pid}/delete")
def proxy_delete(request: Request, pid: int, admin: User = Depends(require_admin),
                 db: Session = Depends(get_db)):
    p = db.get(Proxy, pid)
    if not p:
        raise HTTPException(status_code=404)
    if p.is_direct:
        flash(request, "The 'direct' proxy cannot be deleted (disable it instead)", "error")
        return RedirectResponse("/proxies", status_code=303)
    name = p.name
    db.delete(p)
    log_history(db, admin.id, "proxy", name, "Delete proxy")
    flash(request, f"Proxy {name} deleted")
    return RedirectResponse("/proxies", status_code=303)
