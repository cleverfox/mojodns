import re
from collections import defaultdict

from fastapi import APIRouter, Depends, File, Form, Request, UploadFile
from fastapi.responses import PlainTextResponse, RedirectResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..config import settings
from ..db import HistoryEntry, User, ZoneAccess, ZoneCheck, get_db, log_history
from ..deps import current_user, is_zone_owner, require_admin, user_zones, zone_guard
from ..dnsutil import Soa, build_content, dotted, email_to_rname, flatten_rrsets, quote_txt, split_prio
from ..spf import is_spf, parse_spf
from ..idn import to_ascii, to_unicode
from ..pdns import PdnsError, canonical, is_custom_zone, parse_update_cidrs, pdns
from ..axfr import AxfrError, ZoneParseError, axfr_text, parse_zone_text
from ..slaves import apex_ns, check_delegation, check_slaves, summarize as slave_summary
from ..notifier import notify_zone, parse_targets
from ..templating import flash, render
from .. import ratelimit
from ..verify import check_zone, check_zones, load_checks, store_results, summarize

router = APIRouter()


def rel_name(name: str, zone: str) -> str:
    """FQDN -> display name relative to the zone ('@' for the apex)."""
    bare, zbare = name.rstrip("."), zone.rstrip(".")
    if bare == zbare:
        return "@"
    if bare.endswith("." + zbare):
        bare = bare[: -len(zbare) - 1]
    return to_unicode(bare)


def fqdn(host: str, zone: str) -> str:
    host = host.strip()
    if host in ("@", ""):
        return canonical(zone)
    return canonical(to_ascii(host) + "." + zone.rstrip("."))


def _zone_rows(db: Session, user: User) -> list[dict]:
    """Zones visible to the user, merged with ownership info."""
    access = db.execute(select(ZoneAccess, User.login).join(User, User.id == ZoneAccess.user_id)).all()
    owners: dict[str, str] = {}
    editors: dict[str, list[str]] = defaultdict(list)
    mine: dict[str, bool] = {}
    for za, login in access:
        if za.is_owner:
            owners[za.zone] = login
        else:
            editors[za.zone].append(login)
        if za.user_id == user.id:
            mine[za.zone] = True

    checks = load_checks(db)
    rows = []
    catalog = canonical(settings().catalog_zone)
    for z in pdns.list_zones():
        if z["name"] == catalog or z.get("kind") == "Producer":
            continue
        if not user.is_admin and z["name"] not in mine:
            continue
        rows.append(
            {
                "name": z["name"],
                "display": to_unicode(z["name"].rstrip(".")),
                "serial": z.get("serial"),
                "kind": z.get("kind"),
                "owner": owners.get(z["name"], "—"),
                "editors": editors.get(z["name"], []),
                "check": checks.get(z["name"]),
                "custom": is_custom_zone(z, settings().catalog_zone),
            }
        )
    rows.sort(key=lambda r: r["display"])
    return rows


def _valid_zone_name(zone: str) -> bool:
    return re.fullmatch(r"(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.)+", zone) is not None


@router.get("/zones")
def dashboard(request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    zones = _zone_rows(db, user)
    return render(request, "dashboard.html", user=user, zones=zones, defaults=settings())


@router.post("/zones")
def zone_create(
    request: Request,
    name: str = Form(...),
    soa_ns: str = Form(...),
    soa_mail: str = Form(...),
    refresh: int = Form(10800),
    retry: int = Form(3600),
    expire: int = Form(604800),
    minimum: int = Form(3600),
    nameservers: str = Form(""),
    custom: bool = Form(False),
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    s = settings()
    zone = canonical(to_ascii(name))
    if not _valid_zone_name(zone):
        flash(request, f"'{name}' is not a valid zone name", "error")
        return RedirectResponse("/zones", status_code=303)
    soa = Soa(
        mname=dotted(soa_ns),
        rname=email_to_rname(soa_mail),
        serial=1,  # pdns rewrites it via SOA-EDIT-API on creation
        refresh=refresh,
        retry=retry,
        expire=expire,
        minimum=minimum,
    )
    ns_list = [dotted(n.strip()) for n in nameservers.split(",") if n.strip()] or s.default_ns_list
    rrsets = [
        {"name": zone, "type": "SOA", "ttl": 86400, "changetype": "REPLACE",
         "records": [{"content": soa.content(), "disabled": False}]},
        {"name": zone, "type": "NS", "ttl": 86400, "changetype": "REPLACE",
         "records": [{"content": n, "disabled": False} for n in ns_list]},
    ]
    try:
        if custom:
            # custom DNS: not a catalog member; only the master's primary key
            # is allowed (panel access) until the user adds per-zone keys
            pdns.create_zone(zone, kind="Master", catalog=None, rrsets=rrsets)
            pdns.set_zone_tsig_keys(zone, [s.tsig_key] if s.tsig_key else [])
        else:
            pdns.create_zone(zone, kind="Master", catalog=s.catalog_zone, rrsets=rrsets)
            pdns.ensure_tsig_allow_axfr(zone)
    except PdnsError as e:
        flash(request, str(e), "error")
        return RedirectResponse("/zones", status_code=303)

    db.add(ZoneAccess(zone=zone, user_id=user.id, is_owner=True))
    log_history(db, user.id, "zone", zone,
                f"Create zone {zone}" + (" (custom DNS)" if custom else ""))
    if custom:
        flash(request, f"Zone {to_unicode(zone)} created in custom DNS mode — "
                       "add a transfer key below for your secondaries")
    else:
        flash(request, f"Zone {to_unicode(zone)} created")
    return RedirectResponse(f"/zones/{zone.rstrip('.')}", status_code=303)


def _mark_ns(records: list[dict], zone: str, check) -> None:
    """Annotate apex NS rows with match/miss against the last verification."""
    if not check or check.status == "error":
        return
    resolved = set((check.resolved_ns or "").split())
    for r in records:
        if r["type"] == "NS" and canonical(r["name"]) == zone:
            r["ns_mark"] = "match" if r["content"] in resolved else "miss"


@router.post("/zones/import")
async def zone_import(
    request: Request,
    name: str = Form(""),
    text: str = Form(""),
    file: UploadFile | None = File(None),
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    if file and file.filename:
        try:
            text = (await file.read()).decode()
        except UnicodeDecodeError:
            flash(request, "Uploaded file is not a text zone file", "error")
            return RedirectResponse("/zones", status_code=303)
    if not text.strip():
        flash(request, "Paste zone text or choose a file to import", "error")
        return RedirectResponse("/zones", status_code=303)

    try:
        zone, rrsets = parse_zone_text(text, to_ascii(name) if name.strip() else None)
    except ZoneParseError as e:
        flash(request, str(e), "error")
        return RedirectResponse("/zones", status_code=303)

    zone = canonical(zone)
    if not _valid_zone_name(zone):
        flash(request, f"'{zone}' is not a valid zone name", "error")
        return RedirectResponse("/zones", status_code=303)

    try:
        pdns.create_zone(zone, kind="Master", catalog=settings().catalog_zone, rrsets=rrsets)
        pdns.ensure_tsig_allow_axfr(zone)
    except PdnsError as e:
        flash(request, str(e), "error")
        return RedirectResponse("/zones", status_code=303)

    db.add(ZoneAccess(zone=zone, user_id=user.id, is_owner=True))
    nrec = sum(len(rr["records"]) for rr in rrsets)
    log_history(db, user.id, "zone", zone, f"Import zone {zone} ({nrec} records)")
    flash(request, f"Zone {to_unicode(zone)} imported ({nrec} records)")
    return RedirectResponse(f"/zones/{zone.rstrip('.')}", status_code=303)


@router.post("/zones/verify")
def zones_verify(request: Request, user: User = Depends(current_user),
                 db: Session = Depends(get_db)):
    if user.is_admin:
        catalog = canonical(settings().catalog_zone)
        names = [z["name"] for z in pdns.list_zones()
                 if z["name"] != catalog and z.get("kind") != "Producer"]
    else:
        existing = {z["name"] for z in pdns.list_zones()}
        names = [z for z in user_zones(db, user) if z in existing]
    results = check_zones(names)
    store_results(db, results)
    if user.is_admin:  # prune results of zones that no longer exist
        for zc in db.execute(select(ZoneCheck).where(ZoneCheck.zone.notin_(names))).scalars():
            db.delete(zc)
    log_history(db, user.id, "zone", None, f"Verify {len(names)} zones: {summarize(results)}")
    flash(request, f"Verified {len(names)} zones: {summarize(results)}")
    return RedirectResponse("/zones", status_code=303)


@router.post("/zones/{zone}/verify")
def zone_verify(request: Request, zone: str = Depends(zone_guard),
                user: User = Depends(current_user), db: Session = Depends(get_db)):
    result = check_zone(zone)
    store_results(db, [result])
    log_history(db, user.id, "zone", zone, f"Verify NS: {result.status}"
                + (f" ({result.detail})" if result.detail else ""))
    flash(request, f"NS verification: {result.status}"
          + (f" — {result.detail}" if result.detail else ""),
          "ok" if result.status == "ok" else "error")
    return RedirectResponse(f"/zones/{zone.rstrip('.')}", status_code=303)


@router.get("/zones/{zone}")
def zone_view(request: Request, zone: str = Depends(zone_guard),
              user: User = Depends(current_user), db: Session = Depends(get_db)):
    try:
        zdata = pdns.get_zone(zone)
    except PdnsError as e:
        flash(request, str(e), "error")
        return RedirectResponse("/zones", status_code=303)
    soa, records = flatten_rrsets(zdata["rrsets"])
    owner = db.execute(
        select(User.login).join(ZoneAccess, ZoneAccess.user_id == User.id)
        .where(ZoneAccess.zone == zone, ZoneAccess.is_owner.is_(True))
    ).scalar_one_or_none()
    check = load_checks(db).get(zone)
    for r in records:
        r["rel"] = rel_name(r["name"], zone)
    _mark_ns(records, zone, check)

    custom = is_custom_zone(zdata, settings().catalog_zone)
    return render(request, "zone_view.html", user=user, zone=zone,
                  zone_display=to_unicode(zone.rstrip(".")), zdata=zdata,
                  soa=soa, records=records, owner=owner or "—", check=check,
                  custom=custom)


@router.post("/zones/{zone}/mode")
def zone_mode(request: Request, mode: str = Form(...), zone: str = Depends(zone_guard),
              user: User = Depends(current_user), db: Session = Depends(get_db)):
    s = settings()
    try:
        if mode == "custom":
            pdns.set_zone_catalog(zone, None)
            pdns.set_zone_tsig_keys(zone, [s.tsig_key] if s.tsig_key else [])
            log_history(db, user.id, "zone", zone, "Switch to custom DNS mode")
            flash(request, f"{to_unicode(zone.rstrip('.'))} is now custom DNS — "
                           "it left the catalog; add transfer keys for your secondaries")
        elif mode == "catalog":
            former = pdns.zone_tsig_keys(zone)
            pdns.set_zone_catalog(zone, s.catalog_zone)
            pdns.set_zone_kind(zone, "Master")        # back under pdns NOTIFY
            pdns.set_zone_also_notify(zone, [])       # drop any custom notify list
            pdns.ensure_tsig_allow_axfr(zone)
            # clean up per-zone keys that are no longer referenced anywhere
            globals_ = {canonical(n) for n in s.tsig_key_names}
            for kn in former:
                if canonical(kn) not in globals_ and not pdns.tsig_key_in_use(kn):
                    pdns.delete_tsig_key(kn)
            notify_zone(zone)
            log_history(db, user.id, "zone", zone, "Switch to catalog DNS mode")
            flash(request, f"{to_unicode(zone.rstrip('.'))} is back on the catalog (auto-fleet)")
        else:
            flash(request, f"Unknown mode '{mode}'", "error")
    except PdnsError as e:
        flash(request, str(e), "error")
    return RedirectResponse(f"/zones/{zone.rstrip('.')}/edit", status_code=303)


@router.post("/zones/{zone}/notify-targets")
def zone_notify_targets(request: Request, targets: str = Form(""),
                        zone: str = Depends(zone_guard), user: User = Depends(current_user),
                        db: Session = Depends(get_db)):
    try:
        parsed = parse_targets(targets)
    except ValueError:
        flash(request, "Notify targets must be IPs or hostnames (optionally :port), "
                       "comma/space separated", "error")
        return RedirectResponse(f"/zones/{zone.rstrip('.')}/edit", status_code=303)
    try:
        pdns.set_zone_also_notify(zone, parsed)
        # a non-empty list means the panel notifies exactly those servers, so
        # keep pdns from notifying anyone (Native = no pdns NOTIFY); an empty
        # list restores the default (Master → pdns notifies fleet + NS)
        pdns.set_zone_kind(zone, "Native" if parsed else "Master")
    except PdnsError as e:
        flash(request, str(e), "error")
        return RedirectResponse(f"/zones/{zone.rstrip('.')}/edit", status_code=303)
    log_history(db, user.id, "zone", zone,
                f"Set notify targets: {', '.join(parsed) if parsed else '(default)'}")
    flash(request, f"Notify targets updated ({len(parsed)} server(s))" if parsed
                   else "Notify targets cleared — default behaviour restored")
    return RedirectResponse(f"/zones/{zone.rstrip('.')}/edit", status_code=303)


@router.post("/zones/{zone}/keys")
def zone_key_add(request: Request, action: str = Form("generate"), name: str = Form(...),
                 algorithm: str = Form("hmac-sha256"), secret: str = Form(""),
                 zone: str = Depends(zone_guard), user: User = Depends(current_user),
                 db: Session = Depends(get_db)):
    key_name = name.strip().rstrip(".").lower()
    if not re.fullmatch(r"[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*", key_name or ""):
        flash(request, f"'{name}' is not a valid key name", "error")
        return RedirectResponse(f"/zones/{zone.rstrip('.')}/edit", status_code=303)
    try:
        pdns.create_tsig_key(key_name, algorithm,
                             secret=secret.strip() if action == "import" else None)
        keys = pdns.zone_tsig_keys(zone)
        if key_name not in keys:
            keys.append(key_name)
        pdns.set_zone_tsig_keys(zone, keys)
        log_history(db, user.id, "zone", zone,
                    f"Add transfer key {key_name} ({action})")
        flash(request, f"Transfer key {key_name} added")
    except PdnsError as e:
        flash(request, str(e), "error")
    return RedirectResponse(f"/zones/{zone.rstrip('.')}/edit", status_code=303)


@router.post("/zones/{zone}/keys/{keyname}/delete")
def zone_key_delete(request: Request, keyname: str, zone: str = Depends(zone_guard),
                    user: User = Depends(current_user), db: Session = Depends(get_db)):
    s = settings()
    if s.tsig_key and canonical(keyname) == canonical(s.tsig_key):
        flash(request, "Cannot remove the master's primary key", "error")
        return RedirectResponse(f"/zones/{zone.rstrip('.')}/edit", status_code=303)
    try:
        keys = [k for k in pdns.zone_tsig_keys(zone) if canonical(k) != canonical(keyname)]
        pdns.set_zone_tsig_keys(zone, keys)
        if not pdns.tsig_key_in_use(keyname):
            pdns.delete_tsig_key(keyname)
        log_history(db, user.id, "zone", zone, f"Remove transfer key {keyname}")
        flash(request, f"Transfer key {keyname} removed")
    except PdnsError as e:
        flash(request, str(e), "error")
    return RedirectResponse(f"/zones/{zone.rstrip('.')}/edit", status_code=303)


# -- RFC 2136 dynamic updates ----------------------------------------------

@router.post("/zones/{zone}/dnsupdate/keys")
def zone_update_key_add(request: Request, action: str = Form("generate"),
                        name: str = Form(...), algorithm: str = Form("hmac-sha256"),
                        secret: str = Form(""), zone: str = Depends(zone_guard),
                        user: User = Depends(current_user), db: Session = Depends(get_db)):
    key_name = name.strip().rstrip(".").lower()
    if not re.fullmatch(r"[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*", key_name or ""):
        flash(request, f"'{name}' is not a valid key name", "error")
        return RedirectResponse(f"/zones/{zone.rstrip('.')}/edit", status_code=303)
    try:
        pdns.create_tsig_key(key_name, algorithm,
                             secret=secret.strip() if action == "import" else None)
        keys = pdns.get_zone_update_keys(zone)
        if key_name not in keys:
            keys.append(key_name)
        pdns.set_zone_update_keys(zone, keys)
        log_history(db, user.id, "zone", zone,
                    f"Add dynamic-update key {key_name} ({action})")
        flash(request, f"Dynamic-update key {key_name} added")
    except PdnsError as e:
        flash(request, str(e), "error")
    return RedirectResponse(f"/zones/{zone.rstrip('.')}/edit", status_code=303)


@router.post("/zones/{zone}/dnsupdate/keys/{keyname}/delete")
def zone_update_key_delete(request: Request, keyname: str, zone: str = Depends(zone_guard),
                           user: User = Depends(current_user), db: Session = Depends(get_db)):
    try:
        keys = [k for k in pdns.get_zone_update_keys(zone) if canonical(k) != canonical(keyname)]
        pdns.set_zone_update_keys(zone, keys)
        # delete the underlying key only if no zone references it (AXFR or update)
        s = settings()
        primary = canonical(keyname) in {canonical(n) for n in s.tsig_key_names}
        if not primary and not pdns.tsig_key_in_use(keyname):
            pdns.delete_tsig_key(keyname)
        log_history(db, user.id, "zone", zone, f"Remove dynamic-update key {keyname}")
        flash(request, f"Dynamic-update key {keyname} removed")
    except PdnsError as e:
        flash(request, str(e), "error")
    return RedirectResponse(f"/zones/{zone.rstrip('.')}/edit", status_code=303)


@router.post("/zones/{zone}/dnsupdate/ips")
def zone_update_ips(request: Request, cidrs: str = Form(""),
                    zone: str = Depends(zone_guard), user: User = Depends(current_user),
                    db: Session = Depends(get_db)):
    try:
        parsed = parse_update_cidrs(cidrs)
    except ValueError as bad:
        flash(request, f"'{bad}' is not a valid IP or CIDR range", "error")
        return RedirectResponse(f"/zones/{zone.rstrip('.')}/edit", status_code=303)
    try:
        pdns.set_zone_update_ips(zone, parsed)
        log_history(db, user.id, "zone", zone,
                    f"Set dynamic-update IP allow-list ({len(parsed)} ranges)")
        if parsed and not pdns.get_zone_update_keys(zone):
            flash(request, "IP allow-list noted, but updates stay OFF until you add "
                           "an update key — dynamic updates always require TSIG.", "error")
        elif parsed:
            flash(request, "Dynamic-update IP allow-list saved")
        else:
            flash(request, "IP allow-list cleared — updates allowed from any source (TSIG still required)")
    except PdnsError as e:
        flash(request, str(e), "error")
    return RedirectResponse(f"/zones/{zone.rstrip('.')}/edit", status_code=303)


def _records_partial(request: Request, zone: str, user: User, db: Session | None = None):
    zdata = pdns.get_zone(zone)
    _, records = flatten_rrsets(zdata["rrsets"])
    for r in records:
        r["rel"] = rel_name(r["name"], zone)
    if db is not None:
        _mark_ns(records, zone, load_checks(db).get(zone))
    return render(request, "partials/records_table.html", user=user, zone=zone,
                  zone_display=to_unicode(zone.rstrip(".")), records=records,
                  serial=zdata.get("serial"))


def _rrset_contents(zone: str, name: str, rtype: str) -> tuple[int | None, list[dict]]:
    zdata = pdns.get_zone(zone)
    for rr in zdata["rrsets"]:
        if rr["name"] == name and rr["type"] == rtype:
            return rr["ttl"], [dict(r) for r in rr["records"]]
    return None, []


@router.get("/zones/{zone}/spf")
def spf_edit(request: Request, name: str = "", content: str = "",
             zone: str = Depends(zone_guard), user: User = Depends(current_user)):
    target = canonical(name) if name else canonical(zone)
    ttl, existing = _rrset_contents(zone, target, "TXT")
    orig = content
    if not orig:  # find an existing SPF in the TXT rrset, else start fresh
        orig = next((r["content"] for r in existing if is_spf(r["content"])), "")
    parsed = parse_spf(orig) if orig else parse_spf("v=spf1 ~all")
    return render(request, "spf.html", user=user, zone=zone,
                  zone_display=to_unicode(zone.rstrip(".")), host=rel_name(target, zone),
                  rname=target, orig_content=orig, ttl=ttl or 3600, parsed=parsed)


@router.post("/zones/{zone}/spf/save")
def spf_save(request: Request, name: str = Form(...), orig_content: str = Form(""),
             content: str = Form(...), ttl: int = Form(3600),
             zone: str = Depends(zone_guard), user: User = Depends(current_user),
             db: Session = Depends(get_db)):
    target = canonical(name)
    parsed = parse_spf(content)
    if not parsed["valid"]:
        flash(request, "SPF record has errors — fix them and save again", "error")
        return render(request, "spf.html", user=user, zone=zone,
                      zone_display=to_unicode(zone.rstrip(".")), host=rel_name(target, zone),
                      rname=target, orig_content=orig_content, ttl=ttl, parsed=parsed)
    new_quoted = quote_txt(parsed["raw"])
    try:
        cur_ttl, existing = _rrset_contents(zone, target, "TXT")
        remaining = [r for r in existing if r["content"] != orig_content] if orig_content \
            else list(existing)
        if not any(r["content"] == new_quoted for r in remaining):
            remaining.append({"content": new_quoted, "disabled": False})
        pdns.replace_rrset(zone, target, "TXT", ttl, remaining)
        notify_zone(zone)
    except PdnsError as e:
        flash(request, str(e), "error")
        return render(request, "spf.html", user=user, zone=zone,
                      zone_display=to_unicode(zone.rstrip(".")), host=rel_name(target, zone),
                      rname=target, orig_content=orig_content, ttl=ttl, parsed=parsed)
    log_history(db, user.id, "zone", zone, f"Update SPF at {rel_name(target, zone)}: {parsed['raw']}")
    flash(request, f"SPF record saved for {rel_name(target, zone)}")
    return RedirectResponse(f"/zones/{zone.rstrip('.')}", status_code=303)


@router.post("/zones/{zone}/records")
def record_create(
    request: Request,
    host: str = Form("@"),
    rtype: str = Form(..., alias="type"),
    data: str = Form(...),
    ttl: int = Form(3600),
    prio: int | None = Form(None),
    zone: str = Depends(zone_guard),
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    name = fqdn(host, zone)
    content = build_content(rtype, data, prio)
    _, existing = _rrset_contents(zone, name, rtype)
    if not any(r["content"] == content for r in existing):
        existing.append({"content": content, "disabled": False})
    try:
        pdns.replace_rrset(zone, name, rtype, ttl, existing)
        notify_zone(zone)
        log_history(db, user.id, "zone", zone, f"Create record {name} {rtype} {content}")
    except PdnsError as e:
        flash(request, str(e), "error")
    return _records_partial(request, zone, user, db)


@router.get("/zones/{zone}/records/edit")
def record_edit_form(request: Request, name: str, rtype: str, content: str,
                     zone: str = Depends(zone_guard), user: User = Depends(current_user)):
    ttl, existing = _rrset_contents(zone, name, rtype)
    prio, data = split_prio(rtype, content)
    rec = {"name": name, "rel": rel_name(name, zone), "type": rtype, "ttl": ttl,
           "content": content, "data": data, "prio": prio}
    return render(request, "partials/record_edit_row.html", zone=zone, rec=rec, user=user)


@router.get("/zones/{zone}/records/row")
def record_row(request: Request, name: str, rtype: str, content: str,
               zone: str = Depends(zone_guard), user: User = Depends(current_user)):
    """Cancel-edit: render the plain row back."""
    ttl, existing = _rrset_contents(zone, name, rtype)
    prio, data = split_prio(rtype, content)
    rec = {"name": name, "rel": rel_name(name, zone), "type": rtype, "ttl": ttl,
           "content": content, "data": data, "prio": prio, "disabled": False}
    return render(request, "partials/record_row.html", zone=zone, rec=rec, user=user)


@router.post("/zones/{zone}/records/update")
def record_update(
    request: Request,
    orig_name: str = Form(...),
    orig_type: str = Form(...),
    orig_content: str = Form(...),
    host: str = Form("@"),
    data: str = Form(...),
    ttl: int = Form(3600),
    prio: int | None = Form(None),
    zone: str = Depends(zone_guard),
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    rtype = orig_type
    new_name = fqdn(host, zone)
    new_content = build_content(rtype, data, prio)
    try:
        # remove the old record from its rrset
        old_ttl, old_set = _rrset_contents(zone, orig_name, rtype)
        remaining = [r for r in old_set if r["content"] != orig_content]
        if new_name == canonical(orig_name):
            if not any(r["content"] == new_content for r in remaining):
                remaining.append({"content": new_content, "disabled": False})
            pdns.replace_rrset(zone, orig_name, rtype, ttl, remaining)
        else:
            pdns.replace_rrset(zone, orig_name, rtype, old_ttl or ttl, remaining)
            _, target = _rrset_contents(zone, new_name, rtype)
            if not any(r["content"] == new_content for r in target):
                target.append({"content": new_content, "disabled": False})
            pdns.replace_rrset(zone, new_name, rtype, ttl, target)
        notify_zone(zone)
        log_history(db, user.id, "zone", zone,
                    f"Update record {orig_name} {rtype}: {orig_content} -> {new_content}")
    except PdnsError as e:
        flash(request, str(e), "error")
    return _records_partial(request, zone, user, db)


@router.post("/zones/{zone}/records/delete")
def record_delete(
    request: Request,
    name: str = Form(...),
    rtype: str = Form(...),
    content: str = Form(...),
    zone: str = Depends(zone_guard),
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    try:
        ttl, existing = _rrset_contents(zone, name, rtype)
        remaining = [r for r in existing if r["content"] != content]
        pdns.replace_rrset(zone, name, rtype, ttl or 3600, remaining)
        notify_zone(zone)
        log_history(db, user.id, "zone", zone, f"Delete record {name} {rtype} {content}")
    except PdnsError as e:
        flash(request, str(e), "error")
    return _records_partial(request, zone, user, db)


@router.get("/zones/{zone}/edit")
def zone_edit(request: Request, zone: str = Depends(zone_guard),
              user: User = Depends(current_user)):
    zdata = pdns.get_zone(zone)
    soa, _ = flatten_rrsets(zdata["rrsets"])
    s = settings()
    custom = is_custom_zone(zdata, s.catalog_zone)
    primary = canonical(s.tsig_key) if s.tsig_key else None
    per_zone_keys = []
    if custom:
        for kid in zdata.get("master_tsig_key_ids", []):
            if kid == primary:
                continue  # the master's own key, not a per-secondary key
            k = pdns.get_tsig_key(kid) or {}
            per_zone_keys.append({"name": kid.rstrip("."), "algorithm": k.get("algorithm", "?"),
                                  "secret": k.get("key", "")})
    notify_targets = pdns.get_zone_also_notify(zone) if custom else []
    # RFC 2136 dynamic-update permissions (independent of custom/catalog mode)
    update_keys = []
    for name in pdns.get_zone_update_keys(zone):
        k = pdns.get_tsig_key(name) or {}
        update_keys.append({"name": name, "algorithm": k.get("algorithm", "?"),
                            "secret": k.get("key", "")})
    update_ips = pdns.get_zone_update_ips(zone)
    dnssec = pdns.zone_dnssec_info(zone)
    return render(request, "zone_edit.html", user=user, zone=zone,
                  zone_display=to_unicode(zone.rstrip(".")), zdata=zdata, soa=soa,
                  custom=custom, per_zone_keys=per_zone_keys, master_host=s.master_host,
                  notify_targets=notify_targets, update_keys=update_keys,
                  update_ips=update_ips, dnssec=dnssec)


@router.post("/zones/{zone}/soa")
def soa_update(
    request: Request,
    soa_ns: str = Form(...),
    soa_mail: str = Form(...),
    refresh: int = Form(...),
    retry: int = Form(...),
    expire: int = Form(...),
    minimum: int = Form(...),
    ttl: int = Form(86400),
    zone: str = Depends(zone_guard),
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    zdata = pdns.get_zone(zone)
    soa, _ = flatten_rrsets(zdata["rrsets"])
    soa.mname = dotted(soa_ns)
    soa.rname = email_to_rname(soa_mail)
    soa.refresh, soa.retry, soa.expire, soa.minimum = refresh, retry, expire, minimum
    try:
        pdns.replace_rrset(zone, zone, "SOA", ttl, [{"content": soa.content(), "disabled": False}])
        notify_zone(zone)
        log_history(db, user.id, "zone", zone, "Update SOA")
        flash(request, "SOA updated")
    except PdnsError as e:
        flash(request, str(e), "error")
    return RedirectResponse(f"/zones/{zone.rstrip('.')}/edit", status_code=303)


@router.post("/zones/{zone}/dnssec/enable")
def zone_dnssec_enable(request: Request, zone: str = Depends(zone_guard),
                       user: User = Depends(current_user), db: Session = Depends(get_db)):
    if not is_zone_owner(db, user, zone):
        flash(request, "Only the zone owner or an admin can change DNSSEC", "error")
        return RedirectResponse(f"/zones/{zone.rstrip('.')}/edit", status_code=303)
    try:
        pdns.secure_zone(zone)
        notify_zone(zone)  # serial bumped by rectify → secondaries AXFR the signed zone
        log_history(db, user.id, "zone", zone, "Enable DNSSEC (CSK ECDSA P-256, NSEC3)")
        flash(request, "DNSSEC enabled — submit the DS record to the registrar to "
                       "complete the chain of trust")
    except PdnsError as e:
        flash(request, str(e), "error")
    return RedirectResponse(f"/zones/{zone.rstrip('.')}/edit", status_code=303)


@router.post("/zones/{zone}/dnssec/disable")
def zone_dnssec_disable(request: Request, zone: str = Depends(zone_guard),
                        user: User = Depends(current_user), db: Session = Depends(get_db)):
    if not is_zone_owner(db, user, zone):
        flash(request, "Only the zone owner or an admin can change DNSSEC", "error")
        return RedirectResponse(f"/zones/{zone.rstrip('.')}/edit", status_code=303)
    try:
        pdns.unsecure_zone(zone)
        notify_zone(zone)
        log_history(db, user.id, "zone", zone, "Disable DNSSEC")
        flash(request, "DNSSEC disabled — remove the DS record at the registrar too")
    except PdnsError as e:
        flash(request, str(e), "error")
    return RedirectResponse(f"/zones/{zone.rstrip('.')}/edit", status_code=303)


@router.post("/zones/{zone}/delete")
def zone_delete(request: Request, zone: str = Depends(zone_guard),
                user: User = Depends(current_user), db: Session = Depends(get_db)):
    s = settings()
    # capture the zone's per-zone (non-global) TSIG keys before deletion
    globals_ = {canonical(n) for n in s.tsig_key_names}
    try:
        former_keys = [k for k in pdns.zone_tsig_keys(zone) if canonical(k) not in globals_]
        former_keys += [k for k in pdns.get_zone_update_keys(zone)
                        if canonical(k) not in globals_ and canonical(k) not in
                        {canonical(x) for x in former_keys}]
    except PdnsError:
        former_keys = []
    try:
        pdns.delete_zone(zone)
    except PdnsError as e:
        flash(request, str(e), "error")
        return RedirectResponse(f"/zones/{zone.rstrip('.')}/edit", status_code=303)
    # clean up this zone's per-zone keys if no other zone uses them
    for kn in former_keys:
        try:
            if not pdns.tsig_key_in_use(kn):
                pdns.delete_tsig_key(kn)
        except PdnsError:
            pass
    for za in db.execute(select(ZoneAccess).where(ZoneAccess.zone == zone)).scalars():
        db.delete(za)
    for zc in db.execute(select(ZoneCheck).where(ZoneCheck.zone == zone)).scalars():
        db.delete(zc)
    log_history(db, user.id, "zone", zone, f"Delete zone {zone}")
    flash(request, f"Zone {to_unicode(zone)} deleted")
    return RedirectResponse("/zones", status_code=303)


@router.post("/zones/{zone}/notify")
def zone_notify(request: Request, zone: str = Depends(zone_guard),
                user: User = Depends(current_user)):
    try:
        notify_zone(zone)
        flash(request, "DNS NOTIFY sent")
    except PdnsError as e:
        flash(request, str(e), "error")
    return RedirectResponse(f"/zones/{zone.rstrip('.')}", status_code=303)


@router.get("/zones/{zone}/axfr")
def zone_axfr(request: Request, raw: int = 0, zone: str = Depends(zone_guard),
              user: User = Depends(current_user)):
    try:
        text, count = axfr_text(zone)
    except AxfrError as e:
        flash(request, f"Zone transfer failed: {e}", "error")
        return RedirectResponse(f"/zones/{zone.rstrip('.')}", status_code=303)
    if raw:
        return PlainTextResponse(text, headers={
            "Content-Disposition": f'attachment; filename="{zone.rstrip(".")}.zone"'})
    return render(request, "zone_axfr.html", user=user, zone=zone,
                  zone_display=to_unicode(zone.rstrip(".")), text=text, count=count)


@router.post("/zones/{zone}/servers")
def zone_servers(request: Request, zone: str = Depends(zone_guard),
                 user: User = Depends(current_user), db: Session = Depends(get_db)):
    s = settings()
    limit = user.check_rate_limit if user.check_rate_limit is not None else s.default_check_rate_limit
    ok, retry = ratelimit.allow(user.id, limit)
    if not ok:
        return render(request, "partials/server_results.html", user=user, zone=zone,
                      master_serial=None, rows=[], delegation=None,
                      error=f"Rate limit reached ({limit}/min) — wait {retry}s")
    try:
        zdata = pdns.get_zone(zone)
    except PdnsError as e:
        return render(request, "partials/server_results.html", user=user, zone=zone,
                      master_serial=None, rows=[], delegation=None, error=str(e))
    master_serial = zdata.get("serial")
    rows = check_slaves(zone, master_serial)
    delegation = check_delegation(zone, apex_ns(zone))
    note = slave_summary(rows)
    if delegation["status"] == "mismatch":
        note += "; delegation MISMATCH"
    log_history(db, user.id, "zone", zone, f"Check DNS servers: {note}")
    return render(request, "partials/server_results.html", user=user, zone=zone,
                  master_serial=master_serial, rows=rows, delegation=delegation, error=None)


@router.get("/zones/{zone}/history")
def zone_history(request: Request, zone: str = Depends(zone_guard),
                 user: User = Depends(current_user), db: Session = Depends(get_db)):
    entries = db.execute(
        select(HistoryEntry, User.login)
        .outerjoin(User, User.id == HistoryEntry.user_id)
        .where(HistoryEntry.target_type == "zone", HistoryEntry.target == zone)
        .order_by(HistoryEntry.created_at.desc())
        .limit(500)
    ).all()
    return render(request, "history.html", user=user, title=f"History · {to_unicode(zone.rstrip('.'))}",
                  back=f"/zones/{zone.rstrip('.')}", entries=entries)


@router.get("/zones/{zone}/access")
def zone_access(request: Request, zone: str = Depends(zone_guard),
                user: User = Depends(current_user), db: Session = Depends(get_db)):
    grants = {
        za.user_id: za
        for za in db.execute(select(ZoneAccess).where(ZoneAccess.zone == zone)).scalars()
    }
    # admins see everyone (incl. themselves) so they can reassign ownership
    others = [
        {"user": u, "grant": grants.get(u.id), "me": u.id == user.id}
        for u in db.execute(select(User).order_by(User.login)).scalars()
        if user.is_admin or u.id != user.id
    ]
    return render(request, "zone_access.html", user=user, zone=zone,
                  zone_display=to_unicode(zone.rstrip(".")), others=others)


@router.post("/zones/{zone}/owner/{uid}")
def zone_owner_set(request: Request, uid: int, zone: str = Depends(zone_guard),
                   admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    target = db.get(User, uid)
    if not target:
        flash(request, "No such user", "error")
        return RedirectResponse(f"/zones/{zone.rstrip('.')}/access", status_code=303)

    grants = db.execute(select(ZoneAccess).where(ZoneAccess.zone == zone)).scalars().all()
    old_owner = next((g for g in grants if g.is_owner), None)
    if old_owner and old_owner.user_id == uid:
        flash(request, f"{target.login} already owns this zone")
        return RedirectResponse(f"/zones/{zone.rstrip('.')}/access", status_code=303)

    if old_owner:
        old_owner.is_owner = False  # previous owner keeps editor access
    grant = next((g for g in grants if g.user_id == uid), None)
    if grant:
        grant.is_owner = True
    else:
        db.add(ZoneAccess(zone=zone, user_id=uid, is_owner=True))

    log_history(db, admin.id, "zone", zone, f"Change owner to {target.login}")
    flash(request, f"Owner of {to_unicode(zone.rstrip('.'))} is now {target.login}")
    return RedirectResponse(f"/zones/{zone.rstrip('.')}/access", status_code=303)


@router.post("/zones/{zone}/access/{uid}/toggle")
def zone_access_toggle(request: Request, uid: int, zone: str = Depends(zone_guard),
                       user: User = Depends(current_user), db: Session = Depends(get_db)):
    # only the zone owner (or an admin) may change the access list — a delegated
    # editor must not be able to grant/revoke others or remove the owner
    if not is_zone_owner(db, user, zone):
        flash(request, "Only the zone owner or an admin can change access", "error")
        return RedirectResponse(f"/zones/{zone.rstrip('.')}/access", status_code=303)
    target = db.get(User, uid)
    if target:
        grant = db.execute(
            select(ZoneAccess).where(ZoneAccess.zone == zone, ZoneAccess.user_id == uid)
        ).scalar_one_or_none()
        if grant and grant.is_owner:
            flash(request, "Cannot revoke the owner's access — reassign ownership first", "error")
        elif grant:
            db.delete(grant)
            log_history(db, user.id, "zone", zone, f"Revoke access from {target.login}")
        else:
            db.add(ZoneAccess(zone=zone, user_id=uid, is_owner=False))
            log_history(db, user.id, "zone", zone, f"Grant access to {target.login}")
    return RedirectResponse(f"/zones/{zone.rstrip('.')}/access", status_code=303)
