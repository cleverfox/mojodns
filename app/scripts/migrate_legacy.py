"""Migrate data from the old mojodns-perl database into the new stack.

Reads the legacy PostgreSQL database (restore backup.sql into a scratch DB
first), then:

  * users          -> app_users   (legacy salted-SHA1 hashes kept; they verify
                                   on login and are upgraded to bcrypt)
  * roles_users    -> app_users.role (role_id 1 = admin)
  * domains+records-> PowerDNS via REST API (Master zones, catalog members);
                      legacy `prio` is folded into content for MX/SRV,
                      hostnames get trailing dots, TXT gets quoted
  * domains.user_id + user_access -> zone_access
  * history        -> app_history

Usage (inside the web container or an activated venv with the app's env):

    python -m scripts.migrate_legacy --legacy-dsn postgresql://dns@db/dns_legacy [--dry-run]
"""

import argparse
import sys
from collections import defaultdict

import psycopg
from sqlalchemy import select

from mojodns.config import settings
from mojodns.db import HistoryEntry, SessionLocal, User, ZoneAccess
from mojodns.dnsutil import dotted, quote_txt
from mojodns.idn import to_ascii
from mojodns.pdns import PdnsError, canonical, pdns

HOST_TYPES = {"CNAME", "NS", "PTR"}
PRIO_TYPES = {"MX", "SRV"}
SKIP_TYPES = {"SOA"}  # handled separately

# legacy convention: a zone was "disabled" by renaming it with this prefix
# (its records keep the real names, so it cannot be imported as-is)
DISABLED_PREFIX = "__"


def host(name: str) -> str:
    """Hostname content -> canonical ascii with trailing dot (handles IDN)."""
    return dotted(to_ascii(name.strip()))


def conv_content(rtype: str, content: str, prio) -> str:
    content = (content or "").strip()
    if rtype == "TXT" or rtype == "SPF":
        return quote_txt(content)
    if rtype in HOST_TYPES:
        return host(content)
    if rtype in PRIO_TYPES:
        parts = content.split()
        if parts:
            parts[-1] = host(parts[-1])
        return f"{prio or 0} {' '.join(parts)}"
    return content


def conv_soa(content: str) -> str:
    p = content.split()
    # legacy: "mname rname serial refresh retry expire minimum",
    # rname sometimes stored as an e-mail address
    mname = host(p[0])
    rname = p[1]
    if "@" in rname:
        local, _, dom = rname.partition("@")
        rname = f"{local.replace('.', chr(92) + '.')}.{dom}"
    rname = dotted(rname)
    rest = p[2:7] if len(p) >= 7 else ["1", "10800", "3600", "604800", "3600"]
    return f"{mname} {rname} {' '.join(rest)}"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--legacy-dsn", required=True, help="DSN of the restored legacy database")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    legacy = psycopg.connect(args.legacy_dsn, row_factory=psycopg.rows.dict_row)
    db = SessionLocal()
    s = settings()

    # ---- users -------------------------------------------------------------
    roles = {
        r["user_id"]: r["role_id"]
        for r in legacy.execute("select user_id, role_id from roles_users")
    }
    id_map: dict[int, int] = {}
    for u in legacy.execute("select * from users order by id"):
        existing = db.execute(select(User).where(User.login == u["login"])).scalar_one_or_none()
        if existing:
            id_map[u["id"]] = existing.id
            print(f"user {u['login']}: exists, skipped")
            continue
        user = User(
            login=u["login"],
            email=u["email"],
            password_hash=f"legacysha1${u['salt']}${u['crypted_password']}",
            role="admin" if roles.get(u["id"]) == 1 else "owner",
            state="active" if (u["state"] or "active") in ("active", "passive") else "disabled",
        )
        db.add(user)
        db.flush()
        id_map[u["id"]] = user.id
        print(f"user {u['login']}: migrated ({user.role})")

    # ---- zones + records ---------------------------------------------------
    domains = list(legacy.execute("select * from domains where id > 0 order by name"))
    recs = defaultdict(list)
    for r in legacy.execute("select * from records where domain_id > 0"):
        recs[r["domain_id"]].append(r)

    created = skipped = disabled = 0
    for d in domains:
        if d["name"].startswith(DISABLED_PREFIX):
            print(f"zone {d['name']}: disabled in legacy (prefix {DISABLED_PREFIX}), skipped")
            disabled += 1
            continue
        zone = canonical(to_ascii(d["name"]))
        rrsets: dict[tuple[str, str], dict] = {}
        for r in recs[d["id"]]:
            rtype = r["type"].upper()
            name = canonical(to_ascii(r["name"]))
            if rtype in SKIP_TYPES:
                content = conv_soa(r["content"])
            else:
                content = conv_content(rtype, r["content"], r["prio"])
            key = (name, rtype)
            rr = rrsets.setdefault(
                key,
                {"name": name, "type": rtype, "ttl": r["ttl"] or 3600,
                 "changetype": "REPLACE", "records": []},
            )
            if not any(x["content"] == content for x in rr["records"]):
                rr["records"].append({"content": content, "disabled": False})

        # a CNAME may not coexist with any other rrset at the same name —
        # legacy data has a few (apex CNAME next to SOA/NS); drop those
        for name, rtype in list(rrsets):
            if rtype == "CNAME" and any(k[0] == name and k[1] != "CNAME" for k in rrsets):
                print(f"zone {zone}: dropping CNAME {name} "
                      f"(conflicts with other records at the same name)")
                del rrsets[(name, rtype)]

        if args.dry_run:
            print(f"zone {zone}: would create with {len(rrsets)} rrsets")
            continue
        if pdns.zone_exists(zone):
            print(f"zone {zone}: exists, skipped")
            skipped += 1
        else:
            try:
                pdns.create_zone(zone, kind="Master", catalog=s.catalog_zone,
                                 rrsets=list(rrsets.values()))
                pdns.ensure_tsig_allow_axfr(zone)
                created += 1
                print(f"zone {zone}: created ({len(rrsets)} rrsets)")
            except PdnsError as e:
                print(f"zone {zone}: FAILED — {e}", file=sys.stderr)
                continue

        # ownership + delegated access
        def grant(uid_legacy: int | None, owner: bool):
            uid = id_map.get(uid_legacy or -1)
            if not uid:
                return
            exists = db.execute(
                select(ZoneAccess).where(ZoneAccess.zone == zone, ZoneAccess.user_id == uid)
            ).scalar_one_or_none()
            if not exists:
                db.add(ZoneAccess(zone=zone, user_id=uid, is_owner=owner))

        grant(d["user_id"], True)
        for ua in legacy.execute(
            "select user_id from user_access where domain_id = %s", (d["id"],)
        ):
            grant(ua["user_id"], False)

    # ---- history -------------------------------------------------------
    MARKER = "legacy-history-imported"
    already = db.execute(
        select(HistoryEntry.id).where(
            HistoryEntry.target_type == "system", HistoryEntry.message == MARKER
        )
    ).first()
    if already:
        print("history: already imported, skipped")
    elif not args.dry_run:
        dom_names = {d["id"]: canonical(to_ascii(d["name"])) for d in domains}
        login_by_id = {
            u["id"]: u["login"] for u in legacy.execute("select id, login from users")
        }
        n = 0
        for h in legacy.execute("select * from history order by uid"):
            if h["target_type"] == "domain":
                ttype, target = "zone", dom_names.get(h["target_id"])
            else:
                ttype, target = "user", login_by_id.get(h["target_id"])
            db.add(HistoryEntry(
                user_id=id_map.get(h["user_id"]),
                target_type=ttype,
                target=target,
                message=h["message"] or "",
                created_at=h["t"],
            ))
            n += 1
        db.add(HistoryEntry(user_id=None, target_type="system", target=None, message=MARKER))
        print(f"history: {n} entries")

    if args.dry_run:
        db.rollback()
        print("dry run — nothing written")
    else:
        db.commit()
        print(f"done: {created} zones created, {skipped} already existed, "
              f"{disabled} legacy-disabled skipped")
    return 0


if __name__ == "__main__":
    sys.exit(main())
