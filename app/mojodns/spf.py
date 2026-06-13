"""SPF (RFC 7208) decode / validate / build for the TXT record editor.

Kept self-contained and data-driven so the same parse→terms→build shape can
host other policy-TXT decoders later (e.g. DMARC). A "term" is one
space-separated element of the record: a *mechanism* (optional qualifier +
name + optional value) or a *modifier* (name=value).
"""

import ipaddress
import re
from dataclasses import asdict, dataclass

QUALIFIERS = {"+": "pass", "-": "fail", "~": "softfail", "?": "neutral"}
MECHANISMS = ["all", "include", "a", "mx", "ip4", "ip6", "exists", "ptr"]
MODIFIERS = ["redirect", "exp"]
# mechanisms/modifiers that cost a DNS lookup (RFC 7208 §4.6.4 — limit 10)
LOOKUP_KINDS = {"include", "a", "mx", "ptr", "exists", "redirect"}
# mechanisms whose value is a domain spec
DOMAIN_KINDS = {"include", "exists", "redirect", "exp"}


@dataclass
class Term:
    qualifier: str  # +,-,~,? for mechanisms; "" for modifiers
    kind: str       # all/include/a/mx/ip4/ip6/exists/ptr/redirect/exp/unknown
    value: str      # canonical value (no leading ':'; a/mx keep leading '/')
    raw: str        # original token
    error: str = ""


def is_spf(content: str) -> bool:
    return strip_txt(content).lower().startswith("v=spf1")


def strip_txt(content: str) -> str:
    """Unquote a TXT value, joining adjacent quoted strings ("a" "b" -> ab)."""
    c = (content or "").strip()
    if '"' in c:
        parts = re.findall(r'"((?:[^"\\]|\\.)*)"', c)
        if parts:
            return "".join(p.replace('\\"', '"').replace("\\\\", "\\") for p in parts)
    return c


def _valid_domain(d: str) -> bool:
    # SPF domain-specs may contain macros (%{...}); accept those leniently
    d = d.rstrip(".")
    if not d or len(d) > 253:
        return False
    if "%" in d:  # macro expansion — don't try to fully validate
        return True
    return bool(re.fullmatch(r"(?:[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?\.)*"
                             r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", d))


def _validate(kind: str, value: str) -> str:
    if kind == "all":
        return "'all' takes no value" if value else ""
    if kind in ("include", "exists", "redirect", "exp"):
        if not value:
            return f"'{kind}' requires a domain"
        return "" if _valid_domain(value) else f"invalid domain '{value}'"
    if kind == "ip4":
        if not value:
            return "'ip4' requires an address"
        try:
            ipaddress.IPv4Network(value, strict=False)
            return ""
        except ValueError:
            return f"invalid IPv4 address/range '{value}'"
    if kind == "ip6":
        if not value:
            return "'ip6' requires an address"
        try:
            ipaddress.IPv6Network(value, strict=False)
            return ""
        except ValueError:
            return f"invalid IPv6 address/range '{value}'"
    if kind in ("a", "mx", "ptr"):
        if not value:
            return ""
        dom, _, cidr = value.lstrip("/").rpartition("/") if "/" in value else (value, "", "")
        # value forms: "domain", "domain/cidr", "/cidr"
        if value.startswith("/"):
            cidr = value[1:]
            dom = ""
        elif "/" in value:
            dom, cidr = value.split("/", 1)
        else:
            dom, cidr = value, ""
        if dom and not _valid_domain(dom):
            return f"invalid domain '{dom}'"
        if cidr and not (cidr.isdigit() and 0 <= int(cidr) <= 128):
            return f"invalid CIDR '/{cidr}'"
        return ""
    return f"unknown mechanism '{kind}'"


def parse_term(token: str) -> Term:
    raw = token
    # modifier: name=value (no qualifier)
    if "=" in token and token.split("=", 1)[0].lower() in MODIFIERS:
        name, value = token.split("=", 1)
        return Term("", name.lower(), value, raw, _validate(name.lower(), value))

    qual = ""
    body = token
    if body[:1] in QUALIFIERS:
        qual, body = body[0], body[1:]

    if ":" in body:
        name, value = body.split(":", 1)
    elif "/" in body and body.split("/", 1)[0].lower() in ("a", "mx", "ptr"):
        name, rest = body.split("/", 1)
        value = "/" + rest
    else:
        name, value = body, ""

    name_l = name.lower()
    if name_l not in MECHANISMS:
        return Term(qual, "unknown", value, raw, f"unknown mechanism '{name}'")
    return Term(qual, name_l, value, raw, _validate(name_l, value))


def parse_spf(content: str) -> dict:
    raw = strip_txt(content)
    errors: list[str] = []
    warnings: list[str] = []
    terms: list[Term] = []

    tokens = raw.split()
    if not tokens or tokens[0].lower() != "v=spf1":
        errors.append("record must start with 'v=spf1'")
        return {"raw": raw, "terms": [], "errors": errors, "warnings": warnings, "valid": False}

    seen_all = False
    lookups = 0
    for tok in tokens[1:]:
        t = parse_term(tok)
        terms.append(t)
        if t.error:
            errors.append(f"{tok}: {t.error}")
        if t.kind in LOOKUP_KINDS:
            lookups += 1
        if t.kind == "all":
            seen_all = True
        elif seen_all and t.kind != "unknown":
            warnings.append(f"'{tok}' comes after 'all' and is never evaluated")

    if [t for t in terms if t.kind == "all"][1:]:
        warnings.append("more than one 'all' — only the first applies")
    redirects = [t for t in terms if t.kind == "redirect"]
    if len(redirects) > 1:
        errors.append("more than one 'redirect=' modifier")
    if redirects and any(t.kind == "all" for t in terms):
        warnings.append("'redirect' is ignored when an 'all' mechanism is present")
    if lookups > 10:
        warnings.append(f"{lookups} DNS-lookup terms exceed the RFC 7208 limit of 10")
    if not any(t.kind in ("all", "redirect") for t in terms):
        warnings.append("no 'all' or 'redirect' — the record has no default policy")
    if len(raw) > 255:
        warnings.append(f"{len(raw)} chars; values over 255 must be split into multiple quoted strings")

    return {"raw": raw, "terms": [asdict(t) for t in terms],
            "errors": errors, "warnings": warnings, "valid": not errors}


def render_term(t: dict) -> str:
    kind, value, qual = t["kind"], t.get("value", ""), t.get("qualifier", "")
    if kind in MODIFIERS:
        return f"{kind}={value}"
    s = (qual or "") + kind
    if not value:
        return s
    if kind in ("a", "mx", "ptr"):
        return s + (value if value.startswith("/") else ":" + value)
    return s + ":" + value


def build_spf(terms: list[dict]) -> str:
    parts = ["v=spf1"] + [render_term(t) for t in terms if t.get("kind")]
    return " ".join(parts)
