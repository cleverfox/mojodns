"""DNS record content helpers for the PowerDNS API (canonical form:
trailing dots on hostnames, quoted TXT, priority joined into content)."""

from dataclasses import dataclass

# record types editable in the UI
RECORD_TYPES = ["A", "AAAA", "CAA", "CNAME", "LOC", "MX", "NS", "PTR", "SRV", "SSHFP", "TLSA", "TXT"]
# types whose content carries a priority prefix entered separately in the UI
PRIO_TYPES = {"MX", "SRV"}
# types whose (last) field is a hostname needing a trailing dot
HOSTNAME_TYPES = {"CNAME", "NS", "PTR", "MX", "SRV"}


def dotted(host: str) -> str:
    host = host.strip()
    return host if host.endswith(".") else host + "."


def quote_txt(content: str) -> str:
    content = content.strip()
    if content.startswith('"') and content.endswith('"'):
        return content
    return '"' + content.replace('\\', '\\\\').replace('"', '\\"') + '"'


def build_content(rtype: str, data: str, prio: int | None = None) -> str:
    """Build canonical rrset content from UI fields."""
    data = data.strip()
    if rtype == "TXT":
        return quote_txt(data)
    if rtype in HOSTNAME_TYPES and rtype not in PRIO_TYPES:
        return dotted(data)
    if rtype == "MX":
        return f"{prio or 0} {dotted(data)}"
    if rtype == "SRV":
        # data: "weight port target" (priority entered separately, as before)
        parts = data.split()
        if parts:
            parts[-1] = dotted(parts[-1])
        return f"{prio or 0} {' '.join(parts)}"
    return data


def split_prio(rtype: str, content: str) -> tuple[int | None, str]:
    """Split a stored content back into (prio, rest) for the edit form."""
    if rtype in PRIO_TYPES:
        first, _, rest = content.partition(" ")
        try:
            return int(first), rest
        except ValueError:
            return None, content
    return None, content


@dataclass
class Soa:
    mname: str
    rname: str
    serial: int
    refresh: int
    retry: int
    expire: int
    minimum: int

    @classmethod
    def parse(cls, content: str) -> "Soa":
        p = content.split()
        return cls(p[0], p[1], int(p[2]), int(p[3]), int(p[4]), int(p[5]), int(p[6]))

    def content(self) -> str:
        return (
            f"{dotted(self.mname)} {dotted(self.rname)} {self.serial} "
            f"{self.refresh} {self.retry} {self.expire} {self.minimum}"
        )

    @property
    def email(self) -> str:
        """RNAME shown as an e-mail address (first label = local part)."""
        bare = self.rname.rstrip(".")
        local, _, domain = bare.partition(".")
        return f"{local.replace(chr(92) + '.', '.')}@{domain}" if domain else bare


def email_to_rname(email: str) -> str:
    email = email.strip()
    if "@" in email:
        local, _, domain = email.partition("@")
        return dotted(f"{local.replace('.', chr(92) + '.')}.{domain}")
    return dotted(email)


def flatten_rrsets(rrsets: list[dict]) -> tuple[Soa | None, list[dict]]:
    """Split a pdns rrset list into the SOA and flat per-record rows."""
    soa = None
    rows = []
    for rr in rrsets:
        if rr["type"] == "SOA":
            if rr["records"]:
                soa = Soa.parse(rr["records"][0]["content"])
            continue
        for rec in rr["records"]:
            prio, data = split_prio(rr["type"], rec["content"])
            rows.append(
                {
                    "name": rr["name"],
                    "type": rr["type"],
                    "ttl": rr["ttl"],
                    "content": rec["content"],
                    "data": data,
                    "prio": prio,
                    "disabled": rec.get("disabled", False),
                }
            )
    rows.sort(key=lambda r: (r["name"], r["type"], r["content"]))
    return soa, rows
