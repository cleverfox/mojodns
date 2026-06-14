from functools import lru_cache

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    database_url: str = "postgresql+psycopg://dns:dns@127.0.0.1/dns"
    pdns_api_url: str = "http://127.0.0.1:8081/api/v1"
    pdns_api_key: str = "changeme"
    pdns_server_id: str = "localhost"

    session_secret: str = "dev-secret-change-me"
    # mark the session cookie Secure (HTTPS-only). Default off so dev over plain
    # HTTP works; set COOKIE_SECURE=true in any TLS-fronted deployment.
    cookie_secure: bool = False

    catalog_zone: str = "catalog.mojodns."
    # Primary TSIG key: its name is allowed for AXFR on every zone, and the
    # panel uses its secret for its own transfers (zone text view). The key
    # itself lives in pdns (pdnsutil generate-tsig-key).
    tsig_key: str = ""
    tsig_secret: str = ""
    tsig_algo: str = "hmac-sha256"
    # Additional TSIG key *names* also allowed for AXFR on every zone — one
    # per trust domain (e.g. a separate key for a third-party secondary so
    # you never share the primary secret). Secrets live in pdns; the panel
    # only needs the names. Comma-separated.
    tsig_extra_keys: str = ""

    @property
    def tsig_key_names(self) -> list[str]:
        """All TSIG key names allowed for AXFR (primary first, then extras)."""
        names = [self.tsig_key] if self.tsig_key else []
        names += [k.strip() for k in self.tsig_extra_keys.split(",") if k.strip()]
        # de-dup, preserve order
        seen, out = set(), []
        for n in names:
            if n not in seen:
                seen.add(n)
                out.append(n)
        return out

    # where the panel sends its own AXFR requests (the pdns DNS listener)
    pdns_axfr_host: str = "pdns"
    pdns_axfr_port: int = 1053

    # public address secondaries use to reach this master — shown only in the
    # custom-DNS UI hint (e.g. "195.3.255.70"); cosmetic, no functional effect
    master_host: str = ""
    default_soa_ns: str = "ns1.example.net."
    default_soa_mail: str = "hostmaster.example.net."
    default_nameservers: str = "ns1.example.net.,ns2.example.net."

    bootstrap_admin_password: str = ""

    # NS-delegation verification: recursive resolvers to ask, and how often
    # the background re-check runs (0 disables the periodic check)
    verify_resolvers: str = "1.1.1.1,8.8.8.8"
    verify_interval_hours: float = 24.0

    # timeout (seconds) for per-record TCP/HTTP/HTTPS reachability checks
    check_timeout: float = 6.0
    # allow probing non-public (loopback/private/link-local) addresses. Off by
    # default — keeping it off prevents the checks/DNS-server poll from being
    # used as an internal port-scanner (SSRF). Enable only for an isolated,
    # internal-by-design deployment.
    check_allow_private: bool = False
    # default per-user rate limit (requests/minute) for outbound-probe actions
    # (per-record checks + "check DNS servers"); per-user override on the User row
    default_check_rate_limit: int = 2
    # per-source-IP cap on login attempts/minute (brute-force throttle; 0 = off)
    login_rate_limit: int = 10

    @property
    def verify_resolver_list(self) -> list[str]:
        return [r.strip() for r in self.verify_resolvers.split(",") if r.strip()]

    @property
    def default_ns_list(self) -> list[str]:
        return [n.strip() for n in self.default_nameservers.split(",") if n.strip()]


@lru_cache
def settings() -> Settings:
    return Settings()
