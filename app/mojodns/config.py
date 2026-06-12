from functools import lru_cache

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    database_url: str = "postgresql+psycopg://dns:dns@127.0.0.1/dns"
    pdns_api_url: str = "http://127.0.0.1:8081/api/v1"
    pdns_api_key: str = "changeme"
    pdns_server_id: str = "localhost"

    session_secret: str = "dev-secret-change-me"

    catalog_zone: str = "catalog.mojodns."
    # TSIG key *name* for outgoing zone transfers (TSIG-ALLOW-AXFR metadata
    # is set on every zone when non-empty); the key itself lives in pdns
    tsig_key: str = ""
    # secret + algorithm let the panel itself AXFR zones (zone text view)
    tsig_secret: str = ""
    tsig_algo: str = "hmac-sha256"

    # where the panel sends its own AXFR requests (the pdns DNS listener)
    pdns_axfr_host: str = "pdns"
    pdns_axfr_port: int = 1053
    default_soa_ns: str = "ns1.example.net."
    default_soa_mail: str = "hostmaster.example.net."
    default_nameservers: str = "ns1.example.net.,ns2.example.net."

    bootstrap_admin_password: str = ""

    # NS-delegation verification: recursive resolvers to ask, and how often
    # the background re-check runs (0 disables the periodic check)
    verify_resolvers: str = "1.1.1.1,8.8.8.8"
    verify_interval_hours: float = 24.0

    @property
    def verify_resolver_list(self) -> list[str]:
        return [r.strip() for r in self.verify_resolvers.split(",") if r.strip()]

    @property
    def default_ns_list(self) -> list[str]:
        return [n.strip() for n in self.default_nameservers.split(",") if n.strip()]


@lru_cache
def settings() -> Settings:
    return Settings()
