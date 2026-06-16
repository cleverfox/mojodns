from datetime import datetime

from sqlalchemy import BigInteger, DateTime, ForeignKey, String, Text, UniqueConstraint, create_engine, func
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker

from .config import settings


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "app_users"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    login: Mapped[str] = mapped_column(String(255), unique=True)
    email: Mapped[str | None] = mapped_column(String(255))
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(16), default="owner")
    state: Mapped[str] = mapped_column(String(16), default="active")
    # admin can deactivate an account without deleting it
    enabled: Mapped[bool] = mapped_column(default=True)
    # force a password change at next login (new account / admin reset / expired)
    must_change_password: Mapped[bool] = mapped_column(default=False)
    last_login: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_pwd_change: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # per-minute cap on outbound-probe actions (checks / DNS-server poll);
    # NULL ⇒ use settings.default_check_rate_limit
    check_rate_limit: Mapped[int | None] = mapped_column(default=None)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    @property
    def is_admin(self) -> bool:
        return self.role == "admin"


class ZoneAccess(Base):
    __tablename__ = "zone_access"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    zone: Mapped[str] = mapped_column(String(255))
    user_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("app_users.id", ondelete="CASCADE"))
    is_owner: Mapped[bool] = mapped_column(default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class HistoryEntry(Base):
    __tablename__ = "app_history"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    user_id: Mapped[int | None] = mapped_column(BigInteger, ForeignKey("app_users.id", ondelete="SET NULL"))
    target_type: Mapped[str] = mapped_column(String(16))
    target: Mapped[str | None] = mapped_column(String(255))
    message: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class ZoneCheck(Base):
    """Result of the last NS-delegation verification for a zone."""

    __tablename__ = "zone_checks"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    zone: Mapped[str] = mapped_column(String(255), unique=True)
    # ok = delegation matches | partial = some NS match | mismatch = moved or
    # abandoned (incl. NXDOMAIN) | error = could not check (timeout etc.)
    status: Mapped[str] = mapped_column(String(16))
    resolved_ns: Mapped[str | None] = mapped_column(Text)  # space separated
    detail: Mapped[str | None] = mapped_column(String(255))
    # DNSSEC chain status: unsigned | secure | insecure (signed, no DS at parent)
    # | bogus (validation fails) | error; NULL until first checked
    dnssec: Mapped[str | None] = mapped_column(String(16))
    checked_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class CertObservation(Base):
    """Last TLS certificate seen for a record's host:ip during an HTTPS check."""

    __tablename__ = "cert_observations"
    __table_args__ = (UniqueConstraint("host", "ip", "port", name="uq_cert_host_ip_port"),)

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    zone: Mapped[str] = mapped_column(String(255))
    host: Mapped[str] = mapped_column(String(255))
    ip: Mapped[str] = mapped_column(String(64))
    port: Mapped[int] = mapped_column(default=443)
    subject: Mapped[str | None] = mapped_column(String(255))
    issuer: Mapped[str | None] = mapped_column(String(255))
    not_after: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    days_left: Mapped[int | None] = mapped_column(default=None)
    hostname_match: Mapped[bool | None] = mapped_column(default=None)
    self_signed: Mapped[bool | None] = mapped_column(default=None)
    trusted: Mapped[bool | None] = mapped_column(default=None)
    error: Mapped[str | None] = mapped_column(String(255))
    checked_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class ApiToken(Base):
    __tablename__ = "api_tokens"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    user_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("app_users.id", ondelete="CASCADE"))
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)  # sha256 hex
    name: Mapped[str] = mapped_column(String(255))
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class Proxy(Base):
    """A check vantage point: a SOCKS5 proxy, or the pseudo-proxy 'direct'
    (is_direct=True, no host) which connects from the panel itself.

    Visibility: only `enabled` proxies are usable; a non-public one
    (public_available=False) is offered to admins only. The password is stored
    so we can authenticate to the proxy, but is never rendered back to the UI."""
    __tablename__ = "proxies"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    name: Mapped[str] = mapped_column(String(255), unique=True)
    is_direct: Mapped[bool] = mapped_column(default=False)
    host: Mapped[str | None] = mapped_column(String(255))
    port: Mapped[int | None] = mapped_column()
    username: Mapped[str | None] = mapped_column(String(255))
    password: Mapped[str | None] = mapped_column(String(255))
    enabled: Mapped[bool] = mapped_column(default=True)
    public_available: Mapped[bool] = mapped_column(default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class ZoneSigning(Base):
    """Per-zone DNSSEC re-sign scheduler state. `due_at` is when the zone should
    next be serial-bumped so the dumb secondaries re-AXFR fresh RRSIGs; it's reset
    ~24h out whenever the zone's serial moves for any reason."""
    __tablename__ = "zone_signing"

    zone: Mapped[str] = mapped_column(String(255), primary_key=True)
    last_serial: Mapped[int | None] = mapped_column(BigInteger)
    due_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


engine = create_engine(settings().database_url, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)


def get_db():
    db: Session = SessionLocal()
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def log_history(db: Session, user_id: int | None, target_type: str, target: str | None, message: str) -> None:
    db.add(HistoryEntry(user_id=user_id, target_type=target_type, target=target, message=message))
    db.flush()
