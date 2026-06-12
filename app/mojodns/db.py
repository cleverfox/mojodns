from datetime import datetime

from sqlalchemy import BigInteger, DateTime, ForeignKey, String, Text, create_engine, func
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
    checked_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class ApiToken(Base):
    __tablename__ = "api_tokens"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    user_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("app_users.id", ondelete="CASCADE"))
    token: Mapped[str] = mapped_column(String(64), unique=True)
    note: Mapped[str | None] = mapped_column(String(255))
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


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
