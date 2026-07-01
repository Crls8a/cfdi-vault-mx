"""Database setup and SQLAlchemy models for CFDI Vault MX."""

from __future__ import annotations

from datetime import datetime
from decimal import Decimal
from pathlib import Path

from sqlalchemy import DateTime, Numeric, String, create_engine
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker


class Base(DeclarativeBase):
    """Base class for vault ORM models."""


class Invoice(Base):
    """A normalized synthetic CFDI document imported into the vault."""

    __tablename__ = "invoices"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    uuid: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    issuer_rfc: Mapped[str] = mapped_column(String(32), nullable=False)
    issuer_name: Mapped[str] = mapped_column(String(256), nullable=False)
    receiver_rfc: Mapped[str] = mapped_column(String(32), nullable=False)
    receiver_name: Mapped[str] = mapped_column(String(256), nullable=False)
    issue_date: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    subtotal: Mapped[Decimal] = mapped_column(Numeric(18, 6), nullable=False)
    total: Mapped[Decimal] = mapped_column(Numeric(18, 6), nullable=False)
    currency: Mapped[str] = mapped_column(String(8), nullable=False)
    comprobante_type: Mapped[str] = mapped_column(String(8), nullable=False)
    payment_method: Mapped[str | None] = mapped_column(String(16), nullable=True)
    payment_form: Mapped[str | None] = mapped_column(String(16), nullable=True)
    xml_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    source_name: Mapped[str] = mapped_column(String(512), nullable=False)
    imported_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


SessionFactory = sessionmaker[object]


def create_sqlite_engine(db_path: str | Path) -> Engine:
    """Create a SQLite engine for a local database path."""

    if str(db_path) == ":memory:":
        return create_engine("sqlite+pysqlite:///:memory:", future=True)

    path = Path(db_path).expanduser().resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    return create_engine(f"sqlite+pysqlite:///{path.as_posix()}", future=True)


def create_engine_from_url(database_url: str | None = None, *, sqlite_path: str | Path | None = None) -> Engine:
    """Create an engine from a URL, defaulting to the local SQLite vault.

    The recovery architecture is PostgreSQL-first for durable deployments, but
    tests and local examples still need a dependency-light SQLite path.
    """

    if database_url:
        return create_engine(database_url, future=True)
    return create_sqlite_engine(sqlite_path or "cfdi-vault.sqlite3")


def create_session_factory(engine: Engine) -> SessionFactory:
    """Create a SQLAlchemy session factory with stable post-commit objects."""

    return sessionmaker(bind=engine, autoflush=False, expire_on_commit=False, future=True)


def init_db(engine: Engine) -> None:
    """Create the vault schema if it does not exist."""

    Base.metadata.create_all(engine)
