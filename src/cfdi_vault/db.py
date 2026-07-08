"""PostgreSQL database setup and SQLAlchemy models for CFDI Vault MX."""

from __future__ import annotations

from collections.abc import Iterable
from datetime import datetime
from decimal import Decimal
import os

from sqlalchemy import DateTime, Numeric, String, create_engine, inspect
from sqlalchemy.engine import Engine, make_url
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


def create_engine_from_url(database_url: str | None = None) -> Engine:
    """Create a PostgreSQL SQLAlchemy engine.

    Set DATABASE_URL explicitly for CLI, workers, tests, and local Docker Compose
    runs. Only PostgreSQL URLs are supported.
    """

    resolved_url = database_url or os.getenv("DATABASE_URL")
    if not resolved_url:
        raise RuntimeError("PostgreSQL DATABASE_URL is required.")
    if not make_url(resolved_url).drivername.startswith("postgresql"):
        raise RuntimeError("Only PostgreSQL DATABASE_URL values are supported.")
    return create_engine(resolved_url, future=True)


def create_session_factory(engine: Engine) -> SessionFactory:
    """Create a SQLAlchemy session factory with stable post-commit objects."""

    return sessionmaker(bind=engine, autoflush=False, expire_on_commit=False, future=True)


def init_db(engine: Engine) -> None:
    """Validate that Flyway has created the vault schema."""

    ensure_tables_exist(engine, ("invoices",))


def ensure_tables_exist(engine: Engine, table_names: Iterable[str]) -> None:
    """Fail fast when a PostgreSQL database has not been bootstrapped by Flyway."""

    expected = set(table_names)
    existing = set(inspect(engine).get_table_names())
    missing = sorted(expected - existing)
    if missing:
        missing_list = ", ".join(missing)
        raise RuntimeError(
            "PostgreSQL schema is not initialized. Run Flyway migrations from "
            f"db/migration/ before starting CFDI Vault MX. Missing tables: {missing_list}."
        )
