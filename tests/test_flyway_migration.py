from __future__ import annotations

import re
from pathlib import Path

import pytest
from sqlalchemy import inspect

from cfdi_vault.db import Base, create_engine_from_url, init_db
from cfdi_vault.recovery_db import init_recovery_schema
import cfdi_vault.recovery_db  # noqa: F401


def test_initial_flyway_migration_declares_all_orm_tables_and_indexes() -> None:
    migration = Path("db/migration/V1__initial_postgresql_schema.sql").read_text(encoding="utf-8")

    for table_name in Base.metadata.tables:
        assert re.search(rf"\bCREATE TABLE {re.escape(table_name)}\b", migration), table_name

    for table in Base.metadata.tables.values():
        for index in table.indexes:
            assert re.search(rf"\bINDEX {re.escape(index.name or '')}\b", migration), index.name


def test_initial_flyway_migration_uses_postgresql_jsonb_payloads() -> None:
    migration = Path("db/migration/V1__initial_postgresql_schema.sql").read_text(encoding="utf-8")

    assert "raw_payload JSONB NOT NULL" in migration
    assert "payload JSONB NOT NULL" in migration
    assert "raw_response JSONB NOT NULL" in migration


def test_flyway_baseline_satisfies_runtime_schema_validation(reset_postgres_database: str) -> None:
    engine = create_engine_from_url(reset_postgres_database)
    try:
        init_db(engine)
        init_recovery_schema(engine)
    finally:
        engine.dispose()


def test_runtime_schema_validation_does_not_bootstrap_empty_database(reset_postgres_database: str) -> None:
    engine = create_engine_from_url(reset_postgres_database)
    try:
        with engine.begin() as connection:
            connection.exec_driver_sql("DROP SCHEMA IF EXISTS public CASCADE")
            connection.exec_driver_sql("CREATE SCHEMA public")

        with pytest.raises(RuntimeError, match="Run Flyway migrations"):
            init_db(engine)
        with pytest.raises(RuntimeError, match="Run Flyway migrations"):
            init_recovery_schema(engine)

        assert inspect(engine).get_table_names() == []
    finally:
        engine.dispose()
