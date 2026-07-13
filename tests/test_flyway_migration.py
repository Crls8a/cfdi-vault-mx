from __future__ import annotations

import re
from pathlib import Path
from typing import Callable

import pytest
from sqlalchemy import inspect

from cfdi_vault.db import Base, create_engine_from_url, init_db
from cfdi_vault.recovery_db import init_recovery_schema
import cfdi_vault.recovery_db  # noqa: F401


def test_postgres_fixture_runner_discovers_all_migrations_in_version_order(
    tmp_path: Path,
    migration_paths: Callable[[Path], tuple[Path, ...]],
) -> None:
    for filename in (
        "V10__later.sql",
        "V2__evidence_indexes.sql",
        "V1__baseline.sql",
        "README.md",
    ):
        (tmp_path / filename).write_text("-- synthetic migration", encoding="utf-8")

    assert [path.name for path in migration_paths(tmp_path)] == [
        "V1__baseline.sql",
        "V2__evidence_indexes.sql",
        "V10__later.sql",
    ]


def test_flyway_migrations_declare_all_orm_tables_and_indexes(
    migration_paths: Callable[[Path], tuple[Path, ...]],
) -> None:
    migrations = migration_paths(Path("db/migration"))
    baseline = migrations[0].read_text(encoding="utf-8")
    all_migrations = "\n".join(path.read_text(encoding="utf-8") for path in migrations)

    for table_name in Base.metadata.tables:
        assert re.search(rf"\bCREATE TABLE {re.escape(table_name)}\b", baseline), table_name

    for table in Base.metadata.tables.values():
        for index in table.indexes:
            assert re.search(rf"\bINDEX {re.escape(index.name or '')}\b", all_migrations), index.name


def test_initial_flyway_migration_uses_postgresql_jsonb_payloads() -> None:
    migration = Path("db/migration/V1__initial_postgresql_schema.sql").read_text(encoding="utf-8")

    assert "raw_payload JSONB NOT NULL" in migration
    assert "payload JSONB NOT NULL" in migration
    assert "raw_response JSONB NOT NULL" in migration


def test_evidence_index_migration_is_additive_and_query_driven() -> None:
    migration = Path("db/migration/V2__evidence_query_indexes.sql").read_text(
        encoding="utf-8"
    )
    executable_sql = "\n".join(
        line for line in migration.splitlines() if not line.strip().startswith("--")
    )
    expected_indexes = {
        "ix_xml_evidence_tenant_storage_key",
        "ix_xml_evidence_tenant_sha256",
        "ix_xml_evidence_tenant_parser_created",
        "ix_cfdi_documents_tenant_parser_updated",
        "ix_cfdi_metadata_ledger_tenant_reconciliation_last_seen",
        "ix_download_jobs_tenant_status_updated",
        "ix_queue_job_events_job_created",
    }

    for index_name in expected_indexes:
        assert f"CREATE INDEX {index_name}" in migration
    assert "DROP " not in executable_sql.upper()
    assert "ALTER TABLE" not in executable_sql.upper()
    assert "BYTEA" not in executable_sql.upper()


@pytest.mark.integration
def test_flyway_baseline_satisfies_runtime_schema_validation(reset_postgres_database: str) -> None:
    engine = create_engine_from_url(reset_postgres_database)
    try:
        init_db(engine)
        init_recovery_schema(engine)
    finally:
        engine.dispose()


@pytest.mark.integration
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
