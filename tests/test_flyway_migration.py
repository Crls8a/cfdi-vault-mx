from __future__ import annotations

import re
from pathlib import Path

from cfdi_vault.db import Base
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
