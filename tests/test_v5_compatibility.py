from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
from decimal import Decimal
from pathlib import Path

import pytest
from sqlalchemy import text
from sqlalchemy.dialects import postgresql

from cfdi_vault.accounting_ledger_v5 import (
    AccountingLedgerRepository,
    ConceptWrite,
    EvidenceRef,
    PaymentWrite,
    TaxWrite,
)
from cfdi_vault.db import create_engine_from_url, create_session_factory

MIGRATION = Path("db/migration/V5__accounting_ledger.sql")


def _values() -> dict[str, object]:
    return {
        "tenant_id": "tenant-synthetic",
        "document_id": 7,
        "source_evidence_id": 9,
        "source_sha256": "a" * 64,
        "parser_version": "parser-1",
        "parser_status": "complete",
        "normalization_generation": "v5",
        "idempotency_key": "ledger-v1-" + "b" * 64,
    }


class _Result:
    rowcount = 1


class _Session:
    def __init__(self) -> None:
        self.statement = None

    def execute(self, statement: object) -> _Result:
        self.statement = statement
        return _Result()

    def commit(self) -> None:
        pass

    def rollback(self) -> None:
        pass


class _Factory:
    def __init__(self) -> None:
        self.session = _Session()

    @contextmanager
    def __call__(self):
        yield self.session


def test_v5_makes_legacy_payload_and_uuid_columns_nullable() -> None:
    sql = MIGRATION.read_text(encoding="utf-8")
    for table, columns in {
        "cfdi_concepts": ("raw_payload",),
        "cfdi_payments": ("document_uuid", "raw_payload"),
        "cfdi_payroll": ("document_uuid", "raw_payload"),
        "cfdi_taxes": ("document_uuid",),
        "cfdi_related_documents": ("document_uuid",),
    }.items():
        table_sql = next(line for line in sql.splitlines() if line.startswith(f"ALTER TABLE {table} ALTER COLUMN"))
        for column in columns:
            assert f"ALTER COLUMN {column} DROP NOT NULL" in table_sql


def test_generic_v5_insert_allowlist_excludes_legacy_fields() -> None:
    factory = _Factory()
    values = _values() | {"payroll_ordinal": 1, "source_net_amount": None}
    assert AccountingLedgerRepository(factory).insert_payroll(values) is True
    compiled = str(factory.session.statement.compile(dialect=postgresql.dialect()))
    assert "raw_payload" not in compiled and "document_uuid" not in compiled
    with pytest.raises(ValueError, match="ledger-v5-field-forbidden"):
        AccountingLedgerRepository(factory).insert_payroll(values | {"id": 1})


def test_tax_insert_keeps_required_type_and_concept_scope() -> None:
    factory = _Factory()
    row = TaxWrite(EvidenceRef(**_values()), 1, "VAT", "concept", concept_id=3, concept_ordinal=1)
    assert AccountingLedgerRepository(factory).insert_tax(row) is True
    compiled = str(factory.session.statement.compile(dialect=postgresql.dialect()))
    assert "tax_type" in compiled and "concept_id" in compiled


def test_payment_insert_uses_v5_columns_only() -> None:
    factory = _Factory()
    row = PaymentWrite(EvidenceRef(**_values()), 1, currency="MXN")
    assert AccountingLedgerRepository(factory).insert_payment(row) is True
    compiled = str(factory.session.statement.compile(dialect=postgresql.dialect()))
    assert "document_uuid" not in compiled and "raw_payload" not in compiled


@pytest.mark.integration
def test_v5_all_child_writers_and_aggregate_on_postgres(reset_postgres_database: str) -> None:
    engine = create_engine_from_url(reset_postgres_database)
    now = datetime.now(timezone.utc)
    with engine.begin() as connection:
        connection.execute(
            text("INSERT INTO tenants (id, name, rfc, created_at) VALUES (:id, :name, :rfc, :created_at)"),
            {"id": "tenant-v5-integration", "name": "Synthetic Tenant", "rfc": "SYNTHETIC", "created_at": now},
        )
        document_id = connection.execute(
            text("""INSERT INTO cfdi_documents
            (tenant_id, uuid, download_state, parser_status, search_text, raw_payload, created_at, updated_at)
            VALUES (:tenant_id, :uuid, 'downloaded', 'complete', '', '{}'::jsonb, :now, :now)
            RETURNING id"""),
            {"tenant_id": "tenant-v5-integration", "uuid": "synthetic-doc-v5", "now": now},
        ).scalar_one()
        evidence_id = connection.execute(
            text("""INSERT INTO xml_evidence
            (tenant_id, uuid, xml_sha256, size_bytes, storage_key, parser_version, parser_status, created_at)
            VALUES (:tenant_id, :uuid, :sha, 1, 'synthetic/evidence.xml', 'parser-1', 'complete', :now)
            RETURNING id"""),
            {"tenant_id": "tenant-v5-integration", "uuid": "synthetic-doc-v5", "sha": "a" * 64, "now": now},
        ).scalar_one()

    factory = create_session_factory(engine)
    repo = AccountingLedgerRepository(factory)
    evidence = EvidenceRef(
        "tenant-v5-integration",
        document_id,
        evidence_id,
        "a" * 64,
        "parser-1",
        "complete",
        "v5",
        "ledger-v1-" + "b" * 64,
    )
    assert repo.insert_concept(ConceptWrite(evidence, 1, "synthetic service"))
    with engine.connect() as connection:
        concept_id = connection.execute(
            text("SELECT id FROM cfdi_concepts WHERE document_id = :document_id"), {"document_id": document_id}
        ).scalar_one()
    assert repo.insert_tax(TaxWrite(evidence, 1, "VAT", "concept", concept_id=concept_id, concept_ordinal=1))
    assert repo.insert_payment(PaymentWrite(evidence, 1, currency="MXN"))
    assert repo.insert_payroll(
        {
            **_values(),
            "tenant_id": "tenant-v5-integration",
            "document_id": document_id,
            "source_evidence_id": evidence_id,
            "payroll_ordinal": 1,
            "source_net_amount": Decimal("10"),
        }
    )
    assert repo.insert_related(
        {
            **_values(),
            "tenant_id": "tenant-v5-integration",
            "document_id": document_id,
            "source_evidence_id": evidence_id,
            "related_ordinal": 1,
            "related_uuid": "synthetic-related-v5",
        }
    )
    summary = repo.aggregate("tenant-v5-integration")
    assert (
        summary.concept_count,
        summary.tax_count,
        summary.payment_count,
        summary.payroll_count,
        summary.related_count,
    ) == (1, 1, 1, 1, 1)
    engine.dispose()


def test_related_mapping_requires_positive_ordinal_and_private_identity() -> None:
    factory = _Factory()
    values = _values() | {"related_ordinal": 1, "related_uuid": "related-synthetic"}
    assert AccountingLedgerRepository(factory).insert_related(values) is True
    with pytest.raises(ValueError, match="ledger-v5-related-ordinal-required"):
        AccountingLedgerRepository(factory).insert_related(values | {"related_ordinal": 0})
    with pytest.raises(ValueError, match="ledger-v5-related-identity-required"):
        AccountingLedgerRepository(factory).insert_related(values | {"related_uuid": ""})
