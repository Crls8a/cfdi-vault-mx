from __future__ import annotations

import re
from pathlib import Path

MIGRATION = Path("db/migration/V5__accounting_ledger.sql")


def _sql() -> str:
    return MIGRATION.read_text(encoding="utf-8")


def _normalized_sql() -> str:
    return re.sub(r"\s+", " ", _sql())


def test_v5_migration_is_additive_and_has_manual_rollback() -> None:
    migration = _sql()
    executable = "\n".join(
        line for line in migration.splitlines() if not line.lstrip().startswith("--")
    )

    assert "ALTER TABLE cfdi_documents" in executable
    assert "ALTER TABLE xml_evidence" in executable
    assert "CREATE TABLE" not in executable
    assert not re.search(r"\b(DROP|TRUNCATE|DELETE)\b", executable, re.IGNORECASE)
    assert "Manual rollback" in migration
    assert "V1–V4" in migration

def test_v5_adds_tenant_evidence_provenance_to_each_ledger() -> None:
    normalized = _normalized_sql()
    tables = {
        "cfdi_concepts": (
            "tenant_id",
            "source_evidence_id",
            "source_sha256",
            "source_ordinal",
            "normalization_generation",
            "idempotency_key",
        ),
        "cfdi_taxes": (
            "tenant_id",
            "document_id",
            "source_evidence_id",
            "source_sha256",
            "source_ordinal",
            "normalization_generation",
            "idempotency_key",
        ),
        "cfdi_payments": (
            "tenant_id",
            "document_id",
            "source_evidence_id",
            "source_sha256",
            "payment_ordinal",
            "normalization_generation",
            "idempotency_key",
        ),
        "cfdi_payroll": (
            "tenant_id",
            "document_id",
            "source_evidence_id",
            "source_sha256",
            "payroll_ordinal",
            "normalization_generation",
            "idempotency_key",
        ),
        "cfdi_related_documents": (
            "tenant_id",
            "document_id",
            "source_evidence_id",
            "source_sha256",
            "related_ordinal",
            "normalization_generation",
            "idempotency_key",
        ),
    }
    for table, columns in tables.items():
        assert f"ALTER TABLE {table}" in normalized
        for column in columns:
            assert f"ADD COLUMN {column} " in normalized, (table, column)

    assert "uq_cfdi_documents_tenant_id UNIQUE (tenant_id, id)" in normalized
    assert "uq_xml_evidence_tenant_id UNIQUE (tenant_id, id)" in normalized
    assert "uq_cfdi_concepts_tenant_id UNIQUE (tenant_id, id)" in normalized
    assert "uq_cfdi_concepts_tenant_id_document UNIQUE (tenant_id, id, document_id)" in normalized


def test_v5_enforces_scoped_identity_and_provenance_checks() -> None:
    normalized = _normalized_sql()
    for index_name in (
        "uq_cfdi_concepts_v5_identity",
        "uq_cfdi_taxes_v5_concept_identity",
        "uq_cfdi_taxes_v5_document_identity",
        "uq_cfdi_payments_v5_identity",
        "uq_cfdi_payroll_v5_identity",
        "uq_cfdi_related_documents_v5_identity",
    ):
        assert f"CREATE UNIQUE INDEX {index_name}" in normalized

    assert "WHERE scope = 'concept'" in normalized
    assert "WHERE scope = 'document'" in normalized
    assert "scope = 'document' AND concept_id IS NULL" in normalized
    assert "scope = 'concept' AND concept_id IS NOT NULL" in normalized
    assert "scope = 'document' AND concept_id IS NULL AND concept_ordinal IS NULL" in normalized
    assert "scope = 'concept' AND concept_id IS NOT NULL AND concept_ordinal > 0" in normalized
    assert "scope IS NOT NULL" in normalized
    assert "source_sha256 ~ '^[0-9a-f]{64}$'" in normalized
    assert "source_ordinal IS NULL OR source_ordinal > 0" in normalized
    assert "normalization_generation IS NULL OR length(normalization_generation) BETWEEN 1 AND 64" in normalized
    assert "idempotency_key IS NULL OR length(idempotency_key) BETWEEN 1 AND 192" in normalized
    for table in (
        "concepts",
        "taxes",
        "payments",
        "payroll",
        "related",
    ):
        assert f"ck_cfdi_{table}_v5_required" in normalized


def test_v5_uses_same_tenant_composite_foreign_keys_and_payment_rules() -> None:
    normalized = _normalized_sql()
    assert "FOREIGN KEY (tenant_id, document_id) REFERENCES cfdi_documents (tenant_id, id)" in normalized
    assert "FOREIGN KEY (tenant_id, source_evidence_id) REFERENCES xml_evidence (tenant_id, id)" in normalized
    assert "FOREIGN KEY (tenant_id, concept_id, document_id) REFERENCES cfdi_concepts (tenant_id, id, document_id)" in normalized
    assert "currency IS NULL OR (currency = 'MXN' AND exchange_rate IS NULL)" in normalized
    assert "currency <> 'MXN' AND exchange_rate IS NOT NULL AND exchange_rate > 0" in normalized
    assert "NOT VALID" in normalized
    assert "payment_ordinal IS NULL OR payment_ordinal > 0" in normalized


def test_v5_related_and_payroll_identities_match_approved_scope_rules() -> None:
    normalized = _normalized_sql()
    assert "uq_cfdi_related_documents_v5_identity" in normalized
    assert "uq_cfdi_related_documents_v5_payment_identity" in normalized
    assert "payment_ordinal, related_ordinal" in normalized
    assert "ck_cfdi_related_v5_payment_identity" in normalized
    assert "WHERE payment_ordinal IS NULL" in normalized
    assert "WHERE payment_ordinal IS NOT NULL" in normalized
    assert "uq_cfdi_payroll_v5_identity" in normalized
    assert "payroll_ordinal" in normalized
    assert "source_ordinal" not in normalized.split("ALTER TABLE cfdi_payroll", 1)[1].split(
        "ALTER TABLE cfdi_related_documents", 1
    )[0]


def test_v5_documents_legacy_standalone_fk_transition() -> None:
    migration = _sql().lower()
    assert "legacy standalone" in migration
    assert "backfill" in migration
    assert "validate composite" in migration


def test_v5_does_not_add_payload_or_artifact_bytes() -> None:
    migration = _sql().upper()
    assert "BYTEA" not in migration
    assert "ADD COLUMN RAW_PAYLOAD" not in migration
    assert "ADD COLUMN XML" not in migration
    assert "ADD COLUMN ZIP" not in migration
