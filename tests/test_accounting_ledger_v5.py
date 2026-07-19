from __future__ import annotations

from contextlib import contextmanager
from decimal import Decimal

import pytest
from sqlalchemy.dialects import postgresql

from cfdi_vault.accounting_ledger_v5 import (
    AccountingLedgerRepository,
    ConceptWrite,
    EvidenceRef,
    PaymentWrite,
    aggregate_statement,
)


# fmt: off
def _evidence(**overrides: object) -> EvidenceRef:
    values = {
        "tenant_id": "tenant-synthetic",
        "document_id": 7,
        "source_evidence_id": 9,
        "source_sha256": "a" * 64,
        "parser_version": "parser-1",
        "parser_status": "complete",
        "normalization_generation": "v5",
        "idempotency_key": "ledger-v1-" + "b" * 64,
    }
    values.update(overrides)
    return EvidenceRef(**values)
def test_evidence_ref_rejects_unsafe_provenance() -> None:
    with pytest.raises(ValueError, match="ledger-v5-source-hash-invalid"):
        _evidence(source_sha256="A" * 64)
    with pytest.raises(ValueError, match="ledger-v5-ordinal-required"):
        ConceptWrite(evidence=_evidence(), source_ordinal=0, description="service")
    with pytest.raises(ValueError, match="ledger-v5-raw-payload-forbidden"):
        ConceptWrite(evidence=_evidence(), source_ordinal=1, description="service", raw_payload={})
def test_payment_exchange_rate_is_not_invented() -> None:
    with pytest.raises(ValueError, match="ledger-v5-exchange-rate-required"):
        PaymentWrite(evidence=_evidence(), payment_ordinal=1, currency="USD")
    with pytest.raises(ValueError, match="ledger-v5-exchange-rate-forbidden"):
        PaymentWrite(evidence=_evidence(), payment_ordinal=1, currency="MXN", exchange_rate=Decimal("1"))
def test_insert_statement_targets_exact_identity_and_no_raw_payload() -> None:
    row = ConceptWrite(evidence=_evidence(), source_ordinal=1, description="service", amount=Decimal("10"))
    factory = _FakeFactory()
    inserted = AccountingLedgerRepository(factory).insert_concept(row)
    assert inserted is True
    compiled = str(factory.session.statement.compile(dialect=postgresql.dialect()))
    assert "ON CONFLICT (tenant_id, document_id, source_sha256, normalization_generation, source_ordinal)" in compiled
    assert "raw_payload" not in compiled
def test_aggregate_statement_selects_only_sanitized_aggregates() -> None:
    sql = str(aggregate_statement("tenant-synthetic").compile(dialect=postgresql.dialect()))
    assert "count" in sql.lower() and "sum" in sql.lower()
    assert "raw_payload" not in sql and "uuid" not in sql and "rfc" not in sql
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
class _FakeFactory:
    def __init__(self) -> None:
        self.session = _Session()
    @contextmanager
    def __call__(self):
        yield self.session
