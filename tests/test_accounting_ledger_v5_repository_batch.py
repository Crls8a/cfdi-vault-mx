from __future__ import annotations

from contextlib import contextmanager
from decimal import Decimal

import pytest

from cfdi_vault.accounting_ledger_v5 import AccountingLedgerRepository, ConceptWrite, EvidenceRef


def _evidence() -> EvidenceRef:
    return EvidenceRef(
        tenant_id="tenant-test", document_id=7, source_evidence_id=9, source_sha256="a" * 64,
        parser_version="parser-1", parser_status="complete", normalization_generation="cfdi-v5",
        idempotency_key="ledger-v1-" + "b" * 64,
    )


class _Result:
    rowcount = 1

    def __init__(self, *, valid: bool = True) -> None:
        self.valid = valid

    def first(self):  # type: ignore[no-untyped-def]
        return {"id": 7} if self.valid else None


class _Session:
    def __init__(self, *, binding_ok: bool = True) -> None:
        self.binding_ok = binding_ok
        self.commits = 0
        self.statements: list[object] = []

    def execute(self, statement):  # type: ignore[no-untyped-def]
        self.statements.append(statement)
        return _Result(valid=self.binding_ok) if getattr(statement, "is_select", False) else _Result()

    def commit(self) -> None:
        self.commits += 1

    def rollback(self) -> None:
        pass


class _Factory:
    def __init__(self, *, binding_ok: bool = True) -> None:
        self.session = _Session(binding_ok=binding_ok)

    @contextmanager
    def __call__(self):
        yield self.session


def test_write_batch_verifies_binding_and_commits_once() -> None:
    factory = _Factory()
    result = AccountingLedgerRepository(factory).write_batch(
        (ConceptWrite(_evidence(), 1, "Synthetic service", Decimal("10")),), (), (), (), binding=_evidence()
    )
    assert result.concepts == 1
    assert result.duplicates == 0
    assert factory.session.commits == 1
    assert any("cfdi_documents" in str(statement) for statement in factory.session.statements)


def test_write_batch_rejects_unknown_tax_scope_before_insert() -> None:
    evidence = _evidence()
    values = {
        "tenant_id": evidence.tenant_id, "document_id": evidence.document_id,
        "source_evidence_id": evidence.source_evidence_id, "source_sha256": evidence.source_sha256,
        "parser_version": evidence.parser_version, "parser_status": evidence.parser_status,
        "normalization_generation": evidence.normalization_generation,
        "idempotency_key": evidence.idempotency_key, "source_ordinal": 1,
        "tax_type": "transferred", "scope": "unsafe", "concept_id": None,
        "concept_ordinal": None, "amount": Decimal("1"),
    }
    with pytest.raises(ValueError, match="ledger-v5-tax-scope-invalid"):
        AccountingLedgerRepository(_Factory()).write_batch((), (values,), (), (), binding=evidence)


def test_write_batch_rejects_missing_parent_binding_without_rows() -> None:
    with pytest.raises(ValueError, match="ledger-v5-provenance-binding-invalid"):
        AccountingLedgerRepository(_Factory(binding_ok=False)).write_batch((), (), (), (), binding=_evidence())
