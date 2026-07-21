from __future__ import annotations

from contextlib import contextmanager
from datetime import UTC, datetime
from decimal import Decimal

import pytest
from sqlalchemy.dialects import postgresql

from cfdi_vault.accounting_ledger_v5 import AccountingLedgerRepository
from cfdi_vault.accounting_ledger_v5_mapper import map_ledger_write_intent, map_ledger_write_intent_aggregate
from cfdi_vault.analysis.ledger_intent import LedgerWriteContext, build_ledger_write_intent
from cfdi_vault.analysis.normalization import ConceptRecord
from cfdi_vault.analysis.payments import PaymentRecord
from cfdi_vault.analysis.payroll import PayrollRecord
from cfdi_vault.analysis.projection import AccountingProjection
from cfdi_vault.analysis.taxes import TaxRecord


def _intent(*, related_document_count: int | None = 1):
    concept = ConceptRecord(
        product_service_key="01010101", unit_key="H87", description="Synthetic service",
        quantity=Decimal("1"), unit_value=Decimal("10"), amount=Decimal("10"),
        discount=None, tax_object="02", ordinal=1, provenance="xml-a1b2c3d4e5f60718",
    )
    tax = TaxRecord(
        tax_type="transferred", tax="002", factor_type="Tasa", rate_or_quota=Decimal("0.16"),
        base=Decimal("10"), amount=Decimal("1.60"), concept_ordinal=1,
        document_scope="concept", provenance="xml-a1b2c3d4e5f60718",
    )
    payment = PaymentRecord(
        payment_date=datetime(2026, 1, 2, tzinfo=UTC), payment_form="03", currency="MXN",
        amount=Decimal("11.60"), exchange_rate=None, related_document_count=related_document_count,
        provenance="xml-a1b2c3d4e5f60718",
    )
    payroll = PayrollRecord(
        payroll_type="O", payment_date=datetime(2026, 1, 2, tzinfo=UTC),
        period_start=datetime(2025, 12, 16, tzinfo=UTC), period_end=datetime(2025, 12, 31, tzinfo=UTC),
        paid_days=Decimal("15"), total_perceptions=Decimal("100"), total_deductions=Decimal("20"),
        total_other_payments=Decimal("0"), perception_count=1, deduction_count=1,
        other_payment_count=0, incomplete_count=0, provenance="xml-a1b2c3d4e5f60718",
    )
    projection = AccountingProjection(
        source_ref="xml-aaaaaaaaaaaaaaaaaaaaaaaa", idempotency_key="accounting-v1-" + "a" * 64,
        concepts=(concept,), taxes=(tax,), payments=(payment,), payroll=(payroll,),
        parser_statuses={name: "complete" for name in ("concepts", "taxes", "payments", "payroll")},
        record_counts={name: 1 for name in ("concepts", "taxes", "payments", "payroll")}, completeness="complete",
    )
    return build_ledger_write_intent(
        projection, context=LedgerWriteContext(tenant_ref="tenant-test", work_ref="work-window"),
        normalization_generation="cfdi-v5",
    )


class _Result:
    def __init__(self, rowcount: int = 1, rows: tuple[dict[str, int], ...] = ()) -> None:
        self.rowcount = rowcount
        self._rows = rows

    def all(self):  # type: ignore[no-untyped-def]
        return self._rows

    def first(self):  # type: ignore[no-untyped-def]
        return self._rows[0] if self._rows else None


class _Session:
    def __init__(self, *, binding_ok: bool = True) -> None:
        self.statements: list[object] = []
        self.concepts: dict[int, int] = {}
        self.next_id = 41
        self.commits = 0
        self.binding_ok = binding_ok

    def execute(self, statement):  # type: ignore[no-untyped-def]
        self.statements.append(statement)
        if getattr(statement, "is_select", False):
            if "cfdi_documents" in str(statement):
                return _Result(rows=(({"id": 7},) if self.binding_ok else ()))
            return _Result(rows=tuple({"id": value, "source_ordinal": ordinal} for ordinal, value in self.concepts.items()))
        params = statement.compile(dialect=postgresql.dialect()).params
        if "source_ordinal" in params and "description" in params:
            ordinal = params["source_ordinal"]
            if ordinal in self.concepts:
                return _Result(0)
            self.concepts[ordinal] = self.next_id
            self.next_id += 1
            return _Result(1, rows=({"id": self.concepts[ordinal]},))
        inserted = params.get("idempotency_key") not in self._keys(self.statements[:-1])
        return _Result(1, rows=({"id": self.next_id},)) if inserted else _Result(0)

    def _keys(self, statements: list[object]) -> set[str]:
        return {
            statement.compile(dialect=postgresql.dialect()).params.get("idempotency_key")
            for statement in statements
            if not getattr(statement, "is_select", False)
        }

    def commit(self) -> None:
        self.commits += 1

    def rollback(self) -> None:
        pass


class _Factory:
    def __init__(self, *, binding_ok: bool = True) -> None:
        self.session = _Session(binding_ok=binding_ok)
        self.sessions: list[_Session] = []

    @contextmanager
    def __call__(self):
        session = self.session
        self.sessions.append(session)
        yield session


def _map(repo: AccountingLedgerRepository):
    return map_ledger_write_intent(
        _intent(), repo, tenant_id="tenant-test", document_id=7, source_evidence_id=9, parser_version="parser-1"
    )


def test_mapper_writes_all_supported_families_once_and_omits_related_identity() -> None:
    factory = _Factory()
    first = _map(AccountingLedgerRepository(factory))

    assert first.aggregate.records_seen == 4
    assert first.aggregate.records_written == 4
    assert first.aggregate.concepts == first.aggregate.taxes == first.aggregate.payments == first.aggregate.payroll == 1
    assert first.aggregate.related == 0
    assert first.aggregate.unknown == 1
    assert first.reason_code == "related_identity_missing"
    assert factory.sessions[0].commits == 1
    sql = " ".join(str(statement.compile(dialect=postgresql.dialect())) for statement in factory.sessions[0].statements)
    assert "raw_payload" not in sql and "document_uuid" not in sql
    assert "source_evidence_id" in sql


def test_mapper_rerun_is_idempotent_and_tenant_bound() -> None:
    factory = _Factory()
    repo = AccountingLedgerRepository(factory)
    first = _map(repo)
    second = _map(repo)

    assert first.aggregate.records_written == 4
    assert second.aggregate.records_written == 0
    assert second.aggregate.duplicates == 4
    assert len(factory.sessions) == 2
    assert factory.sessions[0].commits == 2
    with pytest.raises(ValueError, match="tenant-context-mismatch"):
        map_ledger_write_intent(
            _intent(), repo, tenant_id="other-tenant", document_id=7, source_evidence_id=9, parser_version="parser-1"
        )


def test_mapper_keeps_unknown_related_count_without_claiming_missing_rows() -> None:
    factory = _Factory()
    result = map_ledger_write_intent(
        _intent(related_document_count=None),
        AccountingLedgerRepository(factory),
        tenant_id="tenant-test",
        document_id=7,
        source_evidence_id=9,
        parser_version="parser-1",
    )
    assert result.aggregate.unknown == 0
    assert result.reason_code is None


def test_mapper_rejects_unknown_tax_scope_without_sql_interpolation() -> None:
    intent = _intent()
    binding = intent.source
    values = {
        "tenant_id": "tenant-test", "document_id": 7, "source_evidence_id": 9,
        "source_sha256": binding.source_sha256, "parser_version": "parser-1",
        "parser_status": "complete", "normalization_generation": "cfdi-v5",
        "idempotency_key": intent.taxes[0].idempotency_key, "source_ordinal": 1,
        "tax_type": "transferred", "scope": "unsafe", "concept_id": None,
        "concept_ordinal": None, "amount": Decimal("1"),
    }
    with pytest.raises(ValueError, match="ledger-v5-tax-scope-invalid"):
        AccountingLedgerRepository(_Factory()).write_batch(
            (), (values,), (), (), binding=None
        )


def test_mapper_rejects_missing_document_evidence_binding_with_fixed_reason() -> None:
    with pytest.raises(ValueError, match="ledger-v5-provenance-binding-invalid"):
        _map(AccountingLedgerRepository(_Factory(binding_ok=False)))


def test_worker_adapter_returns_only_aggregate() -> None:
    aggregate = map_ledger_write_intent_aggregate(
        _intent(), AccountingLedgerRepository(_Factory()), tenant_id="tenant-test",
        document_id=7, source_evidence_id=9, parser_version="parser-1",
    )
    assert aggregate.records_written == 4
    assert not hasattr(aggregate, "reason_code")
