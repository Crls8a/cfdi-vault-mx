from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime
from decimal import Decimal

import pytest

from cfdi_vault.analysis.ledger_intent import (
    LedgerWriteContext,
    build_ledger_write_intent,
)
from cfdi_vault.analysis.normalization import ConceptRecord
from cfdi_vault.analysis.payments import PaymentRecord
from cfdi_vault.analysis.payroll import PayrollRecord
from cfdi_vault.analysis.projection import AccountingProjection
from cfdi_vault.analysis.taxes import TaxRecord


def _projection(*, completeness: str = "complete") -> AccountingProjection:
    concept = ConceptRecord(
        product_service_key="01010101",
        unit_key="H87",
        description="Synthetic service",
        quantity=Decimal("2"),
        unit_value=Decimal("10"),
        amount=Decimal("20"),
        discount=None,
        tax_object="02",
        ordinal=1,
        provenance="xml-a1b2c3d4e5f60718",
    )
    tax = TaxRecord(
        tax_type="transferred",
        tax="002",
        factor_type="Tasa",
        rate_or_quota=Decimal("0.16"),
        base=Decimal("20"),
        amount=Decimal("3.20"),
        concept_ordinal=1,
        document_scope="concept",
        provenance="xml-a1b2c3d4e5f60718",
    )
    payment = PaymentRecord(
        payment_date=datetime(2026, 1, 2, 12, tzinfo=UTC),
        payment_form="03",
        currency="MXN",
        amount=Decimal("23.20"),
        exchange_rate=None,
        related_document_count=1,
        provenance="xml-a1b2c3d4e5f60718",
    )
    payroll = PayrollRecord(
        payroll_type="O",
        payment_date=datetime(2026, 1, 2, 12, tzinfo=UTC),
        period_start=datetime(2025, 12, 16, tzinfo=UTC),
        period_end=datetime(2025, 12, 31, tzinfo=UTC),
        paid_days=Decimal("15"),
        total_perceptions=Decimal("100"),
        total_deductions=Decimal("20"),
        total_other_payments=Decimal("0"),
        perception_count=1,
        deduction_count=1,
        other_payment_count=0,
        incomplete_count=0,
        provenance="xml-a1b2c3d4e5f60718",
    )
    return AccountingProjection(
        source_ref="xml-aaaaaaaaaaaaaaaaaaaaaaaa",
        idempotency_key="accounting-v1-" + "a" * 64,
        concepts=(concept,),
        taxes=(tax,),
        payments=(payment,),
        payroll=(payroll,),
        parser_statuses={
            "concepts": "complete",
            "taxes": "complete",
            "payments": "complete",
            "payroll": "complete",
        },
        record_counts={"concepts": 1, "taxes": 1, "payments": 1, "payroll": 1},
        completeness=completeness,
    )


def test_build_intent_carries_all_families_and_hides_internal_values() -> None:
    intent = build_ledger_write_intent(
        _projection(),
        context=LedgerWriteContext(tenant_ref="tenant-test", work_ref="work-window"),
        normalization_generation="cfdi-v5",
    )

    assert len(intent.concepts) == 1
    assert len(intent.taxes) == 1
    assert len(intent.payments) == 1
    assert len(intent.payroll) == 1
    assert intent.source.record_counts["concepts"] == 1
    assert intent.normalization_generation == "cfdi-v5"
    public = intent.as_dict()
    assert public == {
        "completeness": "complete",
        "parser_statuses": {
            "concepts": "complete",
            "taxes": "complete",
            "payments": "complete",
            "payroll": "complete",
        },
        "record_counts": {"concepts": 1, "taxes": 1, "payments": 1, "payroll": 1},
    }
    rendered = repr(intent) + repr(public)
    rendered += repr(intent.source) + repr(intent.concepts[0]) + repr(intent.taxes[0])
    rendered += repr(intent.payments[0]) + repr(intent.payroll[0])
    assert "Synthetic service" not in rendered
    assert "tenant-test" not in rendered
    assert "xml-a1b2c3d4e5f60718" not in rendered
    assert "accounting-v1" not in rendered
    assert "ordinal" not in rendered
    assert "LedgerWriteIntent(" in rendered
    assert "<redacted>" in rendered
    assert "source_sha256" not in public
    assert "idempotency_key" not in public


def test_reprocessing_same_projection_context_and_generation_is_deterministic() -> None:
    context = LedgerWriteContext(tenant_ref="tenant-test", work_ref="work-window")
    first = build_ledger_write_intent(_projection(), context=context, normalization_generation="cfdi-v5")
    second = build_ledger_write_intent(_projection(), context=context, normalization_generation="cfdi-v5")

    assert first == second
    assert first.idempotency_key == second.idempotency_key
    assert first.concepts[0].idempotency_key == second.concepts[0].idempotency_key
    assert first.source.source_sha256 == "a" * 64


def test_context_or_generation_is_required_and_opaque() -> None:
    with pytest.raises(TypeError, match="ledger-intent-context-required"):
        build_ledger_write_intent(_projection(), context="tenant-test", normalization_generation="cfdi-v5")  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="ledger-intent-generation-required"):
        build_ledger_write_intent(
            _projection(),
            context=LedgerWriteContext(tenant_ref="tenant-test", work_ref="work-window"),
            normalization_generation="",
        )
    with pytest.raises(ValueError, match="ledger-intent-context-invalid"):
        LedgerWriteContext(tenant_ref="12345", work_ref="work-window")
    with pytest.raises(ValueError, match="ledger-intent-context-invalid"):
        LedgerWriteContext(tenant_ref="tenant/test", work_ref="work-window")


def test_generation_changes_keys_without_mutating_records() -> None:
    context = LedgerWriteContext(tenant_ref="tenant-test", work_ref="work-window")
    first = build_ledger_write_intent(_projection(), context=context, normalization_generation="cfdi-v5")
    second = build_ledger_write_intent(_projection(), context=context, normalization_generation="cfdi-v6")

    assert first.idempotency_key != second.idempotency_key
    assert first.concepts[0].idempotency_key != second.concepts[0].idempotency_key
    assert first.concepts[0].record == second.concepts[0].record


def test_unsupported_and_partial_projection_remain_write_intents_without_rows() -> None:
    unsupported = AccountingProjection(
        source_ref="xml-bbbbbbbbbbbbbbbbbbbbbbbb",
        idempotency_key="accounting-v1-" + "b" * 64,
        concepts=(),
        taxes=(),
        payments=(),
        payroll=(),
        parser_statuses={key: "unsupported-error" for key in ("concepts", "taxes", "payments", "payroll")},
        record_counts={key: 0 for key in ("concepts", "taxes", "payments", "payroll")},
        completeness="unsupported",
    )
    intent = build_ledger_write_intent(
        unsupported,
        context=LedgerWriteContext(tenant_ref="tenant-test", work_ref="work-window"),
        normalization_generation="cfdi-v5",
    )

    assert intent.completeness == "unsupported"
    assert intent.source.parser_statuses["concepts"] == "unsupported-error"
    assert intent.as_dict()["record_counts"] == {key: 0 for key in ("concepts", "taxes", "payments", "payroll")}

    partial_projection = replace(
        _projection(),
        parser_statuses={
            "concepts": "partial",
            "taxes": "complete",
            "payments": "complete",
            "payroll": "complete",
        },
        completeness="partial",
    )
    partial = build_ledger_write_intent(
        partial_projection,
        context=LedgerWriteContext(tenant_ref="tenant-test", work_ref="work-window"),
        normalization_generation="cfdi-v5",
    )
    assert partial.completeness == "partial"
    assert partial.as_dict()["record_counts"] == {key: 1 for key in ("concepts", "taxes", "payments", "payroll")}


def test_projection_type_and_duplicate_ordinals_are_rejected() -> None:
    with pytest.raises(TypeError, match="ledger-intent-projection-required"):
        build_ledger_write_intent(
            object(),  # type: ignore[arg-type]
            context=LedgerWriteContext(tenant_ref="tenant-test", work_ref="work-window"),
            normalization_generation="cfdi-v5",
        )
    projection = _projection()
    duplicate = ConceptRecord(
        product_service_key=projection.concepts[0].product_service_key,
        unit_key=projection.concepts[0].unit_key,
        description=projection.concepts[0].description,
        quantity=projection.concepts[0].quantity,
        unit_value=projection.concepts[0].unit_value,
        amount=projection.concepts[0].amount,
        discount=projection.concepts[0].discount,
        tax_object=projection.concepts[0].tax_object,
        ordinal=1,
        provenance=projection.concepts[0].provenance,
    )
    bad = AccountingProjection(
        source_ref=projection.source_ref,
        idempotency_key=projection.idempotency_key,
        concepts=(projection.concepts[0], duplicate),
        taxes=projection.taxes,
        payments=projection.payments,
        payroll=projection.payroll,
        parser_statuses=projection.parser_statuses,
        record_counts={"concepts": 2, "taxes": 1, "payments": 1, "payroll": 1},
        completeness="complete",
    )
    with pytest.raises(ValueError, match="ledger-intent-ordinal-duplicate"):
        build_ledger_write_intent(
            bad,
            context=LedgerWriteContext(tenant_ref="tenant-test", work_ref="work-window"),
            normalization_generation="cfdi-v5",
        )


def test_direct_intent_counts_must_match_family_tuples() -> None:
    intent = build_ledger_write_intent(
        _projection(),
        context=LedgerWriteContext(tenant_ref="tenant-test", work_ref="work-window"),
        normalization_generation="cfdi-v5",
    )
    with pytest.raises(ValueError, match="ledger-intent-counts-mismatch"):
        replace(intent, concepts=())
    with pytest.raises(ValueError, match="ledger-intent-completeness-mismatch"):
        replace(intent, completeness="partial")
    with pytest.raises(ValueError, match="ledger-intent-completeness-inconsistent"):
        replace(intent.source, completeness="partial")


def test_direct_replacements_cannot_reuse_keys_for_other_scope_or_generation() -> None:
    intent = build_ledger_write_intent(
        _projection(),
        context=LedgerWriteContext(tenant_ref="tenant-test", work_ref="work-window"),
        normalization_generation="cfdi-v5",
    )
    with pytest.raises(ValueError, match="ledger-intent-(?:source|batch)-key-mismatch"):
        replace(intent, context=LedgerWriteContext(tenant_ref="tenant-other", work_ref="work-window"))
    with pytest.raises(ValueError, match="ledger-intent-(?:source|batch)-key-mismatch"):
        replace(intent, normalization_generation="cfdi-v6")
    with pytest.raises(ValueError, match="ledger-intent-source-ref-mismatch"):
        replace(intent.source, source_sha256="b" * 64)
    changed_source = replace(intent.source, source_sha256="b" * 64, source_ref="xml-" + "b" * 24)
    with pytest.raises(ValueError, match="ledger-intent-source-key-mismatch"):
        replace(intent, source=changed_source)
    with pytest.raises(ValueError, match="ledger-intent-source-ref-mismatch"):
        replace(intent.source, source_ref="xml-" + "b" * 24)
    changed_concept = replace(intent.concepts[0], idempotency_key="ledger-v1-" + "c" * 64)
    with pytest.raises(ValueError, match="ledger-intent-family-key-mismatch"):
        replace(intent, concepts=(changed_concept,))
