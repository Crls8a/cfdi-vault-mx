from __future__ import annotations

from datetime import UTC, datetime
from decimal import Decimal

import pytest

from cfdi_vault.analysis.payments import PaymentRecord
from cfdi_vault.analysis.projection import AccountingProjection
from cfdi_vault.analysis.projection_quality import quality_observation_from_projection
from cfdi_vault.analysis.quality import snapshot_quality
from cfdi_vault.domain import ReconciliationState


def _projection(completeness: str = "complete", *, with_payment: bool = False) -> AccountingProjection:
    payment_records: tuple[PaymentRecord, ...] = ()
    if with_payment:
        payment_records = (
            PaymentRecord(
                payment_date=datetime(2026, 1, 15, 12, tzinfo=UTC),
                payment_form="03",
                currency="MXN",
                amount=Decimal("10.00"),
                exchange_rate=None,
                related_document_count=1,
                provenance="xml-" + "a" * 24,
            ),
        )
    statuses = {"concepts": "empty", "taxes": "empty", "payments": "empty", "payroll": "empty"}
    statuses["payments"] = "complete" if with_payment else "empty"
    records = {"concepts": (), "taxes": (), "payments": payment_records, "payroll": ()}
    return AccountingProjection(
        source_ref="xml-" + "a" * 24,
        idempotency_key="accounting-v1-" + "a" * 64,
        concepts=records["concepts"],
        taxes=records["taxes"],
        payments=records["payments"],
        payroll=records["payroll"],
        parser_statuses=statuses,
        record_counts={name: len(values) for name, values in records.items()},
        completeness=completeness,
    )


@pytest.mark.parametrize(
    ("completeness", "expected"),
    [("complete", "complete"), ("empty", "empty"), ("partial", "partial"), ("unsupported", "unsupported-error")],
)
def test_projection_completeness_maps_without_inference(completeness: str, expected: str) -> None:
    observation = quality_observation_from_projection(_projection(completeness), metadata_present=True)

    assert observation.xml_present is True
    assert observation.metadata_present is True
    assert observation.parser_status == expected.replace("-", "_")


def test_metadata_presence_is_explicit_and_xml_presence_is_always_true() -> None:
    without_metadata = quality_observation_from_projection(_projection(), metadata_present=False)
    with_metadata = quality_observation_from_projection(_projection(), metadata_present=True)

    assert snapshot_quality([without_metadata]).count("xml_without_metadata") == 1
    assert snapshot_quality([with_metadata]).count("xml_without_metadata") == 0
    with pytest.raises(TypeError):
        quality_observation_from_projection(_projection())  # type: ignore[call-arg]


def test_payment_presence_comes_only_from_projection_records() -> None:
    absent = quality_observation_from_projection(_projection(), metadata_present=True, payment_expected=True)
    present = quality_observation_from_projection(
        _projection(with_payment=True), metadata_present=True, payment_expected=True
    )

    assert absent.payment_present is False
    assert present.payment_present is True
    assert snapshot_quality([absent]).count("missing_payment_complement") == 1
    assert snapshot_quality([present]).count("missing_payment_complement") == 0


def test_unavailable_payment_evidence_is_preserved_without_false_finding() -> None:
    observation = quality_observation_from_projection(
        _projection(), metadata_present=True, payment_expected=True, payment_evidence_available=False
    )

    assert observation.payment_evidence_available is False
    assert snapshot_quality([observation]).count("missing_payment_complement") == 0


def test_explicit_cancellation_conflict_and_recovery_state_are_not_inferred() -> None:
    observation = quality_observation_from_projection(
        _projection(),
        metadata_present=True,
        cancelled_metadata=True,
        xml_conflict=True,
        reconciliation_state="service_window_exceeded",
    )

    snapshot = snapshot_quality([observation])
    assert snapshot.count("cancelled_with_xml") == 1
    assert snapshot.count("duplicate_or_conflicting_xml") == 1
    assert snapshot.count("expired_recovery") == 1


def test_reconciliation_enum_is_passed_explicitly() -> None:
    observation = quality_observation_from_projection(
        _projection(), metadata_present=True, reconciliation_state=ReconciliationState.RETRY_SCHEDULED
    )

    assert observation.reconciliation_state == "retry_scheduled"
    assert snapshot_quality([observation]).count("uncertain_recovery") == 1


@pytest.mark.parametrize("value", [None, object(), "not-a-projection"])
def test_projection_type_is_validated(value: object) -> None:
    with pytest.raises(TypeError, match="projection-quality-projection-required"):
        quality_observation_from_projection(value, metadata_present=True)  # type: ignore[arg-type]


@pytest.mark.parametrize("field", ["metadata_present", "cancelled_metadata", "xml_conflict", "payment_expected"])
def test_quality_input_boolean_types_are_delegated_to_strict_contract(field: str) -> None:
    kwargs = {field: "yes"}
    if field != "metadata_present":
        kwargs["metadata_present"] = True
    with pytest.raises(TypeError, match=f"quality-{field}-bool-required"):
        quality_observation_from_projection(_projection(), **kwargs)  # type: ignore[arg-type]


def test_observation_is_aggregate_only_and_redacted() -> None:
    observation = quality_observation_from_projection(
        _projection(with_payment=True), metadata_present=True, reconciliation_state=ReconciliationState.STATE_CHECKED
    )

    rendered = repr(observation)
    assert rendered == "QualityObservation(<redacted>)"
    assert "xml-" not in rendered
    assert "accounting-v1" not in rendered
    assert "10.00" not in rendered
    assert "UUID" not in rendered
    assert "RFC" not in rendered


def test_bridge_keeps_reconciliation_explicit_and_payment_presence_derived() -> None:
    observation = quality_observation_from_projection(_projection(), metadata_present=True)

    assert observation.reconciliation_state == "discovered_in_metadata"
    assert observation.payment_present is False
