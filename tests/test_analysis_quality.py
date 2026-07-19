from __future__ import annotations

import pytest

from cfdi_vault.analysis.quality import (
    QUALITY_CATEGORIES,
    QualityObservation,
    QualitySnapshot,
    snapshot_quality,
)
from cfdi_vault.domain import ReconciliationState


def _observation(**overrides: object) -> QualityObservation:
    values: dict[str, object] = {
        "metadata_present": False,
        "xml_present": False,
        "cancelled_metadata": False,
        "xml_conflict": False,
        "payment_expected": False,
        "payment_present": False,
        "parser_status": "complete",
        "reconciliation_state": ReconciliationState.STATE_CHECKED,
    }
    values.update(overrides)
    return QualityObservation(**values)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("overrides", "category"),
    [
        ({"metadata_present": True}, "metadata_without_xml"),
        ({"xml_present": True}, "xml_without_metadata"),
        ({"cancelled_metadata": True, "metadata_present": True, "xml_present": True}, "cancelled_with_xml"),
        ({"xml_conflict": True}, "duplicate_or_conflicting_xml"),
        ({"parser_status": "partial"}, "partial_parser"),
        ({"parser_status": "unsupported-error"}, "unsupported_parser"),
        ({"payment_expected": True}, "missing_payment_complement"),
        ({"reconciliation_state": ReconciliationState.XML_PENDING}, "uncertain_recovery"),
        ({"reconciliation_state": "service_window_exceeded"}, "expired_recovery"),
        ({"reconciliation_state": "UNKNOWN"}, "manual_review"),
        ({"reconciliation_state": ReconciliationState.FAILED_PERMANENT}, "failed_recovery"),
    ],
)
def test_quality_covers_each_documented_category(overrides: dict[str, object], category: str) -> None:
    snapshot = snapshot_quality([_observation(**overrides)])

    assert snapshot.count(category) == 1
    assert tuple(bucket.category for bucket in snapshot.buckets) == (category,)


def test_quality_allows_multiple_categories_without_row_details() -> None:
    observation = _observation(
        metadata_present=True,
        xml_conflict=True,
        payment_expected=True,
        parser_status="partial",
        reconciliation_state=ReconciliationState.RETRY_SCHEDULED,
    )

    snapshot = snapshot_quality([observation])

    assert snapshot.total_observations == 1
    assert snapshot.counts["metadata_without_xml"] == 1
    assert snapshot.counts["duplicate_or_conflicting_xml"] == 1
    assert snapshot.counts["missing_payment_complement"] == 1
    assert snapshot.counts["partial_parser"] == 1
    assert snapshot.counts["uncertain_recovery"] == 1
    assert all(value in QUALITY_CATEGORIES for value in snapshot.counts)


def test_one_observation_counts_each_category_once_and_order_is_fixed() -> None:
    observation = _observation(
        metadata_present=True,
        xml_conflict=True,
        payment_expected=True,
        parser_status="partial",
        reconciliation_state="retry-scheduled",
    )

    forward = snapshot_quality([observation, observation])
    reversed_input = snapshot_quality(reversed([observation, observation]))

    assert forward == reversed_input
    assert all(bucket.count == 2 for bucket in forward.buckets)
    positions = [QUALITY_CATEGORIES.index(bucket.category) for bucket in forward.buckets]
    assert positions == sorted(positions)


def test_existing_reconciliation_states_do_not_create_new_categories() -> None:
    snapshot = snapshot_quality(_observation(reconciliation_state=state) for state in ReconciliationState)

    assert set(snapshot.counts).issubset(set(QUALITY_CATEGORIES))
    assert snapshot.count("manual_review") == 0
    assert snapshot.count("unsupported_parser") == 0


def test_unknown_parser_and_reconciliation_statuses_fail_closed() -> None:
    snapshot = snapshot_quality([_observation(parser_status="UNKNOWN", reconciliation_state="not-a-domain-state")])

    assert snapshot.count("unsupported_parser") == 1
    assert snapshot.count("manual_review") == 1


def test_empty_snapshot_has_all_zero_counts_and_is_redacted() -> None:
    snapshot = snapshot_quality([])

    assert isinstance(snapshot, QualitySnapshot)
    assert snapshot.total_observations == 0
    assert snapshot.buckets == ()
    assert all(value == 0 for value in snapshot.counts.values())
    assert "complete" not in repr(_observation())
    assert "QualityObservation(<redacted>)" == repr(_observation())
    assert "QualitySnapshot(<redacted>)" == repr(snapshot)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("metadata_present", "yes", "quality-metadata_present-bool-required"),
        ("parser_status", None, "quality-parser-status-required"),
        ("reconciliation_state", 42, "quality-reconciliation-status-required"),
    ],
)
def test_quality_observation_validates_types(field: str, value: object, message: str) -> None:
    with pytest.raises(TypeError, match=message):
        QualityObservation(**{field: value})  # type: ignore[arg-type]


def test_snapshot_rejects_non_observations() -> None:
    with pytest.raises(TypeError, match="quality-observation-required"):
        snapshot_quality([object()])
    with pytest.raises(TypeError, match="quality-observations-required"):
        snapshot_quality(None)  # type: ignore[arg-type]
