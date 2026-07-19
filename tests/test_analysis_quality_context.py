from __future__ import annotations

from datetime import UTC, datetime, timedelta, timezone

import pytest

from cfdi_vault.analysis.quality import QUALITY_CATEGORIES, QualityObservation, snapshot_quality
from cfdi_vault.analysis.quality_context import (
    QualityAnalysisRecord,
    QualityContextReport,
    QualityContextSummary,
    summarize_quality_by_context,
)
from cfdi_vault.domain import ReconciliationState


def _observation(**overrides: object) -> QualityObservation:
    values: dict[str, object] = {"reconciliation_state": ReconciliationState.STATE_CHECKED}
    values.update(overrides)
    return QualityObservation(**values)  # type: ignore[arg-type]


def _record(when: datetime, *, direction: str | None = None, currency: str | None = None, **overrides: object):
    return QualityAnalysisRecord(when, _observation(**overrides), direction, currency)


def test_groups_by_utc_month_and_explicit_dimensions() -> None:
    report = summarize_quality_by_context(
        [
            _record(
                datetime(2026, 1, 30, 23, 30, tzinfo=timezone(timedelta(hours=-2))),
                direction="received",
                currency="mxn",
                metadata_present=True,
            ),
            _record(datetime(2026, 1, 15, 12, tzinfo=UTC), direction="received", currency="MXN", xml_conflict=True),
            _record(datetime(2026, 2, 5, 12, tzinfo=UTC)),
        ]
    )
    assert report.source_status == report.completeness == "complete"
    assert [(item.month, item.direction, item.currency) for item in report.contexts] == [
        ("2026-01", "received", "MXN"),
        ("2026-02", None, None),
    ]
    assert report.contexts[0].snapshot.count("metadata_without_xml") == 1
    assert report.contexts[0].snapshot.count("duplicate_or_conflicting_xml") == 1


def test_omitted_dimensions_are_not_inferred_or_emitted() -> None:
    report = summarize_quality_by_context(
        [
            _record(datetime(2026, 1, 1, tzinfo=UTC), direction="issued"),
            _record(datetime(2026, 1, 2, tzinfo=UTC)),
        ]
    )
    assert [(item.direction, item.currency) for item in report.contexts] == [(None, None), ("issued", None)]
    omitted, supplied = report.as_dict()["contexts"]
    assert "direction" not in omitted and "currency" not in omitted
    assert supplied["direction"] == "issued" and "currency" not in supplied
    assert repr(report) == "QualityContextReport(<redacted>)"


def test_fixed_categories_status_and_redaction() -> None:
    report = summarize_quality_by_context(
        [_record(datetime(2026, 1, 1, tzinfo=UTC), parser_status="partial")], source_status="partial"
    )
    context = report.contexts[0].as_dict()
    assert (
        report.source_status == report.completeness == context["source_status"] == context["completeness"] == "partial"
    )
    assert set(context["counts"]) == set(QUALITY_CATEGORIES)
    assert context["counts"]["partial_parser"] == context["total_observations"] == 1
    assert repr(report.contexts[0]) == "QualityContextSummary(<redacted>)"


@pytest.mark.parametrize("status", ["complete", "partial", "unsupported"])
def test_explicit_status_is_preserved(status: str) -> None:
    report = summarize_quality_by_context([_record(datetime(2026, 1, 1, tzinfo=UTC))], source_status=status)
    assert report.source_status == report.completeness == report.contexts[0].source_status == status


def test_empty_report_and_existing_snapshot() -> None:
    empty = summarize_quality_by_context([], source_status="complete")
    assert isinstance(empty, QualityContextReport) and empty.contexts == ()
    assert empty.as_dict() == {"source_status": "empty", "completeness": "empty", "contexts": []}
    snapshot = snapshot_quality([_observation(xml_present=True)])
    summary = QualityContextSummary("2026-01", None, None, snapshot, "complete")
    assert summary.snapshot is snapshot and summary.as_dict()["counts"]["xml_without_metadata"] == 1
    assert "complete" not in repr(summary.snapshot)


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"observed_at": "2026-01-01", "observation": _observation()}, "quality-context-date-invalid"),
        (
            {"observed_at": datetime(2026, 1, 1, tzinfo=UTC), "observation": object()},
            "quality-context-observation-required",
        ),
        (
            {"observed_at": datetime(2026, 1, 1, tzinfo=UTC), "observation": _observation(), "direction": "out"},
            "quality-context-direction-invalid",
        ),
        (
            {"observed_at": datetime(2026, 1, 1, tzinfo=UTC), "observation": _observation(), "currency": "pesos"},
            "quality-context-currency-invalid",
        ),
    ],
)
def test_record_validates_explicit_input(kwargs: dict[str, object], message: str) -> None:
    with pytest.raises((TypeError, ValueError), match=message):
        QualityAnalysisRecord(**kwargs)  # type: ignore[arg-type]


def test_bounds_status_and_record_types_fail_closed() -> None:
    with pytest.raises(ValueError, match="analysis-period-invalid"):
        summarize_quality_by_context([], start=datetime(2026, 2, 1, tzinfo=UTC), end=datetime(2026, 1, 1, tzinfo=UTC))
    with pytest.raises(ValueError, match="analysis-source-status-invalid"):
        summarize_quality_by_context([], source_status="invented")
    with pytest.raises(TypeError, match="quality-context-records-required"):
        summarize_quality_by_context(None)  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="quality-context-record-required"):
        summarize_quality_by_context([object()])
