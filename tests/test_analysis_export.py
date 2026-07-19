from __future__ import annotations

import csv
import io
import json
from datetime import UTC, date, datetime
from decimal import Decimal

import pytest

from cfdi_vault.analysis.accounting import (
    PaymentSummaryReport,
    PaymentSummaryRow,
    TaxSummaryReport,
    TaxSummaryRow,
)
from cfdi_vault.analysis.export import export_private_csv, export_private_json
from cfdi_vault.analysis.monthly import MonthlyAggregate, MonthlyAnalysisReport
from cfdi_vault.analysis.payroll_accounting import PayrollSummaryReport, PayrollSummaryRow
from cfdi_vault.analysis.quality import QualityObservation, snapshot_quality
from cfdi_vault.analysis.reporting import FinancialAnalysisReport


def _report(*, payroll: PayrollSummaryReport | None = None) -> FinancialAnalysisReport:
    return FinancialAnalysisReport(
        monthly=MonthlyAnalysisReport(
            rows=(MonthlyAggregate("2026-01", "received", "MXN", 2, Decimal("10"), Decimal("11.60"), 0, 1, 1),)
        ),
        taxes=TaxSummaryReport(
            rows=(TaxSummaryRow("transferred", "002", "Tasa", 1, Decimal("10"), Decimal("1.60"), Decimal(".16")),),
            source_status="complete",
        ),
        payments=PaymentSummaryReport(
            rows=(PaymentSummaryRow("2026-01", "MXN", "03", 1, Decimal("11.60"), 1),),
            source_status="complete",
        ),
        quality=snapshot_quality([QualityObservation(metadata_present=True, xml_present=True)]),
        period=(date(2026, 1, 1), date(2026, 1, 31)),
        generated_at=datetime(2026, 2, 1, 12, tzinfo=UTC),
        payroll=payroll,
    )


def _payroll(status: str = "complete") -> PayrollSummaryReport:
    rows = (
        ()
        if status in {"empty", "unsupported"}
        else (PayrollSummaryRow("2026-01", "O", 1, 0, Decimal("1"), Decimal("2"), Decimal(".5"), Decimal(".2")),)
    )
    return PayrollSummaryReport(rows, status, 0, 1 if rows else 0)


def test_json_is_canonical_and_contains_only_aggregate_sections() -> None:
    report = _report(payroll=_payroll())
    first = export_private_json(report)
    assert first == export_private_json(_report(payroll=_payroll()))
    assert first.endswith("\n")
    assert "RFC" not in first and "uuid" not in first.lower()
    assert "provenance" not in first and "raw_xml" not in first
    assert "hash" not in first.lower() and "storage" not in first.lower()
    assert isinstance(json.loads(first), dict)
    assert "".join(first.splitlines()).find('": {') == -1


def test_csv_has_fixed_columns_and_section_order() -> None:
    rendered = export_private_csv(_report(payroll=_payroll()))
    rows = list(csv.DictReader(io.StringIO(rendered)))
    assert rows[0]["section"] == "monthly"
    assert rows[0]["row_kind"] == "summary"
    assert rows[1]["section"] == "monthly"
    assert rows[2]["section"] == "taxes"
    assert rows[4]["section"] == "payments"
    assert rows[6]["section"] == "payroll"
    assert rows[-1]["section"] == "quality"
    assert list(rows[0])[:7] == [
        "section",
        "row_kind",
        "status",
        "completeness",
        "period_start",
        "period_end",
        "generated_at",
    ]
    assert "xml_count" in rows[0] and "raw_xml" not in rows[0]
    assert "hash" not in rendered.lower()


@pytest.mark.parametrize("status", ["partial", "empty", "unsupported"])
def test_csv_keeps_partial_empty_and_unsupported_sections(status: str) -> None:
    report = FinancialAnalysisReport(
        monthly=MonthlyAnalysisReport(rows=()),
        taxes=TaxSummaryReport(rows=(), source_status=status),
        payments=PaymentSummaryReport(rows=(), source_status=status),
        quality=snapshot_quality([]),
    )
    rendered = export_private_csv(report)
    rows = list(csv.DictReader(io.StringIO(rendered)))
    section_status = {(row["section"], row["status"]) for row in rows if row["row_kind"] == "summary"}
    assert ("monthly", "empty") in section_status
    assert ("taxes", status) in section_status
    assert ("payments", status) in section_status
    assert ("quality", "empty") in section_status


def test_legacy_report_without_payroll_remains_compatible() -> None:
    report = _report()
    payload = json.loads(export_private_json(report))
    csv_text = export_private_csv(report)
    assert "payroll" not in payload["sections"]
    assert "payroll" not in {row["section"] for row in csv.DictReader(io.StringIO(csv_text))}


def test_export_rejects_wrong_type_and_payload_with_private_provenance() -> None:
    with pytest.raises(TypeError, match="analysis-report-required"):
        export_private_json(object())  # type: ignore[arg-type]

    class MalformedReport(FinancialAnalysisReport):
        def as_dict(self) -> dict[str, object]:
            payload = super().as_dict()
            payload["sections"]["taxes"]["provenance"] = "private"  # type: ignore[index]
            return payload

    with pytest.raises(ValueError, match="analysis-export-payload-invalid"):
        base = _report()
        malformed = MalformedReport(
            base.monthly,
            base.taxes,
            base.payments,
            base.quality,
            base.period,
            base.generated_at,
            base.payroll,
        )
        export_private_json(malformed)


@pytest.mark.parametrize("case", ["rfc", "path", "date", "generated", "count", "decimal", "payment", "status"])
def test_export_fails_closed_for_adversarial_overridden_payload(case: str) -> None:
    base = _report()

    class MalformedReport(FinancialAnalysisReport):
        def as_dict(self) -> dict[str, object]:
            payload = super().as_dict()
            monthly = payload["sections"]["monthly"]  # type: ignore[index]
            if case == "rfc":
                monthly["rows"][0]["direction"] = "RFCABC010101AAA"  # type: ignore[index]
            elif case == "path":
                monthly["rows"][0]["currency"] = "C:/private"  # type: ignore[index]
            elif case == "date":
                payload["period"]["start"] = "2026-02-31"  # type: ignore[index]
            elif case == "generated":
                payload["generated_at"] = "2026-02-01T12:00:00-06:00"
            elif case == "count":
                monthly["rows"][0]["count"] = 1.5  # type: ignore[index]
            elif case == "decimal":
                monthly["rows"][0]["total"] = "NaN"  # type: ignore[index]
            elif case == "payment":
                payload["sections"]["payments"]["rows"][0]["payment_form"] = "３"  # type: ignore[index]
            else:
                payload["section_statuses"]["taxes"] = "empty"  # type: ignore[index]
            return payload

    malformed = MalformedReport(
        base.monthly,
        base.taxes,
        base.payments,
        base.quality,
        base.period,
        base.generated_at,
        base.payroll,
    )
    with pytest.raises((TypeError, ValueError), match="analysis-export-payload-invalid"):
        export_private_json(malformed)
    with pytest.raises((TypeError, ValueError), match="analysis-export-payload-invalid"):
        export_private_csv(malformed)


def test_export_does_not_create_files(tmp_path) -> None:
    before = tuple(tmp_path.iterdir())
    export_private_json(_report())
    export_private_csv(_report())
    assert tuple(tmp_path.iterdir()) == before
