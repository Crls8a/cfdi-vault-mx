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
from cfdi_vault.analysis.contextual_report import compose_contextual_report_bundle
from cfdi_vault.analysis.export import (
    export_contextual_private_csv,
    export_contextual_private_json,
    export_private_csv,
    export_private_json,
)
from cfdi_vault.analysis.monthly import MonthlyAggregate, MonthlyAnalysisReport
from cfdi_vault.analysis.payment_context import PaymentAnalysisRecord, summarize_payments_by_context
from cfdi_vault.analysis.payments import PaymentRecord
from cfdi_vault.analysis.payroll_accounting import PayrollSummaryReport, PayrollSummaryRow
from cfdi_vault.analysis.quality import QualityObservation, snapshot_quality
from cfdi_vault.analysis.quality_context import QualityAnalysisRecord, summarize_quality_by_context
from cfdi_vault.analysis.reporting import FinancialAnalysisReport
from cfdi_vault.analysis.tax_context import TaxAnalysisRecord, summarize_taxes_by_context
from cfdi_vault.analysis.taxes import TaxRecord


def _contextual_bundle():
    tax = TaxAnalysisRecord(
        date(2026, 1, 1),
        "received",
        "MXN",
        TaxRecord(
            tax_type="transferred",
            tax="002",
            factor_type="Tasa",
            rate_or_quota=Decimal("0.16"),
            base=Decimal("100"),
            amount=Decimal("16"),
            concept_ordinal=1,
            document_scope="concept",
            provenance="private-tax",
        ),
    )
    payment = PaymentAnalysisRecord(
        PaymentRecord(
            payment_date=datetime(2026, 1, 1, tzinfo=UTC),
            payment_form="03",
            currency="MXN",
            amount=Decimal("116"),
            exchange_rate=None,
            related_document_count=1,
            provenance="private-payment",
        ),
        "received",
    )
    quality = QualityAnalysisRecord(
        date(2026, 1, 1),
        QualityObservation(metadata_present=True, xml_present=True),
        "received",
        "MXN",
    )
    return compose_contextual_report_bundle(
        summarize_taxes_by_context((tax,)),
        summarize_payments_by_context((payment,)),
        summarize_quality_by_context((quality,)),
    )


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


def test_contextual_json_is_canonical_and_aggregate_only() -> None:
    bundle = _contextual_bundle()

    rendered = export_contextual_private_json(bundle)
    assert rendered == export_contextual_private_json(bundle)
    assert rendered == export_private_json(bundle)
    assert rendered.endswith("\n")
    payload = json.loads(rendered)
    assert payload["status"] == "complete"
    assert payload["period"] == {"start_month": "2026-01", "end_month": "2026-01"}
    assert set(payload) == {"status", "period", "taxes", "payments", "quality"}
    assert "private-tax" not in rendered and "private-payment" not in rendered
    assert "provenance" not in rendered and "raw_xml" not in rendered
    assert "uuid" not in rendered.lower() and "rfc" not in rendered.lower()
    assert '"taxes": {' not in rendered


def test_contextual_csv_has_fixed_columns_and_context_order() -> None:
    rendered = export_contextual_private_csv(_contextual_bundle())
    assert rendered == export_private_csv(_contextual_bundle())
    rows = list(csv.DictReader(io.StringIO(rendered)))

    assert rows[0]["section"] == "taxes"
    assert rows[0]["row_kind"] == "summary"
    assert rows[0]["metric"] == "rows"
    assert rows[1]["row_kind"] == "context"
    assert rows[2]["row_kind"] == "aggregate"
    assert rows[3]["section"] == "payments"
    assert rows[6]["section"] == "quality"
    assert rows[-1]["row_kind"] == "category"
    assert list(rows[0])[:6] == [
        "section",
        "row_kind",
        "status",
        "completeness",
        "month",
        "direction",
    ]
    assert "private-tax" not in rendered
    assert "hash" not in rendered.lower()


def test_contextual_export_rejects_wrong_type() -> None:
    with pytest.raises(TypeError, match="contextual-report-required"):
        export_contextual_private_json(object())  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="analysis-report-required"):
        export_private_json(object())  # type: ignore[arg-type]
