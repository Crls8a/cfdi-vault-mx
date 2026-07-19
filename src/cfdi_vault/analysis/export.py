"""Render validated aggregate reports to private JSON/CSV text in memory."""

from __future__ import annotations

import csv
import io
import json
import re
from collections.abc import Iterator, Mapping
from datetime import UTC, date, datetime
from decimal import Decimal
from typing import Any

from cfdi_vault.analysis.contextual_report import ContextualReportBundle
from cfdi_vault.analysis.quality import QUALITY_CATEGORIES
from cfdi_vault.analysis.reporting import FinancialAnalysisReport

_STATUSES = frozenset({"complete", "partial", "empty", "unsupported"})
_SECTIONS = ("monthly", "taxes", "payments", "payroll", "quality")
_MONTH = re.compile(r"^[0-9]{4}-(?:0[1-9]|1[0-2])$")
_CURRENCY = re.compile(r"^(?:[A-Z]{3}|UNKNOWN)$")
_PAYMENT_FORM = re.compile(r"^(?:[0-9]{2}|UNKNOWN)$")
_DECIMAL = re.compile(r"^-?(?:0|[1-9]\d*)(?:\.\d+)?$")
_CSV_COLUMNS = (
    "section",
    "row_kind",
    "status",
    "completeness",
    "period_start",
    "period_end",
    "generated_at",
    "month",
    "direction",
    "currency",
    "payment_form",
    "payroll_type",
    "tax_type",
    "tax",
    "factor_type",
    "prior_month",
    "prior_available",
    "metric",
    "count",
    "record_count",
    "incomplete_count",
    "subtotal",
    "total",
    "cancelled_count",
    "metadata_count",
    "xml_count",
    "active_count",
    "unknown_status_count",
    "count_delta",
    "subtotal_delta",
    "total_delta",
    "cancelled_count_delta",
    "active_count_delta",
    "unknown_status_count_delta",
    "metadata_count_delta",
    "xml_count_delta",
    "base",
    "amount",
    "rate_or_quota",
    "related_document_count",
    "paid_days",
    "total_perceptions",
    "total_deductions",
    "total_other_payments",
    "total_observations",
)
_CONTEXTUAL_CSV_COLUMNS = (
    "section",
    "row_kind",
    "status",
    "completeness",
    "month",
    "direction",
    "currency",
    "payment_form",
    "tax_type",
    "tax",
    "factor_type",
    "metric",
    "count",
    "incomplete_count",
    "base",
    "amount",
    "rate_or_quota",
    "related_document_count",
    "total_observations",
    "category",
)

_SECTION_KEYS = {
    "monthly": frozenset({"status", "completeness", "rows", "trends"}),
    "taxes": frozenset({"status", "completeness", "incomplete_count", "rows"}),
    "payments": frozenset({"status", "completeness", "incomplete_count", "rows"}),
    "payroll": frozenset({"status", "completeness", "record_count", "incomplete_count", "rows"}),
    "quality": frozenset({"status", "completeness", "total_observations", "counts"}),
}
_ROW_KEYS = {
    "monthly": frozenset(
        {
            "month",
            "direction",
            "currency",
            "count",
            "subtotal",
            "total",
            "cancelled_count",
            "metadata_count",
            "xml_count",
            "active_count",
            "unknown_status_count",
        }
    ),
    "trend": frozenset(
        {
            "month",
            "direction",
            "currency",
            "prior_month",
            "prior_available",
            "count_delta",
            "subtotal_delta",
            "total_delta",
            "cancelled_count_delta",
            "active_count_delta",
            "unknown_status_count_delta",
            "metadata_count_delta",
            "xml_count_delta",
        }
    ),
    "taxes": frozenset(
        {"tax_type", "tax", "factor_type", "count", "base", "amount", "rate_or_quota", "incomplete_count"}
    ),
    "payments": frozenset(
        {"month", "currency", "payment_form", "count", "amount", "related_document_count", "incomplete_count"}
    ),
    "payroll": frozenset(
        {
            "month",
            "payroll_type",
            "count",
            "incomplete_count",
            "paid_days",
            "total_perceptions",
            "total_deductions",
            "total_other_payments",
        }
    ),
}


def export_private_json(report: FinancialAnalysisReport | ContextualReportBundle) -> str:
    """Return canonical ASCII JSON; reject wrong types or altered payloads."""

    if isinstance(report, ContextualReportBundle):
        return export_contextual_private_json(report)
    payload = _validated_payload(report)
    return json.dumps(payload, allow_nan=False, ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n"


def export_private_csv(report: FinancialAnalysisReport | ContextualReportBundle) -> str:
    """Return deterministic, fixed-schema CSV text without file effects."""

    if isinstance(report, ContextualReportBundle):
        return export_contextual_private_csv(report)
    payload = _validated_payload(report)
    output = io.StringIO(newline="")
    writer = csv.DictWriter(
        output,
        fieldnames=_CSV_COLUMNS,
        lineterminator="\n",
        quoting=csv.QUOTE_MINIMAL,
        extrasaction="raise",
    )
    writer.writeheader()
    for row in _csv_rows(payload):
        writer.writerow({column: row.get(column, "") for column in _CSV_COLUMNS})
    return output.getvalue()


def export_contextual_private_json(bundle: ContextualReportBundle) -> str:
    """Return canonical aggregate JSON for contextual tax/payment/quality views.

    The result contains only the validated bundle projection.  It never writes
    files or exposes source provenance, identifiers, paths, or fiscal rows.
    """

    payload = _validated_contextual_payload(bundle)
    return json.dumps(payload, allow_nan=False, ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n"


def export_contextual_private_csv(bundle: ContextualReportBundle) -> str:
    """Return deterministic fixed-schema CSV for contextual aggregates in memory."""

    payload = _validated_contextual_payload(bundle)
    output = io.StringIO(newline="")
    writer = csv.DictWriter(
        output,
        fieldnames=_CONTEXTUAL_CSV_COLUMNS,
        lineterminator="\n",
        quoting=csv.QUOTE_MINIMAL,
        extrasaction="raise",
    )
    writer.writeheader()
    for row in _contextual_csv_rows(payload):
        writer.writerow({column: row.get(column, "") for column in _CONTEXTUAL_CSV_COLUMNS})
    return output.getvalue()


def _validated_payload(report: FinancialAnalysisReport) -> dict[str, Any]:
    if not isinstance(report, FinancialAnalysisReport):
        raise TypeError("analysis-report-required")
    payload = report.as_dict()
    if not isinstance(payload, dict):
        raise TypeError("analysis-export-payload-invalid")
    _validate_payload(payload)
    return payload


def _validated_contextual_payload(bundle: ContextualReportBundle) -> dict[str, Any]:
    if not isinstance(bundle, ContextualReportBundle):
        raise TypeError("contextual-report-required")
    payload = bundle.as_dict()
    if not isinstance(payload, dict):
        raise TypeError("analysis-export-payload-invalid")
    _validate_contextual_payload(payload)
    return payload


def _validate_contextual_payload(payload: Mapping[str, Any]) -> None:
    _require_keys(payload, {"status", "period", "taxes", "payments", "quality"})
    _require_status(payload["status"])
    period = payload["period"]
    if not isinstance(period, dict) or set(period) != {"start_month", "end_month"}:
        raise ValueError("analysis-export-payload-invalid")
    for value in period.values():
        if value is not None:
            _require_text(value, pattern=_MONTH)
    if (period["start_month"] is None) != (period["end_month"] is None):
        raise ValueError("analysis-export-payload-invalid")

    for section in ("taxes", "payments"):
        value = payload[section]
        if not isinstance(value, dict) or set(value) != {"status", "contexts"}:
            raise ValueError("analysis-export-payload-invalid")
        _require_status(value["status"])
        _validate_contexts(value["contexts"], section)

    quality = payload["quality"]
    if not isinstance(quality, dict) or set(quality) != {"source_status", "completeness", "contexts"}:
        raise ValueError("analysis-export-payload-invalid")
    _require_status(quality["source_status"])
    _require_status(quality["completeness"])
    _validate_contexts(quality["contexts"], "quality")


def _validate_contexts(value: object, section: str) -> None:
    if not isinstance(value, list):
        raise TypeError("analysis-export-payload-invalid")
    for context in value:
        if not isinstance(context, dict):
            raise TypeError("analysis-export-payload-invalid")
        if section == "taxes":
            _require_keys(context, {"month", "direction", "currency", "status", "incomplete_count", "rows"})
            _validate_context_header(context, direction=True, currency=True)
            _require_int(context["incomplete_count"], nonnegative=True)
            _validate_rows(context["rows"], "taxes")
        elif section == "payments":
            _require_keys(
                context,
                {"month", "direction", "currency", "payment_form", "status", "incomplete_count", "rows"},
            )
            _validate_context_header(context, direction=True, currency=True, payment_form=True)
            _require_int(context["incomplete_count"], nonnegative=True)
            _validate_rows(context["rows"], "payments")
        else:
            allowed = {
                "month",
                "source_status",
                "completeness",
                "total_observations",
                "counts",
                "direction",
                "currency",
            }
            if not isinstance(context, dict) or not set(context).issubset(allowed):
                raise ValueError("analysis-export-payload-invalid")
            if set(context) - {"direction", "currency"} != {
                "month",
                "source_status",
                "completeness",
                "total_observations",
                "counts",
            }:
                raise ValueError("analysis-export-payload-invalid")
            _require_text(context["month"], pattern=_MONTH)
            _require_status(context["source_status"])
            _require_status(context["completeness"])
            for key in ("direction", "currency"):
                if key in context:
                    _require_text(
                        context[key],
                        choices={"received", "issued", "unknown"} if key == "direction" else None,
                        pattern=None if key == "direction" else _CURRENCY,
                    )
            _require_int(context["total_observations"], nonnegative=True)
            counts = context["counts"]
            if not isinstance(counts, dict) or tuple(counts) != QUALITY_CATEGORIES:
                raise ValueError("analysis-export-payload-invalid")
            for count in counts.values():
                _require_int(count, nonnegative=True)


def _validate_context_header(
    context: Mapping[str, Any], *, direction: bool = False, currency: bool = False, payment_form: bool = False
) -> None:
    _require_text(context["month"], pattern=_MONTH)
    if direction:
        _require_text(context["direction"], choices={"received", "issued", "unknown"})
    if currency:
        _require_text(context["currency"], pattern=_CURRENCY)
    if payment_form:
        _require_text(context["payment_form"], pattern=_PAYMENT_FORM)


def _validate_payload(payload: Mapping[str, Any]) -> None:
    _require_keys(payload, {"period", "generated_at", "section_statuses", "section_completeness", "sections"})
    period = payload["period"]
    if period is not None:
        if not isinstance(period, dict):
            raise TypeError("analysis-export-payload-invalid")
        _require_keys(period, {"start", "end"})
        for key in ("start", "end"):
            _require_date(period[key])
    generated_at = payload["generated_at"]
    if generated_at is not None:
        _require_generated_at(generated_at)
    sections = payload["sections"]
    if not isinstance(sections, dict) or set(sections) not in (
        {"monthly", "taxes", "payments", "quality"},
        {"monthly", "taxes", "payments", "payroll", "quality"},
    ):
        raise ValueError("analysis-export-payload-invalid")
    for key in ("section_statuses", "section_completeness"):
        values = payload[key]
        if not isinstance(values, dict) or set(values) != set(sections):
            raise ValueError("analysis-export-payload-invalid")
        for value in values.values():
            _require_status(value)
    for section, value in sections.items():
        _validate_section(section, value)
        if (
            payload["section_statuses"][section] != value["status"]
            or payload["section_completeness"][section] != value["completeness"]
        ):
            raise ValueError("analysis-export-payload-invalid")


def _validate_section(section: str, value: object) -> None:
    if not isinstance(value, dict):
        raise TypeError("analysis-export-payload-invalid")
    _require_keys(value, set(_SECTION_KEYS[section]))
    _require_status(value["status"])
    _require_status(value["completeness"])
    if section == "monthly":
        _validate_rows(value["rows"], "monthly")
        _validate_rows(value["trends"], "trend")
    elif section in {"taxes", "payments", "payroll"}:
        _require_int(value["incomplete_count"], nonnegative=True)
        if section == "payroll":
            _require_int(value["record_count"], nonnegative=True)
        _validate_rows(value["rows"], section)
    else:
        _require_int(value["total_observations"], nonnegative=True)
        counts = value["counts"]
        if not isinstance(counts, dict) or tuple(counts) != QUALITY_CATEGORIES:
            raise ValueError("analysis-export-payload-invalid")
        for count in counts.values():
            _require_int(count, nonnegative=True)


def _validate_rows(value: object, kind: str) -> None:
    if not isinstance(value, list):
        raise TypeError("analysis-export-payload-invalid")
    for row in value:
        if not isinstance(row, dict):
            raise TypeError("analysis-export-payload-invalid")
        _require_keys(row, set(_ROW_KEYS[kind]))
        _validate_row_values(kind, row)


def _validate_row_values(kind: str, row: Mapping[str, Any]) -> None:
    if kind in {"monthly", "trend", "payments", "payroll"}:
        _require_text(row["month"], pattern=_MONTH)
    if kind in {"monthly", "trend"}:
        _require_text(row["direction"], choices={"received", "issued", "unknown"})
        _require_text(row["currency"], pattern=_CURRENCY)
    if kind == "monthly":
        _require_int(row["count"], nonnegative=True)
        _require_decimal(row["subtotal"])
        _require_decimal(row["total"])
        for key in ("cancelled_count", "metadata_count", "xml_count", "active_count", "unknown_status_count"):
            _require_int(row[key], nonnegative=True)
    elif kind == "trend":
        _require_text(row["prior_month"], pattern=_MONTH)
        _require_bool(row["prior_available"])
        for key in (
            "count_delta",
            "cancelled_count_delta",
            "active_count_delta",
            "unknown_status_count_delta",
            "metadata_count_delta",
            "xml_count_delta",
        ):
            _require_int(row[key], optional=True)
        for key in ("subtotal_delta", "total_delta"):
            _require_decimal(row[key], optional=True)
    elif kind == "taxes":
        _require_text(row["tax_type"], choices={"transferred", "withheld", "UNKNOWN"})
        _require_text(row["tax"], choices={"001", "002", "003", "UNKNOWN"})
        _require_text(row["factor_type"], choices={"Tasa", "Cuota", "Exento", "UNKNOWN"})
        _require_int(row["count"], nonnegative=True)
        _require_int(row["incomplete_count"], nonnegative=True)
        for key in ("base", "amount", "rate_or_quota"):
            _require_decimal(row[key], optional=True)
    elif kind == "payments":
        _require_text(row["currency"], pattern=_CURRENCY)
        _require_text(row["payment_form"], pattern=_PAYMENT_FORM)
        _require_int(row["count"], nonnegative=True)
        _require_int(row["related_document_count"], nonnegative=True)
        _require_int(row["incomplete_count"], nonnegative=True)
        _require_decimal(row["amount"], optional=True)
    else:
        _require_text(row["payroll_type"], choices={"O", "E", "UNKNOWN"})
        _require_int(row["count"], nonnegative=True)
        _require_int(row["incomplete_count"], nonnegative=True)
        for key in ("paid_days", "total_perceptions", "total_deductions", "total_other_payments"):
            _require_decimal(row[key], optional=True)


def _require_keys(value: Mapping[str, Any], expected: set[str]) -> None:
    if set(value) != expected:
        raise ValueError("analysis-export-payload-invalid")


def _require_status(value: object) -> None:
    if type(value) is not str or value not in _STATUSES:
        raise ValueError("analysis-export-payload-invalid")


def _require_text(value: object, *, choices: set[str] | None = None, pattern: re.Pattern[str] | None = None) -> None:
    if (
        not isinstance(value, str)
        or (choices is not None and value not in choices)
        or (pattern is not None and pattern.fullmatch(value) is None)
    ):
        raise ValueError("analysis-export-payload-invalid")


def _require_int(value: object, *, nonnegative: bool = False, optional: bool = False) -> None:
    if optional and value is None:
        return
    if type(value) is not int or (nonnegative and value < 0):
        raise TypeError("analysis-export-payload-invalid")


def _require_bool(value: object) -> None:
    if type(value) is not bool:
        raise TypeError("analysis-export-payload-invalid")


def _require_decimal(value: object, *, optional: bool = False) -> None:
    if optional and value is None:
        return
    if not isinstance(value, str) or _DECIMAL.fullmatch(value) is None:
        raise ValueError("analysis-export-payload-invalid")
    try:
        parsed = Decimal(value)
    except Exception as exc:
        raise ValueError("analysis-export-payload-invalid") from exc
    if not parsed.is_finite() or format(parsed, "f") != value:
        raise ValueError("analysis-export-payload-invalid")


def _require_date(value: object) -> None:
    if not isinstance(value, str):
        raise ValueError("analysis-export-payload-invalid")
    try:
        parsed = date.fromisoformat(value)
    except ValueError as exc:
        raise ValueError("analysis-export-payload-invalid") from exc
    if parsed.isoformat() != value:
        raise ValueError("analysis-export-payload-invalid")


def _require_generated_at(value: object) -> None:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ValueError("analysis-export-payload-invalid")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise ValueError("analysis-export-payload-invalid") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != UTC.utcoffset(parsed):
        raise ValueError("analysis-export-payload-invalid")
    if parsed.astimezone(UTC).isoformat().replace("+00:00", "Z") != value:
        raise ValueError("analysis-export-payload-invalid")


def _csv_rows(payload: Mapping[str, Any]) -> Iterator[dict[str, Any]]:
    period = payload["period"] or {}
    context = {
        "period_start": period.get("start", ""),
        "period_end": period.get("end", ""),
        "generated_at": payload["generated_at"] or "",
    }
    statuses = payload["section_statuses"]
    completeness = payload["section_completeness"]
    sections = payload["sections"]
    for section in _SECTIONS:
        if section not in sections:
            continue
        base = {"section": section, "status": statuses[section], "completeness": completeness[section], **context}
        value = sections[section]
        summary = {**base, "row_kind": "summary"}
        if section == "monthly":
            summary.update({"metric": "rows", "count": sum(row["count"] for row in value["rows"])})
            yield summary
            for row in value["rows"]:
                yield {**base, "row_kind": "aggregate", **row}
            for row in value["trends"]:
                yield {**base, "row_kind": "trend", **row}
        elif section in {"taxes", "payments"}:
            summary.update(
                {
                    "metric": "rows",
                    "count": sum(row["count"] for row in value["rows"]),
                    "incomplete_count": value["incomplete_count"],
                }
            )
            yield summary
            for row in value["rows"]:
                yield {**base, "row_kind": "aggregate", **row}
        elif section == "payroll":
            summary.update(
                {
                    "metric": "records",
                    "record_count": value["record_count"],
                    "incomplete_count": value["incomplete_count"],
                }
            )
            yield summary
            for row in value["rows"]:
                yield {**base, "row_kind": "aggregate", **row}
        else:
            summary.update({"metric": "observations", "total_observations": value["total_observations"]})
            yield summary
            for category in QUALITY_CATEGORIES:
                yield {**base, "row_kind": "category", "metric": category, "count": value["counts"][category]}


def _contextual_csv_rows(payload: Mapping[str, Any]) -> Iterator[dict[str, Any]]:
    for section in ("taxes", "payments", "quality"):
        value = payload[section]
        status = value.get("status", value.get("source_status"))
        completeness = value.get("completeness", status)
        contexts = value["contexts"]
        base = {"section": section, "status": status, "completeness": completeness}
        if section in {"taxes", "payments"}:
            count = sum(row["count"] for context in contexts for row in context["rows"])
            yield {**base, "row_kind": "summary", "metric": "rows", "count": count}
            for context in contexts:
                context_base = {**base, "row_kind": "context", **_context_dimensions(context)}
                context_base["incomplete_count"] = context["incomplete_count"]
                yield context_base
                for row in context["rows"]:
                    yield {**context_base, "row_kind": "aggregate", **row}
            continue

        total = sum(context["total_observations"] for context in contexts)
        yield {**base, "row_kind": "summary", "metric": "observations", "total_observations": total}
        for context in contexts:
            context_base = {
                **base,
                "row_kind": "context",
                **_context_dimensions(context),
                "total_observations": context["total_observations"],
            }
            yield context_base
            for category in QUALITY_CATEGORIES:
                yield {
                    **context_base,
                    "row_kind": "category",
                    "category": category,
                    "count": context["counts"][category],
                }


def _context_dimensions(context: Mapping[str, Any]) -> dict[str, Any]:
    return {key: context[key] for key in ("month", "direction", "currency", "payment_form") if key in context}
