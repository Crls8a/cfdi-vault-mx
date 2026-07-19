from __future__ import annotations

from contextlib import contextmanager
from datetime import date, datetime, timedelta, timezone
from decimal import Decimal
from types import SimpleNamespace

import pytest
from sqlalchemy.dialects import postgresql

from cfdi_vault.analysis.postgres import (
    MonthlyAnalysisPostgresAdapter,
    monthly_records_statement,
)


class _Result:
    def __init__(self, rows: list[object]) -> None:
        self._rows = rows

    def all(self) -> list[object]:
        return self._rows


class _Session:
    def __init__(self, rows: list[object]) -> None:
        self.rows = rows
        self.statement = None

    def execute(self, statement: object) -> _Result:
        self.statement = statement
        return _Result(self.rows)


def _factory(rows: list[object]) -> tuple[object, _Session]:
    session = _Session(rows)

    @contextmanager
    def open_session():
        yield session

    return open_session, session


def _row(**values: object) -> SimpleNamespace:
    return SimpleNamespace(**values)


def test_adapter_keeps_metadata_without_document_and_maps_xml_fields() -> None:
    factory, _ = _factory(
        [
            _row(
                direction="received",
                issue_date=datetime(2026, 1, 14, 23, 30, tzinfo=timezone(timedelta(hours=-6))),
                metadata_effect="E",
                metadata_total=Decimal("120.00"),
                metadata_status="Vigente",
                xml_backed=False,
                document_currency="EUR",
                document_subtotal=Decimal("100.00"),
                document_total=Decimal("110.00"),
                document_status="Cancelado",
            ),
            _row(
                direction="issued",
                issue_date=datetime(2026, 1, 15, 2, 0, tzinfo=timezone.utc),
                metadata_effect="I",
                metadata_total=Decimal("999.00"),
                metadata_status="Vigente",
                xml_backed=True,
                document_currency="USD",
                document_subtotal=Decimal("10.00"),
                document_total=Decimal("12.00"),
                document_status="Cancelado",
            ),
        ]
    )
    adapter = MonthlyAnalysisPostgresAdapter(factory)

    records = adapter.records_for_period("tenant", start=date(2026, 1, 14), end=date(2026, 1, 15))

    assert records[0].source_kind == "metadata"
    assert records[0].currency == "UNKNOWN"
    assert records[0].subtotal is None
    assert records[0].total == Decimal("120.00")
    assert records[0].issue_date == date(2026, 1, 15)
    assert records[0].effect == "E"
    assert records[0].document_type is None
    assert records[1].source_kind == "xml"
    assert records[1].currency == "USD"
    assert records[1].subtotal == Decimal("10.00")
    assert records[1].total == Decimal("12.00")
    assert records[1].status == "Cancelado"
    assert records[1].effect == "I"
    assert records[1].document_type is None


def test_xml_record_maps_document_type_without_inference_or_optional_row_breakage() -> None:
    factory, _ = _factory(
        [
            _row(
                direction="received",
                issue_date=date(2026, 1, 15),
                metadata_effect="I",
                metadata_total=Decimal("45.00"),
                metadata_status="Vigente",
                xml_backed=True,
                document_type="I",
                document_currency="MXN",
                document_subtotal=Decimal("40.00"),
                document_total=Decimal("45.00"),
                document_status="Vigente",
            ),
            _row(
                direction="issued",
                issue_date=date(2026, 1, 15),
                metadata_total=Decimal("12.00"),
                metadata_status="Cancelado",
                xml_backed=True,
                document_currency="MXN",
                document_subtotal=Decimal("10.00"),
                document_total=Decimal("12.00"),
                document_status="Cancelado",
            ),
        ]
    )

    records = MonthlyAnalysisPostgresAdapter(factory).records_for_period("tenant")

    assert records[0].effect == "I"
    assert records[0].document_type == "I"
    # Missing optional metadata effect/document type stays absent; no inference
    # from direction or status is allowed.
    assert records[1].effect is None
    assert records[1].document_type is None


def test_statement_uses_tenant_join_and_inclusive_utc_bounds_without_sensitive_selects() -> None:
    statement = monthly_records_statement(
        "tenant",
        start=date(2026, 1, 14),
        end=date(2026, 1, 15),
    )
    sql = str(statement.compile(dialect=postgresql.dialect()))

    assert "cfdi_metadata_ledger.tenant_id" in sql
    assert "WHERE cfdi_metadata_ledger.tenant_id =" in sql
    assert "cfdi_documents.tenant_id = cfdi_metadata_ledger.tenant_id" in sql
    assert "cfdi_documents.uuid = cfdi_metadata_ledger.uuid" in sql
    assert "cfdi_metadata_ledger.effect AS metadata_effect" in sql
    assert "cfdi_documents.document_type AS document_type" in sql
    assert "xml_evidence.tenant_id = cfdi_metadata_ledger.tenant_id" in sql
    assert "EXISTS (SELECT 1" in sql
    assert "FROM xml_evidence" in sql
    assert "JOIN xml_evidence" not in sql
    assert "cfdi_metadata_ledger.issue_date >=" in sql
    assert "cfdi_metadata_ledger.issue_date <" in sql
    select_part = sql.split(" FROM ", 1)[0]
    assert "issuer_rfc" not in select_part
    assert "receiver_rfc" not in select_part
    assert "raw_payload" not in select_part
    assert "storage_key" not in select_part
    assert "xml_sha256" not in select_part


def test_adapter_omits_null_dates_and_rejects_broad_or_inverted_periods() -> None:
    factory, _ = _factory(
        [
            _row(
                direction="received",
                issue_date=None,
                metadata_total=Decimal("1"),
                metadata_status="Vigente",
                xml_backed=False,
                document_currency=None,
                document_subtotal=None,
                document_total=None,
                document_status=None,
            )
        ]
    )
    adapter = MonthlyAnalysisPostgresAdapter(factory)

    assert adapter.records_for_period("tenant") == ()
    with pytest.raises(ValueError, match="analysis-tenant-required"):
        adapter.records_for_period(" ")
    with pytest.raises(ValueError, match="analysis-period-invalid"):
        adapter.records_for_period("tenant", start=date(2026, 2, 1), end=date(2026, 1, 1))


def test_xml_record_falls_back_to_metadata_when_document_header_is_partial() -> None:
    factory, _ = _factory(
        [
            _row(
                direction="received",
                issue_date=date(2026, 1, 15),
                metadata_total=Decimal("45.00"),
                metadata_status="Vigente",
                xml_backed=True,
                document_currency=None,
                document_subtotal=None,
                document_total=None,
                document_status=None,
            ),
            _row(
                direction="received",
                issue_date=date(2026, 1, 15),
                metadata_total=Decimal("45.00"),
                metadata_status="Vigente",
                xml_backed=True,
                document_currency="MXN",
                document_subtotal=Decimal("0.00"),
                document_total=Decimal("0.00"),
                document_status="Cancelado",
            ),
        ]
    )

    records = MonthlyAnalysisPostgresAdapter(factory).records_for_period("tenant")

    assert records[0].currency == "UNKNOWN"
    assert records[0].subtotal is None
    assert records[0].total == Decimal("45.00")
    assert records[0].status == "Vigente"
    assert records[1].total == Decimal("0.00")
    assert records[1].status == "Cancelado"
