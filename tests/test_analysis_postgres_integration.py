from __future__ import annotations

from datetime import UTC, datetime
from decimal import Decimal

import pytest
from sqlalchemy import text

from cfdi_vault.accounting_ledger_v5 import AccountingLedgerRepository
from cfdi_vault.accounting_ledger_v5_mapper import LedgerWriteIntentMapper
from cfdi_vault.analysis.ledger_intent import LedgerWriteContext, build_ledger_write_intent
from cfdi_vault.analysis.normalization import ConceptRecord
from cfdi_vault.analysis.payments import PaymentRecord
from cfdi_vault.analysis.payroll import PayrollRecord
from cfdi_vault.analysis.postgres import MonthlyAnalysisPostgresAdapter
from cfdi_vault.analysis.postgres_accounting import AccountingPostgresAdapter
from cfdi_vault.analysis.postgres_report import PostgresFinancialAnalysisService
from cfdi_vault.analysis.projection import AccountingProjection
from cfdi_vault.analysis.taxes import TaxRecord
from cfdi_vault.db import create_engine_from_url, create_session_factory


def _projection(digest: str, currency: str) -> AccountingProjection:
    source_ref = f"xml-{digest[:24]}"
    stamp = datetime(2026, 1, 14, 12, 0, tzinfo=UTC)
    concept = ConceptRecord(
        product_service_key="01010101",
        unit_key="ACT",
        description="Synthetic service",
        quantity=Decimal("1"),
        unit_value=Decimal("10"),
        amount=Decimal("10"),
        discount=None,
        tax_object="02",
        ordinal=1,
        provenance=source_ref,
    )
    tax = TaxRecord(
        tax_type="transferred",
        tax="002",
        factor_type="Tasa",
        rate_or_quota=Decimal("0.16"),
        base=Decimal("10"),
        amount=Decimal("1.60"),
        concept_ordinal=1,
        document_scope="concept",
        provenance=source_ref,
    )
    payment = PaymentRecord(
        payment_date=stamp,
        payment_form="03",
        currency=currency,
        amount=Decimal("11.60"),
        exchange_rate=None if currency == "MXN" else Decimal("20"),
        related_document_count=0,
        provenance=source_ref,
    )
    payroll = PayrollRecord(
        payroll_type="O",
        payment_date=stamp,
        period_start=datetime(2026, 1, 1, tzinfo=UTC),
        period_end=datetime(2026, 1, 14, tzinfo=UTC),
        paid_days=Decimal("14"),
        total_perceptions=Decimal("100"),
        total_deductions=Decimal("10"),
        total_other_payments=Decimal("0"),
        perception_count=1,
        deduction_count=1,
        other_payment_count=0,
        incomplete_count=0,
        provenance=source_ref,
    )
    return AccountingProjection(
        source_ref=source_ref,
        idempotency_key=f"accounting-v1-{digest}",
        concepts=(concept,),
        taxes=(tax,),
        payments=(payment,),
        payroll=(payroll,),
        parser_statuses={name: "complete" for name in ("concepts", "taxes", "payments", "payroll")},
        record_counts={name: 1 for name in ("concepts", "taxes", "payments", "payroll")},
        completeness="complete",
    )


def _seed_document(connection, tenant: str, key: str, issue_date: datetime, currency: str, digest: str):
    document_id = connection.execute(
        text(
            """INSERT INTO cfdi_documents
            (tenant_id, uuid, version, document_type, status, issue_date, currency,
             subtotal, total, payment_method, download_state, parser_status, search_text,
             raw_payload, created_at, updated_at)
            VALUES (:tenant, :key, '4.0', 'I', 'vigente', :issue, :currency,
                    10, 11.60, 'PPD', 'downloaded', 'complete', '', '{}'::jsonb, :now, :now)
            RETURNING id"""
        ),
        {"tenant": tenant, "key": key, "issue": issue_date, "currency": currency, "now": issue_date},
    ).scalar_one()
    evidence_id = connection.execute(
        text(
            """INSERT INTO xml_evidence
            (tenant_id, uuid, xml_sha256, size_bytes, storage_key, parser_version,
             parser_status, created_at)
            VALUES (:tenant, :key, :digest, 1, :storage, 'parser-1', 'complete', :now)
            RETURNING id"""
        ),
        {
            "tenant": tenant,
            "key": key,
            "digest": digest,
            "storage": f"synthetic/{key}.xml",
            "now": issue_date,
        },
    ).scalar_one()
    connection.execute(
        text(
            """INSERT INTO cfdi_metadata_ledger
            (tenant_id, uuid, direction, issue_date, total, status, effect,
             reconciliation_state, first_seen_at, last_seen_at, raw_payload)
            VALUES (:tenant, :key, 'received', :issue, 11.60, 'vigente', 'I',
                    'state_checked', :now, :now, '{}'::jsonb)"""
        ),
        {"tenant": tenant, "key": key, "issue": issue_date, "now": issue_date},
    )
    return document_id, evidence_id


@pytest.mark.integration
def test_postgres_mapper_reads_and_report_are_idempotent_and_tenant_safe(reset_postgres_database: str) -> None:
    engine = create_engine_from_url(reset_postgres_database)
    start = datetime(2026, 1, 1, tzinfo=UTC)
    end = datetime(2026, 1, 14, 23, 59, tzinfo=UTC)
    outside = datetime(2026, 1, 15, tzinfo=UTC)
    with engine.begin() as connection:
        for tenant in ("tenant-alpha", "tenant-beta"):
            connection.execute(
                text("INSERT INTO tenants (id, name, rfc, created_at) VALUES (:id, :name, 'SYNTHETIC', :now)"),
                {"id": tenant, "name": "Synthetic Tenant", "now": start},
            )
        alpha_first = _seed_document(connection, "tenant-alpha", "doc-alpha-mxn", start, "MXN", "a" * 64)
        alpha_second = _seed_document(
            connection, "tenant-alpha", "doc-alpha-usd", end, "USD", "b" * 64
        )
        _seed_document(connection, "tenant-alpha", "doc-alpha-outside", outside, "MXN", "c" * 64)
        _seed_document(connection, "tenant-beta", "doc-beta-mxn", start, "MXN", "d" * 64)

    factory = create_session_factory(engine)
    mapper = LedgerWriteIntentMapper(AccountingLedgerRepository(factory))
    for document_id, evidence_id, digest, currency in (
        (*alpha_first, "a" * 64, "MXN"),
        (*alpha_second, "b" * 64, "USD"),
    ):
        intent = build_ledger_write_intent(
            _projection(digest, currency),
            context=LedgerWriteContext("tenant-alpha", f"work-{digest[0]}"),
            normalization_generation="cfdi-v5",
        )
        first = mapper.map(
            intent,
            tenant_id="tenant-alpha",
            document_id=document_id,
            source_evidence_id=evidence_id,
            parser_version="parser-1",
        )
        second = mapper.map(
            intent,
            tenant_id="tenant-alpha",
            document_id=document_id,
            source_evidence_id=evidence_id,
            parser_version="parser-1",
        )
        assert first.aggregate.records_written == 4
        assert second.aggregate.records_written == 0
        assert second.aggregate.duplicates == 4

    with engine.connect() as connection:
        counts = connection.execute(
            text(
                "SELECT COUNT(*) FROM cfdi_concepts WHERE tenant_id = 'tenant-alpha'"
            )
        ).scalar_one()
        assert counts == 2
        assert connection.execute(text("SELECT COUNT(*) FROM cfdi_concepts WHERE tenant_id = 'tenant-beta'")).scalar_one() == 0

    accounting = AccountingPostgresAdapter(factory)
    taxes = accounting.tax_records("tenant-alpha", start=start.date(), end=end.date())
    payments = accounting.payment_records("tenant-alpha", start=start.date(), end=end.date())
    payroll = accounting.payroll_records("tenant-alpha", start=start.date(), end=end.date())
    assert len(taxes) == len(payments) == len(payroll) == 2
    assert {row.currency for row in payments} == {"MXN", "USD"}
    assert payroll.parser_status == "partial" and not payroll.money_available
    assert accounting.payment_records("tenant-beta", start=start.date(), end=end.date()).rows == ()

    alpha_quality = accounting.quality_observations("tenant-alpha", start=start.date(), end=end.date())
    beta_quality = accounting.quality_observations("tenant-beta", start=start.date(), end=end.date())
    assert all(observation.payment_present for observation in alpha_quality)
    assert all(not observation.payment_present for observation in beta_quality)

    monthly = MonthlyAnalysisPostgresAdapter(factory)
    monthly_rows = monthly.records_for_period("tenant-alpha", start=start.date(), end=end.date())
    assert len(monthly_rows) == 2
    assert all(row.issue_date <= end.date() for row in monthly_rows)
    report = PostgresFinancialAnalysisService(monthly, accounting).build_report(
        "tenant-alpha", start.date(), end.date()
    )
    payload = report.to_public_dict()
    assert {row["currency"] for row in payload["sections"]["monthly"]["rows"]} == {"MXN", "USD"}
    assert payload["sections"]["payroll"]["record_count"] == 2
    assert payload["section_statuses"]["payroll"] == "partial"
    assert "tenant-alpha" not in repr(payload)
    engine.dispose()
