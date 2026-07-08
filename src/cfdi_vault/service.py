"""Application service layer for importing, summarizing, and exporting CFDI data."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from decimal import Decimal
import csv
import hashlib
from pathlib import Path
from zipfile import ZipFile

from sqlalchemy import select

from cfdi_vault.db import Invoice, create_engine_from_url, create_session_factory, init_db
from cfdi_vault.parser import CfdiParseError, ParsedCfdi, parse_cfdi_xml


@dataclass(frozen=True)
class ImportRecord:
    """Result for one XML import attempt."""

    source_name: str
    uuid: str | None
    imported: bool
    duplicate: bool
    xml_sha256: str | None
    error: str | None = None


@dataclass(frozen=True)
class ImportBatchResult:
    """Aggregated result for an XML or ZIP import operation."""

    records: tuple[ImportRecord, ...]

    @property
    def total_files(self) -> int:
        return len(self.records)

    @property
    def imported(self) -> int:
        return sum(1 for record in self.records if record.imported)

    @property
    def duplicates(self) -> int:
        return sum(1 for record in self.records if record.duplicate)

    @property
    def failed(self) -> int:
        return sum(1 for record in self.records if record.error is not None)


@dataclass(frozen=True)
class SummaryRow:
    """One aggregate row for a summary dimension."""

    label: str
    count: int
    subtotal: Decimal
    total: Decimal


@dataclass(frozen=True)
class VaultSummary:
    """Totals grouped by the dimensions required for phase one."""

    by_month: tuple[SummaryRow, ...]
    by_issuer: tuple[SummaryRow, ...]
    by_comprobante_type: tuple[SummaryRow, ...]


class VaultService:
    """Use-case boundary for PostgreSQL-backed CFDI import/export workflows."""

    def __init__(self, database_url: str | None = None) -> None:
        self.engine = create_engine_from_url(database_url)
        init_db(self.engine)
        self.session_factory = create_session_factory(self.engine)

    def import_xml_file(self, xml_path: str | Path) -> ImportRecord:
        path = Path(xml_path)
        return self.import_xml_bytes(path.read_bytes(), path.name)

    def import_xml_bytes(self, xml_bytes: bytes, source_name: str) -> ImportRecord:
        xml_sha256 = hashlib.sha256(xml_bytes).hexdigest()

        try:
            parsed = parse_cfdi_xml(xml_bytes)
        except CfdiParseError as exc:
            return ImportRecord(
                source_name=source_name,
                uuid=None,
                imported=False,
                duplicate=False,
                xml_sha256=xml_sha256,
                error=str(exc),
            )

        with self.session_factory() as session:
            existing = session.scalar(select(Invoice).where(Invoice.uuid == parsed.uuid))
            if existing is not None:
                return ImportRecord(
                    source_name=source_name,
                    uuid=parsed.uuid,
                    imported=False,
                    duplicate=True,
                    xml_sha256=xml_sha256,
                    error=None,
                )

            invoice = _invoice_from_parsed(parsed, xml_sha256, source_name)
            session.add(invoice)
            session.commit()

        return ImportRecord(
            source_name=source_name,
            uuid=parsed.uuid,
            imported=True,
            duplicate=False,
            xml_sha256=xml_sha256,
            error=None,
        )

    def import_zip_file(self, zip_path: str | Path) -> ImportBatchResult:
        path = Path(zip_path)
        records: list[ImportRecord] = []
        with ZipFile(path) as archive:
            for member in sorted(archive.namelist()):
                if member.endswith("/") or not member.lower().endswith(".xml"):
                    continue
                records.append(self.import_xml_bytes(archive.read(member), member))
        return ImportBatchResult(tuple(records))

    def summary(self) -> VaultSummary:
        with self.session_factory() as session:
            invoices = tuple(session.scalars(select(Invoice).order_by(Invoice.issue_date, Invoice.uuid)).all())

        return VaultSummary(
            by_month=_group_summary(invoices, lambda invoice: invoice.issue_date.strftime("%Y-%m")),
            by_issuer=_group_summary(invoices, lambda invoice: f"{invoice.issuer_name} ({invoice.issuer_rfc})"),
            by_comprobante_type=_group_summary(invoices, lambda invoice: invoice.comprobante_type),
        )

    def export_csv(self, output_path: str | Path) -> int:
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        columns = [
            "uuid",
            "issuer_rfc",
            "issuer_name",
            "receiver_rfc",
            "receiver_name",
            "issue_date",
            "subtotal",
            "total",
            "currency",
            "comprobante_type",
            "payment_method",
            "payment_form",
            "xml_sha256",
            "source_name",
        ]

        with self.session_factory() as session:
            invoices = session.scalars(select(Invoice).order_by(Invoice.issue_date, Invoice.uuid)).all()

        with path.open("w", newline="", encoding="utf-8") as csv_file:
            writer = csv.DictWriter(csv_file, fieldnames=columns)
            writer.writeheader()
            for invoice in invoices:
                writer.writerow(
                    {
                        "uuid": invoice.uuid,
                        "issuer_rfc": invoice.issuer_rfc,
                        "issuer_name": invoice.issuer_name,
                        "receiver_rfc": invoice.receiver_rfc,
                        "receiver_name": invoice.receiver_name,
                        "issue_date": invoice.issue_date.isoformat(),
                        "subtotal": _decimal_to_text(invoice.subtotal),
                        "total": _decimal_to_text(invoice.total),
                        "currency": invoice.currency,
                        "comprobante_type": invoice.comprobante_type,
                        "payment_method": invoice.payment_method or "",
                        "payment_form": invoice.payment_form or "",
                        "xml_sha256": invoice.xml_sha256,
                        "source_name": invoice.source_name,
                    }
                )
        return len(invoices)


def _invoice_from_parsed(parsed: ParsedCfdi, xml_sha256: str, source_name: str) -> Invoice:
    return Invoice(
        uuid=parsed.uuid,
        issuer_rfc=parsed.issuer_rfc,
        issuer_name=parsed.issuer_name,
        receiver_rfc=parsed.receiver_rfc,
        receiver_name=parsed.receiver_name,
        issue_date=parsed.issue_date,
        subtotal=parsed.subtotal,
        total=parsed.total,
        currency=parsed.currency,
        comprobante_type=parsed.comprobante_type,
        payment_method=parsed.payment_method,
        payment_form=parsed.payment_form,
        xml_sha256=xml_sha256,
        source_name=source_name,
        imported_at=datetime.now(timezone.utc),
    )


def _group_summary(invoices: tuple[Invoice, ...], label_for: Callable[[Invoice], str]) -> tuple[SummaryRow, ...]:
    grouped: dict[str, tuple[int, Decimal, Decimal]] = {}
    for invoice in invoices:
        label = str(label_for(invoice))
        count, subtotal, total = grouped.get(label, (0, Decimal("0"), Decimal("0")))
        grouped[label] = (count + 1, subtotal + _to_decimal(invoice.subtotal), total + _to_decimal(invoice.total))
    return tuple(
        SummaryRow(label=label, count=count, subtotal=subtotal, total=total)
        for label, (count, subtotal, total) in sorted(grouped.items())
    )


def _to_decimal(value: object) -> Decimal:
    if isinstance(value, Decimal):
        return value
    return Decimal(str(value or "0"))


def _decimal_to_text(value: Decimal) -> str:
    return format(value.quantize(Decimal("0.01")), "f")
