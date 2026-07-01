from __future__ import annotations

import csv
from pathlib import Path

from cfdi_vault.service import VaultService
from tests.conftest import write_xml


def test_summary_returns_totals_by_month_issuer_and_type(tmp_path: Path) -> None:
    db_path = tmp_path / "vault.sqlite3"
    service = VaultService(db_path)
    service.import_xml_file(write_xml(tmp_path / "jan.xml", uuid="00000000-0000-4000-8000-000000000301", issuer_name="Synthetic Issuer A", issue_date="2026-01-05T10:00:00", total="143.20", comprobante_type="I"))
    service.import_xml_file(write_xml(tmp_path / "feb.xml", uuid="00000000-0000-4000-8000-000000000302", issuer_name="Synthetic Issuer A", issue_date="2026-02-05T10:00:00", total="143.20", comprobante_type="I"))
    service.import_xml_file(write_xml(tmp_path / "egress.xml", uuid="00000000-0000-4000-8000-000000000303", issuer_name="Synthetic Issuer B", issue_date="2026-02-20T10:00:00", total="50.00", comprobante_type="E"))

    summary = service.summary()

    assert [row.label for row in summary.by_month] == ["2026-01", "2026-02"]
    assert [row.count for row in summary.by_month] == [1, 2]
    assert [row.label for row in summary.by_comprobante_type] == ["E", "I"]
    assert [row.count for row in summary.by_comprobante_type] == [1, 2]
    assert len(summary.by_issuer) == 2


def test_export_csv_writes_imported_invoices(tmp_path: Path, sample_xml: bytes) -> None:
    db_path = tmp_path / "vault.sqlite3"
    xml_path = tmp_path / "invoice.xml"
    csv_path = tmp_path / "export.csv"
    xml_path.write_bytes(sample_xml)
    service = VaultService(db_path)
    service.import_xml_file(xml_path)

    count = service.export_csv(csv_path)

    assert count == 1
    rows = list(csv.DictReader(csv_path.open(newline="", encoding="utf-8")))
    assert len(rows) == 1
    assert rows[0]["uuid"] == "00000000-0000-4000-8000-000000000101"
    assert rows[0]["issuer_name"] == "Synthetic Issuer Test"
    assert rows[0]["total"] == "143.20"
    assert rows[0]["xml_sha256"]
