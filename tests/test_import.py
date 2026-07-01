from __future__ import annotations

from decimal import Decimal
from pathlib import Path
from zipfile import ZipFile

from sqlalchemy import select

from cfdi_vault.db import Invoice
from cfdi_vault.service import VaultService
from tests.conftest import write_xml


def test_import_xml_stores_invoice_and_hash(tmp_path: Path, sample_xml: bytes) -> None:
    db_path = tmp_path / "vault.sqlite3"
    xml_path = tmp_path / "invoice.xml"
    xml_path.write_bytes(sample_xml)

    service = VaultService(db_path)
    record = service.import_xml_file(xml_path)

    assert record.imported is True
    assert record.duplicate is False
    assert record.xml_sha256 is not None
    assert len(record.xml_sha256) == 64

    with service.session_factory() as session:
        invoice = session.scalar(select(Invoice).where(Invoice.uuid == record.uuid))

    assert invoice is not None
    assert invoice.total == Decimal("143.200000")


def test_import_zip_imports_multiple_xml_files(tmp_path: Path) -> None:
    db_path = tmp_path / "vault.sqlite3"
    first = write_xml(tmp_path / "first.xml", uuid="00000000-0000-4000-8000-000000000201")
    second = write_xml(tmp_path / "second.xml", uuid="00000000-0000-4000-8000-000000000202")
    zip_path = tmp_path / "batch.zip"
    with ZipFile(zip_path, "w") as archive:
        archive.write(first, "first.xml")
        archive.write(second, "nested/second.xml")
        archive.writestr("notes.txt", "not an XML file")

    result = VaultService(db_path).import_zip_file(zip_path)

    assert result.total_files == 2
    assert result.imported == 2
    assert result.duplicates == 0
    assert result.failed == 0


def test_import_deduplicates_by_uuid(tmp_path: Path, sample_xml: bytes) -> None:
    db_path = tmp_path / "vault.sqlite3"
    xml_path = tmp_path / "invoice.xml"
    xml_path.write_bytes(sample_xml)
    service = VaultService(db_path)

    first = service.import_xml_file(xml_path)
    second = service.import_xml_file(xml_path)

    assert first.imported is True
    assert second.imported is False
    assert second.duplicate is True

    with service.session_factory() as session:
        count = len(session.scalars(select(Invoice)).all())

    assert count == 1
