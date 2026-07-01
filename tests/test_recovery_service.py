from datetime import datetime, timezone

from cfdi_vault.domain import DownloadDirection, RequestType
from cfdi_vault.fake_sat import FakeSatClient
from cfdi_vault.recovery_db import CfdiDocument, CfdiMetadataLedger, SatPackageRecord, SatRequestRecord, XmlEvidence
from cfdi_vault.recovery_service import RecoveryService, build_default_query, write_minimal_pdf
from cfdi_vault.worker import RecoveryWorker
from sqlalchemy import select


def test_fake_metadata_sync_creates_searchable_documents(tmp_path) -> None:
    service = RecoveryService(sqlite_path=tmp_path / "recovery.sqlite3", storage_root=tmp_path / "storage")
    try:
        query = build_default_query(
            tenant_id="default",
            rfc="XAXX010101000",
            direction=DownloadDirection.RECEIVED,
            request_type=RequestType.METADATA,
            start=datetime(2024, 1, 1, tzinfo=timezone.utc),
            end=datetime(2024, 1, 31, tzinfo=timezone.utc),
        )

        result = service.sync_metadata(query)
        rows = service.search("fake receiver")
        queue_rows = service.queue_status()

        assert result.status == "succeeded"
        assert result.metadata_count == 2
        assert len(rows) == 2
        assert rows[0]["parser_status"] == "metadata_only"
        assert any(row["queue"] == "sat.download" for row in queue_rows)
    finally:
        service.close()


def test_print_and_export_use_normalized_recovery_data(tmp_path) -> None:
    service = RecoveryService(sqlite_path=tmp_path / "recovery.sqlite3", storage_root=tmp_path / "storage")
    try:
        query = build_default_query(
            tenant_id="default",
            rfc="XAXX010101000",
            direction=DownloadDirection.RECEIVED,
            request_type=RequestType.METADATA,
            start=datetime(2024, 1, 1, tzinfo=timezone.utc),
            end=datetime(2024, 1, 31, tzinfo=timezone.utc),
        )
        service.sync_metadata(query)
        uuid = service.search("")[0]["uuid"]

        rendered = service.render_text(str(uuid))
        csv_path = tmp_path / "exports" / "cfdi.csv"
        pdf_path = tmp_path / "exports" / "cfdi.pdf"
        count = service.export_csv(csv_path)
        write_minimal_pdf(pdf_path, rendered)

        assert "CFDI" in rendered
        assert count == 2
        assert csv_path.read_text(encoding="utf-8").startswith("uuid,issuer_rfc")
        assert pdf_path.read_bytes().startswith(b"%PDF-1.4")
    finally:
        service.close()


def test_duplicate_sync_result_is_scoped_to_original_job(tmp_path) -> None:
    service = RecoveryService(sqlite_path=tmp_path / "recovery.sqlite3", storage_root=tmp_path / "storage")
    try:
        january = build_default_query(
            tenant_id="default",
            rfc="XAXX010101000",
            direction=DownloadDirection.RECEIVED,
            request_type=RequestType.METADATA,
            start=datetime(2024, 1, 1, tzinfo=timezone.utc),
            end=datetime(2024, 1, 31, tzinfo=timezone.utc),
        )
        february = build_default_query(
            tenant_id="default",
            rfc="XAXX010101000",
            direction=DownloadDirection.RECEIVED,
            request_type=RequestType.METADATA,
            start=datetime(2024, 2, 1, tzinfo=timezone.utc),
            end=datetime(2024, 2, 29, tzinfo=timezone.utc),
        )

        first = service.sync_metadata(january)
        service.sync_metadata(february)
        replay = service.sync_metadata(january)

        assert replay.job_id == first.job_id
        assert replay.packages == first.packages
        assert replay.metadata_count == first.metadata_count == 2
    finally:
        service.close()


def test_xml_sync_stores_extracted_xml_evidence(tmp_path) -> None:
    service = RecoveryService(sqlite_path=tmp_path / "recovery.sqlite3", storage_root=tmp_path / "storage")
    try:
        query = build_default_query(
            tenant_id="default",
            rfc="XAXX010101000",
            direction=DownloadDirection.RECEIVED,
            request_type=RequestType.CFDI,
            start=datetime(2024, 1, 1, tzinfo=timezone.utc),
            end=datetime(2024, 1, 31, tzinfo=timezone.utc),
        )

        service.sync_metadata(query)

        with service.session_factory() as session:
            evidence = session.scalars(select(XmlEvidence)).all()
        xml_files = list((tmp_path / "storage" / "XAXX010101000" / "xml" / "2024" / "01").glob("*.xml"))
        rows = service.search("fake accounting")

        assert len(evidence) == 2
        assert len(xml_files) == 2
        assert {row["parser_status"] for row in rows} == {"complete"}
    finally:
        service.close()


def test_xml_sync_registers_idempotent_storage_metadata_and_pipeline_state(tmp_path) -> None:
    service = RecoveryService(sqlite_path=tmp_path / "recovery.sqlite3", storage_root=tmp_path / "storage")
    try:
        query = build_default_query(
            tenant_id="default",
            rfc="XAXX010101000",
            direction=DownloadDirection.RECEIVED,
            request_type=RequestType.CFDI,
            start=datetime(2024, 1, 1, tzinfo=timezone.utc),
            end=datetime(2024, 1, 31, tzinfo=timezone.utc),
        )

        first = service.sync_metadata(query)
        replay = service.sync_metadata(query)

        with service.session_factory() as session:
            request = session.scalar(select(SatRequestRecord))
            package = session.scalar(select(SatPackageRecord))
            ledgers = session.scalars(select(CfdiMetadataLedger)).all()
            documents = session.scalars(select(CfdiDocument)).all()
            evidence = session.scalars(select(XmlEvidence)).all()

        assert replay.job_id == first.job_id
        assert request is not None
        assert request.metadata_sha256
        assert request.metadata_storage_key is not None
        metadata_path = tmp_path / "storage" / "XAXX010101000" / "metadata" / "2024" / "01"
        assert str(request.metadata_storage_key).startswith(str(metadata_path))
        assert str(request.metadata_storage_key).endswith(".csv")
        assert package is not None
        assert package.status == "downloaded"
        assert package.sha256_zip
        assert str(package.storage_key).startswith(str(tmp_path / "storage" / "XAXX010101000" / "packages" / "2024" / "01"))
        assert len(ledgers) == 2
        assert {ledger.reconciliation_state for ledger in ledgers} == {"XML_DOWNLOADED"}
        assert {ledger.source_metadata_sha256 for ledger in ledgers} == {request.metadata_sha256}
        assert len(documents) == 2
        assert {document.download_state for document in documents} == {"XML_DOWNLOADED"}
        assert all(document.xml_sha256 for document in documents)
        assert len(evidence) == 2
    finally:
        service.close()


def test_fake_sat_packages_are_deterministic_across_fresh_clients(tmp_path) -> None:
    query = build_default_query(
        tenant_id="default",
        rfc="XAXX010101000",
        direction=DownloadDirection.RECEIVED,
        request_type=RequestType.CFDI,
        start=datetime(2024, 1, 1, tzinfo=timezone.utc),
        end=datetime(2024, 1, 31, tzinfo=timezone.utc),
    )
    first_client = FakeSatClient()
    second_client = FakeSatClient()

    first_request = first_client.submit_request(query)
    second_request = second_client.submit_request(query)
    first_package_id = first_client.verify_request(first_request)["packages"][0]
    second_package_id = second_client.verify_request(second_request)["packages"][0]

    first_content = first_client.download_package(str(first_package_id))
    second_content = second_client.download_package(str(second_package_id))

    assert first_package_id == second_package_id
    assert first_content == second_content


def test_enqueued_sync_is_processed_by_worker(tmp_path) -> None:
    service = RecoveryService(sqlite_path=tmp_path / "recovery.sqlite3", storage_root=tmp_path / "storage")
    try:
        query = build_default_query(
            tenant_id="default",
            rfc="XAXX010101000",
            direction=DownloadDirection.RECEIVED,
            request_type=RequestType.METADATA,
            start=datetime(2024, 1, 1, tzinfo=timezone.utc),
            end=datetime(2024, 1, 31, tzinfo=timezone.utc),
        )

        queued = service.sync_metadata(query, enqueue=True)
        report = RecoveryWorker(service).run_once()

        assert queued.status == "pending"
        assert report.processed == 1
        assert len(service.search("fake")) == 2
    finally:
        service.close()
