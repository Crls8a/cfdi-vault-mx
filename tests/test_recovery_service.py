from datetime import datetime, timezone

from cfdi_vault.domain import DownloadDirection, QueueName, ReconciliationState, RequestType
from cfdi_vault.fake_sat import FakeSatClient
from cfdi_vault.recovery_db import CfdiDocument, CfdiMetadataLedger, SatPackageRecord, SatRequestRecord, XmlEvidence
from cfdi_vault.recovery_service import RecoveryService, build_default_query, write_minimal_pdf
from cfdi_vault.worker import RecoveryWorker
from sqlalchemy import select


def _synthetic_metadata_bytes(*rows: tuple[str, str, str, str]) -> bytes:
    lines = [
        "uuid|rfcEmisor|nombreEmisor|rfcReceptor|nombreReceptor|fechaEmision|montoTotal|estadoComprobante|tipoComprobante|idPaquete",
    ]
    for uuid, status, total, effect in rows:
        lines.append(
            f"{uuid}|AAA010101AAA|Synthetic Issuer|BBB010101BBB|Synthetic Receiver|2024-01-15T10:30:00Z|{total}|{status}|{effect}|SYN-PACKAGE-002"
        )
    return "\n".join(lines).encode("utf-8")


def test_fake_metadata_sync_creates_searchable_documents(tmp_path, reset_postgres_database: str) -> None:
    service = RecoveryService(database_url=reset_postgres_database, storage_root=tmp_path / "storage")
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


def test_ingest_metadata_file_stores_inventory_and_invalid_rows(tmp_path, reset_postgres_database: str) -> None:
    service = RecoveryService(database_url=reset_postgres_database, storage_root=tmp_path / "storage")
    try:
        query = build_default_query(
            tenant_id="default",
            rfc="XAXX010101000",
            direction=DownloadDirection.RECEIVED,
            request_type=RequestType.METADATA,
            start=datetime(2024, 1, 1, tzinfo=timezone.utc),
            end=datetime(2024, 1, 31, tzinfo=timezone.utc),
        )
        content = b"\n".join(
            [
                _synthetic_metadata_bytes(
                    ("00000000-0000-4000-8000-000000000011", "Vigente", "100.00", "I"),
                    ("00000000-0000-4000-8000-000000000012", "Cancelado", "200.00", "E"),
                ),
                b"NOT-A-UUID|AAA010101AAA|Synthetic Issuer|BBB010101BBB|Synthetic Receiver|2024-01-15|300.00|Vigente|I|SYN-PACKAGE-002",
            ]
        )

        result = service.ingest_metadata_file(query, content, source_package_id="SYN-PACKAGE-002")

        with service.session_factory() as session:
            ledgers = session.scalars(select(CfdiMetadataLedger).order_by(CfdiMetadataLedger.uuid)).all()
            documents = session.scalars(select(CfdiDocument).order_by(CfdiDocument.uuid)).all()

        assert result.accepted_count == 2
        assert result.rejected_count == 1
        assert result.invalid_rows[0].line_number == 4
        assert result.storage_key.endswith(".txt")
        assert len(ledgers) == 2
        assert [ledger.reconciliation_state for ledger in ledgers] == [
            ReconciliationState.DISCOVERED_IN_METADATA.value,
            ReconciliationState.CANCELLED_METADATA.value,
        ]
        assert len(documents) == 2
        assert {document.parser_status for document in documents} == {"metadata_only"}

    finally:
        service.close()


def test_reconcile_metadata_moves_existing_without_xml_to_pending(tmp_path, reset_postgres_database: str) -> None:
    service = RecoveryService(database_url=reset_postgres_database, storage_root=tmp_path / "storage")
    try:
        query = build_default_query(
            tenant_id="default",
            rfc="XAXX010101000",
            direction=DownloadDirection.RECEIVED,
            request_type=RequestType.METADATA,
            start=datetime(2024, 1, 1, tzinfo=timezone.utc),
            end=datetime(2024, 1, 31, tzinfo=timezone.utc),
        )
        service.ingest_metadata_file(
            query,
            _synthetic_metadata_bytes(("00000000-0000-4000-8000-000000000013", "Vigente", "100.00", "I")),
        )

        changed = service.reconcile(tenant_id="default")

        with service.session_factory() as session:
            ledger = session.scalar(select(CfdiMetadataLedger))

        assert changed == 1
        assert ledger is not None
        assert ledger.reconciliation_state == ReconciliationState.XML_PENDING.value
    finally:
        service.close()


def test_reconcile_metadata_identifies_existing_xml_evidence(tmp_path, reset_postgres_database: str) -> None:
    service = RecoveryService(database_url=reset_postgres_database, storage_root=tmp_path / "storage")
    try:
        query = build_default_query(
            tenant_id="default",
            rfc="XAXX010101000",
            direction=DownloadDirection.RECEIVED,
            request_type=RequestType.METADATA,
            start=datetime(2024, 1, 1, tzinfo=timezone.utc),
            end=datetime(2024, 1, 31, tzinfo=timezone.utc),
        )
        uuid = "00000000-0000-4000-8000-000000000014"
        xml_sha256 = "0" * 64
        service.ingest_metadata_file(query, _synthetic_metadata_bytes((uuid, "Vigente", "100.00", "I")))
        with service.session_factory() as session:
            document = session.scalar(select(CfdiDocument).where(CfdiDocument.uuid == uuid))
            assert document is not None
            document.xml_sha256 = xml_sha256
            document.download_state = ReconciliationState.XML_DOWNLOADED.value
            session.add(
                XmlEvidence(
                    tenant_id="default",
                    uuid=uuid,
                    source_package_id="SYN-PACKAGE-002",
                    xml_sha256=xml_sha256,
                    size_bytes=10,
                    storage_key="synthetic/xml.xml",
                    parser_version="test",
                    parser_status="complete",
                    created_at=datetime(2024, 1, 20, tzinfo=timezone.utc),
                )
            )
            session.commit()

        changed = service.reconcile(tenant_id="default")

        with service.session_factory() as session:
            ledger = session.scalar(select(CfdiMetadataLedger).where(CfdiMetadataLedger.uuid == uuid))

        assert changed == 1
        assert ledger is not None
        assert ledger.reconciliation_state == ReconciliationState.XML_DOWNLOADED.value
    finally:
        service.close()


def test_repeated_metadata_ingest_marks_status_change_for_consultation(tmp_path, reset_postgres_database: str) -> None:
    service = RecoveryService(database_url=reset_postgres_database, storage_root=tmp_path / "storage")
    try:
        query = build_default_query(
            tenant_id="default",
            rfc="XAXX010101000",
            direction=DownloadDirection.RECEIVED,
            request_type=RequestType.METADATA,
            start=datetime(2024, 1, 1, tzinfo=timezone.utc),
            end=datetime(2024, 1, 31, tzinfo=timezone.utc),
        )
        uuid = "00000000-0000-4000-8000-000000000015"
        service.ingest_metadata_file(query, _synthetic_metadata_bytes((uuid, "Vigente", "100.00", "I")))

        service.ingest_metadata_file(query, _synthetic_metadata_bytes((uuid, "En Proceso", "100.00", "I")))

        with service.session_factory() as session:
            ledger = session.scalar(select(CfdiMetadataLedger).where(CfdiMetadataLedger.uuid == uuid))

        assert ledger is not None
        assert ledger.status == "En Proceso"
        assert ledger.reconciliation_state == ReconciliationState.STATE_CHECK_PENDING.value
    finally:
        service.close()


def test_print_and_export_use_normalized_recovery_data(tmp_path, reset_postgres_database: str) -> None:
    service = RecoveryService(database_url=reset_postgres_database, storage_root=tmp_path / "storage")
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


def test_duplicate_sync_result_is_scoped_to_original_job(tmp_path, reset_postgres_database: str) -> None:
    service = RecoveryService(database_url=reset_postgres_database, storage_root=tmp_path / "storage")
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


def test_xml_sync_stores_extracted_xml_evidence(tmp_path, reset_postgres_database: str) -> None:
    service = RecoveryService(database_url=reset_postgres_database, storage_root=tmp_path / "storage")
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


def test_xml_sync_registers_idempotent_storage_metadata_and_pipeline_state(tmp_path, reset_postgres_database: str) -> None:
    service = RecoveryService(database_url=reset_postgres_database, storage_root=tmp_path / "storage")
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


def test_fake_sat_packages_are_deterministic_across_fresh_clients(tmp_path, reset_postgres_database: str) -> None:
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


def test_enqueued_sync_is_processed_by_worker(tmp_path, reset_postgres_database: str) -> None:
    service = RecoveryService(database_url=reset_postgres_database, storage_root=tmp_path / "storage")
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
        message = service.queue._messages[QueueName.SAT_REQUEST.value][0]  # type: ignore[attr-defined]
        assert message is not None
        assert message.job_id == queued.job_id
        assert message.tenant_id == "default"
        assert all(key not in message.as_dict() for key in ("rfc", "uuid", "criteria", "payload"))
        report = RecoveryWorker(service).run_once()

        assert queued.status == "pending"
        assert report.processed == 1
        assert len(service.search("fake")) == 2
    finally:
        service.close()
