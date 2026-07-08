"""Application services for SAT recovery, queues, cache, and search."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from decimal import Decimal
import csv
from io import BytesIO
from io import StringIO
from pathlib import Path
from typing import Iterable
import xml.etree.ElementTree as ET
from uuid import uuid4
from zipfile import ZipFile

from sqlalchemy import func, or_, select
from sqlalchemy.exc import SQLAlchemyError

from cfdi_vault.cache import InMemoryCache
from cfdi_vault.cfdi_parser import CfdiVersionDetector, parser_for_version
from cfdi_vault.db import create_engine_from_url, create_session_factory
from cfdi_vault.domain import (
    DateTimePeriod,
    DownloadDirection,
    DownloadQuery,
    JobStatus,
    MetadataEntry,
    QueueMessage,
    QueueName,
    ReconciliationState,
    RequestType,
    SatRequestState,
)
from cfdi_vault.fake_sat import FakeSatClient
from cfdi_vault.metadata_parser import InvalidMetadataRow, parse_metadata_bytes
from cfdi_vault.ports import CachePort, QueuePort, SatClientPort, StoragePort
from cfdi_vault.queueing import InMemoryQueue
from cfdi_vault.reconciliation import decide_metadata_state
from cfdi_vault.recovery_db import (
    CfdiDocument,
    CfdiMetadataLedger,
    CfdiParty,
    DownloadJob,
    QueueJobEvent,
    ReconciliationEvent,
    SatPackageRecord,
    SatRequestRecord,
    Tenant,
    XmlEvidence,
    init_recovery_schema,
)
from cfdi_vault.storage import LocalStorage, sha256_bytes


@dataclass(frozen=True)
class DoctorCheck:
    """One operational diagnostic row."""

    name: str
    ok: bool
    detail: str


@dataclass(frozen=True)
class SyncResult:
    """Result of a fake or live sync request."""

    job_id: str
    request_id: str
    packages: tuple[str, ...]
    metadata_count: int
    status: str


@dataclass(frozen=True)
class DownloadStatus:
    """Safe persisted aggregate status for one local download job."""

    job_id: str
    request_id: str
    status: str
    sat_state: str
    kind: str
    direction: str
    criteria_hash: str
    metadata_count: int
    package_count: int
    downloaded_package_count: int
    xml_count: int


@dataclass(frozen=True)
class MetadataImportResult:
    """Result of ingesting a SAT-like metadata file."""

    accepted_count: int
    rejected_count: int
    invalid_rows: tuple[InvalidMetadataRow, ...]
    metadata_sha256: str
    storage_key: str


def read_download_status(database_url: str, tenant_id: str, job_id: str) -> DownloadStatus | None:
    """Read safe persisted aggregates for one download job without initializing schema."""

    engine = create_engine_from_url(database_url)
    try:
        session_factory = create_session_factory(engine)
        with session_factory() as session:
            job = session.scalar(
                select(DownloadJob).where(
                    DownloadJob.tenant_id == tenant_id,
                    DownloadJob.id == job_id,
                )
            )
            if job is None:
                return None

            request = session.scalar(
                select(SatRequestRecord)
                .where(
                    SatRequestRecord.tenant_id == tenant_id,
                    SatRequestRecord.job_id == job.id,
                )
                .order_by(SatRequestRecord.id.desc())
            )
            request_id = request.id_solicitud if request is not None else ""
            package_ids = _package_ids_for_request(session, tenant_id=tenant_id, request_id=request_id)

            return DownloadStatus(
                job_id=job.id,
                request_id=request_id,
                status=job.status,
                sat_state=request.sat_state if request is not None else "",
                kind=job.request_type,
                direction=job.direction,
                criteria_hash=job.criteria_hash,
                metadata_count=_metadata_count_for_packages(session, tenant_id=tenant_id, package_ids=package_ids),
                package_count=len(package_ids),
                downloaded_package_count=_downloaded_package_count(session, tenant_id=tenant_id, request_id=request_id),
                xml_count=_xml_count_for_packages(session, tenant_id=tenant_id, package_ids=package_ids),
            )
    except SQLAlchemyError:
        return None
    finally:
        engine.dispose()


def _package_ids_for_request(session: object, *, tenant_id: str, request_id: str) -> tuple[str, ...]:
    if not request_id:
        return ()
    return tuple(
        row[0]
        for row in session.execute(
            select(SatPackageRecord.id_paquete).where(
                SatPackageRecord.tenant_id == tenant_id,
                SatPackageRecord.id_solicitud == request_id,
            )
        ).all()
    )


def _metadata_count_for_packages(session: object, *, tenant_id: str, package_ids: tuple[str, ...]) -> int:
    if not package_ids:
        return 0
    count = session.scalar(
        select(func.count()).select_from(CfdiMetadataLedger).where(
            CfdiMetadataLedger.tenant_id == tenant_id,
            CfdiMetadataLedger.source_package_id.in_(package_ids),
        )
    )
    return int(count or 0)


def _downloaded_package_count(session: object, *, tenant_id: str, request_id: str) -> int:
    if not request_id:
        return 0
    count = session.scalar(
        select(func.count()).select_from(SatPackageRecord).where(
            SatPackageRecord.tenant_id == tenant_id,
            SatPackageRecord.id_solicitud == request_id,
            SatPackageRecord.status == "downloaded",
        )
    )
    return int(count or 0)


def _xml_count_for_packages(session: object, *, tenant_id: str, package_ids: tuple[str, ...]) -> int:
    if not package_ids:
        return 0
    count = session.scalar(
        select(func.count()).select_from(XmlEvidence).where(
            XmlEvidence.tenant_id == tenant_id,
            XmlEvidence.source_package_id.in_(package_ids),
        )
    )
    return int(count or 0)


class RecoveryService:
    """Use-case boundary for the v2 recovery architecture."""

    def __init__(
        self,
        *,
        database_url: str | None = None,
        storage_root: str | Path = "storage",
        sat_client: SatClientPort | None = None,
        queue: QueuePort | None = None,
        cache: CachePort | None = None,
    ) -> None:
        self.engine = create_engine_from_url(database_url)
        init_recovery_schema(self.engine)
        self.session_factory = create_session_factory(self.engine)
        self.storage: LocalStorage | StoragePort = LocalStorage(storage_root)
        self.sat_client = sat_client or FakeSatClient()
        self.queue = queue or InMemoryQueue()
        self.cache = cache or InMemoryCache()

    def close(self) -> None:
        """Release database resources, useful for Windows test cleanup."""

        self.engine.dispose()

    def doctor(self) -> tuple[DoctorCheck, ...]:
        checks: list[DoctorCheck] = []
        try:
            with self.session_factory() as session:
                session.execute(select(func.count()).select_from(Tenant)).scalar_one()
            checks.append(DoctorCheck("database", True, "schema reachable"))
        except Exception as exc:  # pragma: no cover - defensive CLI path
            checks.append(DoctorCheck("database", False, str(exc)))

        try:
            pending = self.queue.pending_count()
            checks.append(DoctorCheck("queue", True, f"adapter reachable; pending={pending}"))
        except Exception as exc:  # pragma: no cover - optional RabbitMQ path
            checks.append(DoctorCheck("queue", False, str(exc)))

        try:
            self.cache.set_json("doctor", {"ok": True}, ttl_seconds=30)
            checks.append(DoctorCheck("cache", self.cache.get_json("doctor") is not None, "adapter reachable"))
        except Exception as exc:  # pragma: no cover - optional Redis path
            checks.append(DoctorCheck("cache", False, str(exc)))

        try:
            paths = LocalStorage(getattr(self.storage, "root", "storage")).ensure_layout()
            checks.append(DoctorCheck("storage", True, ", ".join(str(path) for path in paths)))
        except Exception as exc:  # pragma: no cover - defensive CLI path
            checks.append(DoctorCheck("storage", False, str(exc)))

        return tuple(checks)

    def init_tenant(self, tenant_id: str, rfc: str, name: str | None = None) -> None:
        now = _now()
        with self.session_factory() as session:
            tenant = session.get(Tenant, tenant_id)
            if tenant is None:
                session.add(Tenant(id=tenant_id, name=name or tenant_id, rfc=rfc.upper(), created_at=now))
            else:
                tenant.name = name or tenant.name
                tenant.rfc = rfc.upper()
            session.commit()

    def sync_metadata(self, query: DownloadQuery, *, live: bool = False, enqueue: bool = False) -> SyncResult:
        if live:
            raise NotImplementedError("Live SAT SOAP is intentionally opt-in and not implemented in this slice.")

        errors = query.validate()
        if errors:
            raise ValueError("; ".join(errors))

        now = _now()
        criteria_hash = query.criteria_hash()
        self.init_tenant(query.tenant_id, query.requester_rfc, query.tenant_id)

        with self.session_factory() as session:
            existing = session.scalar(
                select(DownloadJob).where(
                    DownloadJob.tenant_id == query.tenant_id,
                    DownloadJob.criteria_hash == criteria_hash,
                )
            )
            if existing is not None:
                return self._result_for_existing_job(session, existing)

            job_id = str(uuid4())
            job = DownloadJob(
                id=job_id,
                tenant_id=query.tenant_id,
                rfc=query.requester_rfc.upper(),
                direction=query.direction.value,
                request_type=query.request_type.value,
                status=JobStatus.PENDING.value if enqueue else JobStatus.RUNNING.value,
                criteria_hash=criteria_hash,
                payload=_query_payload(query),
                created_at=now,
                updated_at=now,
            )
            session.add(job)
            self._event(
                session,
                job_id,
                QueueName.SAT_REQUEST,
                JobStatus.PENDING if enqueue else JobStatus.RUNNING,
                "metadata sync requested",
                _query_payload(query),
            )
            session.commit()

        self.cache.set_json(
            f"progress:{job_id}",
            {"status": JobStatus.PENDING.value if enqueue else "requesting", "metadata_count": 0},
            ttl_seconds=3600,
        )
        if enqueue:
            self.queue.publish(QueueMessage(QueueName.SAT_REQUEST, query.tenant_id, query.requester_rfc, _query_payload(query), job_id=job_id))
            return SyncResult(job_id=job_id, request_id="", packages=(), metadata_count=0, status=JobStatus.PENDING.value)

        return self._process_sat_request_job(query, job_id=job_id)

    def process_queue_message(self, message: QueueMessage) -> SyncResult:
        """Process one queued SAT request message."""

        query = _query_from_payload(message.payload)
        return self._process_sat_request_job(query, job_id=message.job_id)

    def ingest_metadata_file(
        self,
        query: DownloadQuery,
        content: bytes,
        *,
        delimiter: str | None = None,
        source_package_id: str = "",
    ) -> MetadataImportResult:
        """Parse and reconcile one SAT-like metadata TXT/CSV file."""

        errors = query.validate()
        if errors:
            raise ValueError("; ".join(errors))
        self.init_tenant(query.tenant_id, query.requester_rfc, query.tenant_id)
        parsed = parse_metadata_bytes(content, delimiter=delimiter, source_package_id=source_package_id)
        metadata_sha256 = sha256_bytes(content)
        metadata_key = self.storage.metadata_key(
            query.requester_rfc,
            _storage_period(query),
            source_package_id or f"metadata-{query.criteria_hash()[:12]}",
            metadata_sha256,
            extension=_metadata_extension(content, delimiter=delimiter),
        )
        metadata_file = self.storage.write_bytes_idempotent(metadata_key, content)
        with self.session_factory() as session:
            count = self._upsert_metadata(session, query, parsed.entries, metadata_sha256=metadata_file.sha256)
            session.commit()
        return MetadataImportResult(
            accepted_count=count,
            rejected_count=parsed.rejected_count,
            invalid_rows=parsed.invalid_rows,
            metadata_sha256=metadata_file.sha256,
            storage_key=str(metadata_file.path),
        )

    def _process_sat_request_job(self, query: DownloadQuery, *, job_id: str) -> SyncResult:
        now = _now()
        criteria_hash = query.criteria_hash()
        self.cache.set_json(f"progress:{job_id}", {"status": "requesting", "metadata_count": 0}, ttl_seconds=3600)
        with self.session_factory() as session:
            job = session.get(DownloadJob, job_id)
            if job is not None:
                job.status = JobStatus.RUNNING.value
                job.updated_at = now
                session.commit()

        request_id = self.sat_client.submit_request(query)
        verify_result = self.sat_client.verify_request(request_id)
        state = str(verify_result.get("state", SatRequestState.ERROR.value))
        packages = tuple(str(package_id) for package_id in verify_result.get("packages", ()))
        metadata = tuple(_metadata_from_dict(item) for item in verify_result.get("metadata", ()) if isinstance(item, dict))

        with self.session_factory() as session:
            metadata_csv = _metadata_csv_bytes(request_id, packages, metadata)
            metadata_sha256 = sha256_bytes(metadata_csv)
            metadata_key = self.storage.metadata_key(query.requester_rfc, _storage_period(query), request_id, metadata_sha256)
            metadata_file = self.storage.write_bytes_idempotent(metadata_key, metadata_csv)
            request_record = SatRequestRecord(
                tenant_id=query.tenant_id,
                job_id=job_id,
                id_solicitud=request_id,
                criteria_hash=criteria_hash,
                direction=query.direction.value,
                request_type=query.request_type.value,
                sat_state=state,
                sat_code=str(verify_result.get("sat_code") or ""),
                sat_message=str(verify_result.get("message") or ""),
                requested_at=now,
                last_verified_at=_now(),
                metadata_sha256=metadata_file.sha256,
                metadata_storage_key=str(metadata_file.path),
                raw_response=dict(verify_result),
            )
            session.add(request_record)
            self._event(session, job_id, QueueName.SAT_VERIFY, JobStatus.SUCCEEDED, f"SAT state={state}", dict(verify_result))
            package_contents: dict[str, bytes] = {}
            for package_id in packages:
                existing_package = session.scalar(
                    select(SatPackageRecord).where(
                        SatPackageRecord.tenant_id == query.tenant_id,
                        SatPackageRecord.id_paquete == package_id,
                    )
                )
                if (
                    existing_package is not None
                    and existing_package.status == "downloaded"
                    and existing_package.storage_key
                    and Path(existing_package.storage_key).exists()
                ):
                    content = Path(existing_package.storage_key).read_bytes()
                    package_contents[package_id] = content
                    self._event(
                        session,
                        job_id,
                        QueueName.SAT_DOWNLOAD,
                        JobStatus.SUCCEEDED,
                        f"reused downloaded package {package_id}",
                        {"sha256": existing_package.sha256_zip or ""},
                    )
                    continue

                content = self.sat_client.download_package(package_id)
                package_contents[package_id] = content
                package_sha256 = sha256_bytes(content)
                package_key = self.storage.package_key(query.requester_rfc, _storage_period(query), package_id, package_sha256)
                package_file = self.storage.write_bytes_idempotent(package_key, content)
                if existing_package is None:
                    session.add(
                        SatPackageRecord(
                            tenant_id=query.tenant_id,
                            id_paquete=package_id,
                            id_solicitud=request_id,
                            status="downloaded",
                            attempts=1,
                            sha256_zip=package_file.sha256,
                            size_bytes=package_file.size_bytes,
                            storage_key=str(package_file.path),
                            downloaded_at=_now(),
                            expires_at=None,
                            last_error={},
                            created_at=now,
                            updated_at=_now(),
                        )
                    )
                else:
                    existing_package.id_solicitud = request_id
                    existing_package.status = "downloaded"
                    existing_package.attempts += 1
                    existing_package.sha256_zip = package_file.sha256
                    existing_package.size_bytes = package_file.size_bytes
                    existing_package.storage_key = str(package_file.path)
                    existing_package.downloaded_at = _now()
                    existing_package.updated_at = _now()
                    existing_package.last_error = {}
                self._event(
                    session,
                    job_id,
                    QueueName.SAT_DOWNLOAD,
                    JobStatus.SUCCEEDED,
                    f"downloaded {package_id}",
                    {"sha256": package_file.sha256, "storage_key": str(package_file.path)},
                )

            upserted = self._upsert_metadata(session, query, metadata, metadata_sha256=metadata_file.sha256)
            session.flush()
            self._event(session, job_id, QueueName.CFDI_PARSE_METADATA, JobStatus.SUCCEEDED, f"metadata rows={upserted}", {})
            if query.request_type == RequestType.CFDI:
                xml_count = 0
                for package_id, content in package_contents.items():
                    xml_count += self._store_xml_package(session, query, package_id, content)
                self._event(session, job_id, QueueName.CFDI_PARSE_XML, JobStatus.SUCCEEDED, f"xml rows={xml_count}", {})
            self._event(session, job_id, QueueName.CFDI_RECONCILE, JobStatus.SUCCEEDED, "metadata reconciled", {})
            job = session.get(DownloadJob, job_id)
            if job is not None:
                job.status = JobStatus.SUCCEEDED.value
                job.updated_at = _now()
            session.commit()

        self.cache.set_json(
            f"progress:{job_id}",
            {"status": JobStatus.SUCCEEDED.value, "metadata_count": len(metadata), "packages": list(packages)},
            ttl_seconds=86400,
        )
        return SyncResult(job_id=job_id, request_id=request_id, packages=packages, metadata_count=len(metadata), status=JobStatus.SUCCEEDED.value)

    def _result_for_existing_job(self, session: object, job: DownloadJob) -> SyncResult:
        request = session.scalar(select(SatRequestRecord).where(SatRequestRecord.job_id == job.id))
        if request is None:
            return SyncResult(job_id=job.id, request_id="", packages=(), metadata_count=0, status=job.status)
        package_ids = tuple(
            row[0]
            for row in session.execute(
                select(SatPackageRecord.id_paquete).where(
                    SatPackageRecord.tenant_id == job.tenant_id,
                    SatPackageRecord.id_solicitud == request.id_solicitud,
                )
            ).all()
        )
        count_statement = select(func.count()).select_from(CfdiMetadataLedger).where(CfdiMetadataLedger.tenant_id == job.tenant_id)
        if package_ids:
            count_statement = count_statement.where(CfdiMetadataLedger.source_package_id.in_(package_ids))
        else:
            count_statement = count_statement.where(CfdiMetadataLedger.source_package_id == "__none__")
        count = session.scalar(count_statement)
        return SyncResult(
            job_id=job.id,
            request_id=request.id_solicitud,
            packages=package_ids,
            metadata_count=int(count or 0),
            status=job.status,
        )

    def queue_status(self) -> tuple[dict[str, object], ...]:
        with self.session_factory() as session:
            rows = session.execute(
                select(QueueJobEvent.queue_name, QueueJobEvent.status, func.count(QueueJobEvent.id))
                .group_by(QueueJobEvent.queue_name, QueueJobEvent.status)
                .order_by(QueueJobEvent.queue_name, QueueJobEvent.status)
            ).all()
        return tuple({"queue": queue, "status": status, "count": int(count)} for queue, status, count in rows)

    def progress(self, job_id: str) -> dict[str, object] | None:
        return self.cache.get_json(f"progress:{job_id}")

    def search(self, text: str = "", *, tenant_id: str | None = None, limit: int = 20) -> tuple[dict[str, object], ...]:
        with self.session_factory() as session:
            statement = select(CfdiDocument).order_by(CfdiDocument.issue_date.desc(), CfdiDocument.uuid).limit(limit)
            filters = []
            if tenant_id:
                filters.append(CfdiDocument.tenant_id == tenant_id)
            normalized = text.strip().lower()
            if normalized:
                pattern = f"%{normalized}%"
                filters.append(
                    or_(
                        func.lower(CfdiDocument.uuid).like(pattern),
                        func.lower(CfdiDocument.issuer_rfc).like(pattern),
                        func.lower(CfdiDocument.issuer_name).like(pattern),
                        func.lower(CfdiDocument.receiver_rfc).like(pattern),
                        func.lower(CfdiDocument.receiver_name).like(pattern),
                        func.lower(CfdiDocument.search_text).like(pattern),
                    )
                )
            if filters:
                statement = statement.where(*filters)
            docs = session.scalars(statement).all()
        return tuple(_document_row(doc) for doc in docs)

    def show(self, uuid: str, *, tenant_id: str | None = None) -> dict[str, object] | None:
        with self.session_factory() as session:
            statement = select(CfdiDocument).where(func.lower(CfdiDocument.uuid) == uuid.lower())
            if tenant_id:
                statement = statement.where(CfdiDocument.tenant_id == tenant_id)
            doc = session.scalar(statement)
            return _document_row(doc) if doc else None

    def render_text(self, uuid: str, *, tenant_id: str | None = None) -> str:
        doc = self.show(uuid, tenant_id=tenant_id)
        if doc is None:
            raise LookupError(f"CFDI not found: {uuid}")
        return "\n".join(
            [
                f"CFDI {doc['uuid']}",
                f"Status: {doc['status']} | Parser: {doc['parser_status']}",
                f"Issuer: {doc['issuer_name']} ({doc['issuer_rfc']})",
                f"Receiver: {doc['receiver_name']} ({doc['receiver_rfc']})",
                f"Issue date: {doc['issue_date']}",
                f"Type: {doc['document_type']} | Currency: {doc['currency']}",
                f"Subtotal: {doc['subtotal']} | Total: {doc['total']}",
            ]
        )

    def render_html(self, uuid: str, *, tenant_id: str | None = None) -> str:
        doc = self.show(uuid, tenant_id=tenant_id)
        if doc is None:
            raise LookupError(f"CFDI not found: {uuid}")
        warning = ""
        if doc["parser_status"] != "complete":
            warning = "<p><strong>Warning:</strong> this CFDI was parsed partially. Use XML evidence for audit.</p>"
        return f"""<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>CFDI {doc['uuid']}</title></head>
<body>
<h1>CFDI {doc['uuid']}</h1>
{warning}
<table>
<tr><th>Status</th><td>{doc['status']}</td></tr>
<tr><th>Issuer</th><td>{doc['issuer_name']} ({doc['issuer_rfc']})</td></tr>
<tr><th>Receiver</th><td>{doc['receiver_name']} ({doc['receiver_rfc']})</td></tr>
<tr><th>Issue date</th><td>{doc['issue_date']}</td></tr>
<tr><th>Type</th><td>{doc['document_type']}</td></tr>
<tr><th>Total</th><td>{doc['total']} {doc['currency']}</td></tr>
</table>
</body>
</html>
"""

    def export_csv(self, output_path: str | Path, *, tenant_id: str | None = None) -> int:
        rows = self.search("", tenant_id=tenant_id, limit=100000)
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        columns = [
            "uuid",
            "issuer_rfc",
            "issuer_name",
            "receiver_rfc",
            "receiver_name",
            "issue_date",
            "document_type",
            "status",
            "currency",
            "subtotal",
            "total",
            "parser_status",
        ]
        with path.open("w", newline="", encoding="utf-8") as csv_file:
            writer = csv.DictWriter(csv_file, fieldnames=columns)
            writer.writeheader()
            for row in rows:
                writer.writerow({column: row.get(column, "") for column in columns})
        return len(rows)

    def reconcile(self, *, tenant_id: str | None = None) -> int:
        with self.session_factory() as session:
            statement = select(CfdiMetadataLedger)
            if tenant_id:
                statement = statement.where(CfdiMetadataLedger.tenant_id == tenant_id)
            ledgers = session.scalars(statement).all()
            count = 0
            for ledger in ledgers:
                existing = session.scalar(
                    select(CfdiDocument).where(CfdiDocument.tenant_id == ledger.tenant_id, CfdiDocument.uuid == ledger.uuid)
                )
                new_state = (
                    ReconciliationState.XML_DOWNLOADED.value
                    if existing and existing.xml_sha256
                    else _metadata_state(str(ledger.status or ""), has_xml=bool(existing and existing.xml_sha256))
                )
                if ledger.reconciliation_state != new_state:
                    session.add(
                        ReconciliationEvent(
                            tenant_id=ledger.tenant_id,
                            uuid=ledger.uuid,
                            previous_state=ledger.reconciliation_state,
                            new_state=new_state,
                            reason="reconcile command",
                            actor="cli",
                            created_at=_now(),
                        )
                    )
                    ledger.reconciliation_state = new_state
                    count += 1
            session.commit()
        return count

    def _upsert_metadata(
        self,
        session: object,
        query: DownloadQuery,
        metadata: Iterable[MetadataEntry],
        *,
        metadata_sha256: str,
    ) -> int:
        count = 0
        now = _now()
        for entry in metadata:
            existing = session.scalar(
                select(CfdiMetadataLedger).where(
                    CfdiMetadataLedger.tenant_id == query.tenant_id,
                    CfdiMetadataLedger.uuid == entry.uuid,
                    CfdiMetadataLedger.direction == query.direction.value,
                )
            )
            raw_payload = _metadata_payload(entry)
            has_xml = _has_xml_evidence(session, query.tenant_id, entry.uuid)
            new_state = _metadata_state(entry.status, has_xml=has_xml, is_new=existing is None, previous_status=existing.status if existing else None)
            if existing is None:
                session.add(
                    CfdiMetadataLedger(
                        tenant_id=query.tenant_id,
                        uuid=entry.uuid,
                        direction=query.direction.value,
                        issuer_rfc=entry.issuer_rfc,
                        issuer_name=entry.issuer_name,
                        receiver_rfc=entry.receiver_rfc,
                        receiver_name=entry.receiver_name,
                        issue_date=entry.issue_date,
                        total=entry.total,
                        status=entry.status,
                        effect=entry.effect,
                        reconciliation_state=new_state,
                        source_package_id=entry.source_package_id,
                        source_metadata_sha256=metadata_sha256,
                        first_seen_at=now,
                        last_seen_at=now,
                        raw_payload=raw_payload,
                    )
                )
                session.add(
                    ReconciliationEvent(
                        tenant_id=query.tenant_id,
                        uuid=entry.uuid,
                        previous_state=None,
                        new_state=new_state,
                        reason="metadata discovered",
                        actor="fake-sat",
                        created_at=now,
                    )
                )
            else:
                previous_state = existing.reconciliation_state
                existing.issuer_rfc = entry.issuer_rfc
                existing.issuer_name = entry.issuer_name
                existing.receiver_rfc = entry.receiver_rfc
                existing.receiver_name = entry.receiver_name
                existing.issue_date = entry.issue_date
                existing.total = entry.total
                existing.status = entry.status
                existing.effect = entry.effect
                existing.reconciliation_state = new_state
                existing.source_package_id = entry.source_package_id
                existing.source_metadata_sha256 = metadata_sha256
                existing.last_seen_at = now
                existing.raw_payload = raw_payload
                if previous_state != new_state:
                    session.add(
                        ReconciliationEvent(
                            tenant_id=query.tenant_id,
                            uuid=entry.uuid,
                            previous_state=previous_state,
                            new_state=new_state,
                            reason="metadata state updated",
                            actor="fake-sat",
                            created_at=now,
                        )
                    )

            if query.request_type == RequestType.METADATA:
                document = session.scalar(select(CfdiDocument).where(CfdiDocument.tenant_id == query.tenant_id, CfdiDocument.uuid == entry.uuid))
                if document is None:
                    document = CfdiDocument(
                        tenant_id=query.tenant_id,
                        uuid=entry.uuid,
                        version=None,
                        document_type=entry.effect,
                        status=entry.status,
                        issue_date=entry.issue_date,
                        certified_at=None,
                        currency="MXN",
                        subtotal=None,
                        discount=None,
                        total=entry.total,
                        issuer_rfc=entry.issuer_rfc,
                        issuer_name=entry.issuer_name,
                        receiver_rfc=entry.receiver_rfc,
                        receiver_name=entry.receiver_name,
                        payment_method=None,
                        payment_form=None,
                        download_state=new_state,
                        xml_sha256=None,
                        parser_status="metadata_only",
                        search_text=_search_text(entry),
                        raw_payload=raw_payload,
                        created_at=now,
                        updated_at=now,
                    )
                    session.add(document)
                    session.add_all(
                        [
                            CfdiParty(tenant_id=query.tenant_id, rfc=entry.issuer_rfc, name=entry.issuer_name, role="issuer", document_uuid=entry.uuid),
                            CfdiParty(tenant_id=query.tenant_id, rfc=entry.receiver_rfc, name=entry.receiver_name, role="receiver", document_uuid=entry.uuid),
                        ]
                    )
                else:
                    document.updated_at = now
                    document.status = entry.status
                    document.document_type = entry.effect
                    document.issue_date = entry.issue_date
                    document.total = entry.total
                    document.issuer_rfc = entry.issuer_rfc
                    document.issuer_name = entry.issuer_name
                    document.receiver_rfc = entry.receiver_rfc
                    document.receiver_name = entry.receiver_name
                    if document.xml_sha256 is None:
                        document.download_state = new_state
                    document.raw_payload = raw_payload

            count += 1
        return count

    def _store_xml_package(self, session: object, query: DownloadQuery, package_id: str, content: bytes) -> int:
        count = 0
        detector = CfdiVersionDetector()
        with ZipFile(BytesIO(content)) as archive:
            for member in sorted(archive.namelist()):
                if member.endswith("/") or not member.lower().endswith(".xml"):
                    continue
                xml_bytes = archive.read(member)
                version = detector.detect(xml_bytes)
                parsed = parser_for_version(version).parse(xml_bytes)
                concepts = _concept_descriptions(xml_bytes)
                uuid = parsed.parsed.uuid.upper()
                xml_sha256 = sha256_bytes(xml_bytes)
                xml_period = parsed.parsed.issue_date or _storage_period(query)
                storage_key = self.storage.xml_key(query.requester_rfc, xml_period, uuid, xml_sha256)
                stored_xml = self.storage.write_bytes_idempotent(storage_key, xml_bytes)
                raw_payload = {
                    "version": parsed.version,
                    "complements": list(parsed.complements),
                    "concepts": list(concepts),
                    "source_package_id": package_id,
                    "xml_sha256": xml_sha256,
                }
                document = session.scalar(select(CfdiDocument).where(CfdiDocument.tenant_id == query.tenant_id, CfdiDocument.uuid == uuid))
                if document is None:
                    document = CfdiDocument(
                        tenant_id=query.tenant_id,
                        uuid=uuid,
                        version=parsed.version,
                        document_type=parsed.parsed.comprobante_type,
                        status="vigente",
                        issue_date=parsed.parsed.issue_date,
                        certified_at=None,
                        currency=parsed.parsed.currency,
                        subtotal=parsed.parsed.subtotal,
                        discount=None,
                        total=parsed.parsed.total,
                        issuer_rfc=parsed.parsed.issuer_rfc,
                        issuer_name=parsed.parsed.issuer_name,
                        receiver_rfc=parsed.parsed.receiver_rfc,
                        receiver_name=parsed.parsed.receiver_name,
                        payment_method=parsed.parsed.payment_method,
                        payment_form=parsed.parsed.payment_form,
                        download_state=ReconciliationState.XML_DOWNLOADED.value,
                        xml_sha256=xml_sha256,
                        parser_status=parsed.parser_status,
                        search_text=_parsed_search_text(parsed.parsed, concepts),
                        raw_payload=raw_payload,
                        created_at=_now(),
                        updated_at=_now(),
                    )
                    session.add(document)
                    session.add_all(
                        [
                            CfdiParty(
                                tenant_id=query.tenant_id,
                                rfc=parsed.parsed.issuer_rfc,
                                name=parsed.parsed.issuer_name,
                                role="issuer",
                                document_uuid=uuid,
                            ),
                            CfdiParty(
                                tenant_id=query.tenant_id,
                                rfc=parsed.parsed.receiver_rfc,
                                name=parsed.parsed.receiver_name,
                                role="receiver",
                                document_uuid=uuid,
                            ),
                        ]
                    )
                else:
                    document.version = parsed.version
                    document.document_type = parsed.parsed.comprobante_type
                    document.issue_date = parsed.parsed.issue_date
                    document.currency = parsed.parsed.currency
                    document.subtotal = parsed.parsed.subtotal
                    document.total = parsed.parsed.total
                    document.issuer_rfc = parsed.parsed.issuer_rfc
                    document.issuer_name = parsed.parsed.issuer_name
                    document.receiver_rfc = parsed.parsed.receiver_rfc
                    document.receiver_name = parsed.parsed.receiver_name
                    document.payment_method = parsed.parsed.payment_method
                    document.payment_form = parsed.parsed.payment_form
                    document.download_state = ReconciliationState.XML_DOWNLOADED.value
                    document.xml_sha256 = xml_sha256
                    document.parser_status = parsed.parser_status
                    document.search_text = _parsed_search_text(parsed.parsed, concepts)
                    document.raw_payload = raw_payload
                    document.updated_at = _now()

                existing_evidence = session.scalar(
                    select(XmlEvidence).where(
                        XmlEvidence.tenant_id == query.tenant_id,
                        XmlEvidence.uuid == uuid,
                        XmlEvidence.xml_sha256 == xml_sha256,
                    )
                )
                if existing_evidence is None:
                    session.add(
                        XmlEvidence(
                            tenant_id=query.tenant_id,
                            uuid=uuid,
                            source_package_id=package_id,
                            xml_sha256=xml_sha256,
                            size_bytes=stored_xml.size_bytes,
                            storage_key=str(stored_xml.path),
                            parser_version=f"cfdi-{parsed.version or 'unknown'}",
                            parser_status=parsed.parser_status,
                            created_at=_now(),
                        )
                    )
                ledger = session.scalar(
                    select(CfdiMetadataLedger).where(
                        CfdiMetadataLedger.tenant_id == query.tenant_id,
                        CfdiMetadataLedger.uuid == uuid,
                        CfdiMetadataLedger.direction == query.direction.value,
                    )
                )
                if ledger is not None:
                    previous_state = ledger.reconciliation_state
                    ledger.reconciliation_state = ReconciliationState.XML_DOWNLOADED.value
                    if previous_state != ReconciliationState.XML_DOWNLOADED.value:
                        session.add(
                            ReconciliationEvent(
                                tenant_id=query.tenant_id,
                                uuid=uuid,
                                previous_state=previous_state,
                                new_state=ReconciliationState.XML_DOWNLOADED.value,
                                reason="xml evidence stored",
                                actor="fake-sat",
                                created_at=_now(),
                            )
                        )
                count += 1
        return count

    def _event(
        self,
        session: object,
        job_id: str,
        queue_name: QueueName,
        status: JobStatus,
        message: str,
        payload: dict[str, object],
    ) -> None:
        session.add(
            QueueJobEvent(
                job_id=job_id,
                queue_name=queue_name.value,
                status=status.value,
                correlation_id=str(uuid4()),
                attempt=0,
                message=message,
                payload=payload,
                created_at=_now(),
            )
        )


def build_default_query(
    *,
    tenant_id: str,
    rfc: str,
    direction: DownloadDirection,
    request_type: RequestType,
    start: datetime,
    end: datetime,
) -> DownloadQuery:
    return DownloadQuery(
        tenant_id=tenant_id,
        requester_rfc=rfc,
        direction=direction,
        request_type=request_type,
        period=DateTimePeriod(start=start, end=end),
    )


def write_minimal_pdf(output_path: str | Path, text: str) -> None:
    """Write a tiny text-only PDF without adding a heavy dependency."""

    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    escaped = text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
    lines = escaped.splitlines() or [""]
    stream_lines = ["BT", "/F1 11 Tf", "50 780 Td"]
    for index, line in enumerate(lines[:45]):
        if index:
            stream_lines.append("0 -16 Td")
        stream_lines.append(f"({line}) Tj")
    stream_lines.append("ET")
    stream = "\n".join(stream_lines).encode("latin-1", errors="replace")
    objects = [
        b"1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj\n",
        b"2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj\n",
        b"3 0 obj << /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >> endobj\n",
        b"4 0 obj << /Type /Font /Subtype /Type1 /BaseFont /Helvetica >> endobj\n",
        b"5 0 obj << /Length " + str(len(stream)).encode("ascii") + b" >> stream\n" + stream + b"\nendstream endobj\n",
    ]
    content = bytearray(b"%PDF-1.4\n")
    offsets = [0]
    for obj in objects:
        offsets.append(len(content))
        content.extend(obj)
    xref_start = len(content)
    content.extend(f"xref\n0 {len(objects) + 1}\n0000000000 65535 f \n".encode("ascii"))
    for offset in offsets[1:]:
        content.extend(f"{offset:010d} 00000 n \n".encode("ascii"))
    content.extend(f"trailer << /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref_start}\n%%EOF\n".encode("ascii"))
    path.write_bytes(bytes(content))


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _query_payload(query: DownloadQuery) -> dict[str, object]:
    return {
        "tenant_id": query.tenant_id,
        "requester_rfc": query.requester_rfc.upper(),
        "direction": query.direction.value,
        "request_type": query.request_type.value,
        "period": query.period.as_dict() if query.period else None,
        "issuer_rfc": query.issuer_rfc,
        "receiver_rfcs": list(query.receiver_rfcs),
        "uuid": query.uuid,
        "document_status": query.document_status,
        "document_type": query.document_type,
        "complement": query.complement,
        "rfc_on_behalf": query.rfc_on_behalf,
        "criteria_hash": query.criteria_hash(),
    }


def _query_from_payload(payload: dict[str, object]) -> DownloadQuery:
    period_payload = payload.get("period")
    period = None
    if isinstance(period_payload, dict):
        period = DateTimePeriod(
            start=datetime.fromisoformat(str(period_payload["start"])),
            end=datetime.fromisoformat(str(period_payload["end"])),
        )
    return DownloadQuery(
        tenant_id=str(payload["tenant_id"]),
        requester_rfc=str(payload["requester_rfc"]),
        direction=DownloadDirection(str(payload["direction"])),
        request_type=RequestType(str(payload["request_type"])),
        period=period,
        issuer_rfc=str(payload["issuer_rfc"]) if payload.get("issuer_rfc") else None,
        receiver_rfcs=tuple(str(value) for value in (payload.get("receiver_rfcs") or ())),
        uuid=str(payload["uuid"]) if payload.get("uuid") else None,
        document_status=str(payload["document_status"]) if payload.get("document_status") else None,
        document_type=str(payload["document_type"]) if payload.get("document_type") else None,
        complement=str(payload["complement"]) if payload.get("complement") else None,
        rfc_on_behalf=str(payload["rfc_on_behalf"]) if payload.get("rfc_on_behalf") else None,
    )


def _metadata_from_dict(item: dict[str, object]) -> MetadataEntry:
    return MetadataEntry(
        uuid=str(item["uuid"]),
        issuer_rfc=str(item["issuer_rfc"]),
        issuer_name=str(item["issuer_name"]),
        receiver_rfc=str(item["receiver_rfc"]),
        receiver_name=str(item["receiver_name"]),
        issue_date=datetime.fromisoformat(str(item["issue_date"])),
        total=Decimal(str(item["total"])),
        status=str(item["status"]),
        effect=str(item["effect"]),
        source_package_id=str(item["source_package_id"]),
    )


def _metadata_csv_bytes(request_id: str, packages: Iterable[str], metadata: Iterable[MetadataEntry]) -> bytes:
    """Serialize SAT metadata rows as the local primary index for a request."""

    package_set = tuple(packages)
    output = StringIO(newline="")
    fieldnames = (
        "idSolicitud",
        "idPaquete",
        "uuid",
        "rfcEmisor",
        "rfcReceptor",
        "fechaEmision",
        "estadoComprobante",
        "tipoComprobante",
    )
    writer = csv.DictWriter(output, fieldnames=fieldnames)
    writer.writeheader()
    for entry in sorted(metadata, key=lambda item: item.uuid):
        writer.writerow(
            {
                "idSolicitud": request_id,
                "idPaquete": entry.source_package_id or (package_set[0] if package_set else ""),
                "uuid": entry.uuid,
                "rfcEmisor": entry.issuer_rfc,
                "rfcReceptor": entry.receiver_rfc,
                "fechaEmision": entry.issue_date.isoformat(),
                "estadoComprobante": entry.status,
                "tipoComprobante": entry.effect,
            }
        )
    return output.getvalue().encode("utf-8")


def _metadata_payload(entry: MetadataEntry) -> dict[str, object]:
    return {
        "uuid": entry.uuid,
        "issuer_rfc": entry.issuer_rfc,
        "issuer_name": entry.issuer_name,
        "receiver_rfc": entry.receiver_rfc,
        "receiver_name": entry.receiver_name,
        "issue_date": entry.issue_date.isoformat(),
        "total": str(entry.total),
        "status": entry.status,
        "effect": entry.effect,
        "source_package_id": entry.source_package_id,
    }


def _search_text(entry: MetadataEntry) -> str:
    return " ".join(
        [entry.uuid, entry.issuer_rfc, entry.issuer_name, entry.receiver_rfc, entry.receiver_name, entry.status, entry.effect]
    ).lower()


def _metadata_state(status: str, *, has_xml: bool, is_new: bool = False, previous_status: str | None = None) -> str:
    return decide_metadata_state(status, has_xml=has_xml, is_new=is_new, previous_status=previous_status).state.value


def _metadata_extension(content: bytes, *, delimiter: str | None) -> str:
    first_line = content.splitlines()[0] if content.splitlines() else b""
    if delimiter in {"|", "\t"} or b"|" in first_line or b"\t" in first_line:
        return "txt"
    return "csv"


def _has_xml_evidence(session: object, tenant_id: str, uuid: str) -> bool:
    return (
        session.scalar(
            select(func.count())
            .select_from(XmlEvidence)
            .where(XmlEvidence.tenant_id == tenant_id, XmlEvidence.uuid == uuid)
        )
        or 0
    ) > 0


def _storage_period(query: DownloadQuery) -> datetime:
    if query.period is not None:
        return query.period.start
    return datetime.now(timezone.utc)


def _concept_descriptions(xml_bytes: bytes) -> tuple[str, ...]:
    root = ET.fromstring(xml_bytes)
    descriptions: list[str] = []
    for element in root.iter():
        local_name = element.tag.rsplit("}", 1)[-1] if "}" in element.tag else element.tag
        if local_name == "Concepto" and element.attrib.get("Descripcion"):
            descriptions.append(str(element.attrib["Descripcion"]))
    return tuple(descriptions)


def _parsed_search_text(parsed: object, concepts: Iterable[str] = ()) -> str:
    return " ".join(
        [
            str(getattr(parsed, "uuid", "")),
            str(getattr(parsed, "issuer_rfc", "")),
            str(getattr(parsed, "issuer_name", "")),
            str(getattr(parsed, "receiver_rfc", "")),
            str(getattr(parsed, "receiver_name", "")),
            str(getattr(parsed, "comprobante_type", "")),
            *[str(concept) for concept in concepts],
        ]
    ).lower()


def _document_row(doc: CfdiDocument) -> dict[str, object]:
    return {
        "uuid": doc.uuid,
        "tenant_id": doc.tenant_id,
        "version": doc.version or "",
        "document_type": doc.document_type or "",
        "status": doc.status or "",
        "issue_date": doc.issue_date.isoformat() if doc.issue_date else "",
        "currency": doc.currency or "",
        "subtotal": str(doc.subtotal) if doc.subtotal is not None else "",
        "total": str(doc.total) if doc.total is not None else "",
        "issuer_rfc": doc.issuer_rfc or "",
        "issuer_name": doc.issuer_name or "",
        "receiver_rfc": doc.receiver_rfc or "",
        "receiver_name": doc.receiver_name or "",
        "payment_method": doc.payment_method or "",
        "payment_form": doc.payment_form or "",
        "download_state": doc.download_state,
        "xml_sha256": doc.xml_sha256 or "",
        "parser_status": doc.parser_status,
    }
