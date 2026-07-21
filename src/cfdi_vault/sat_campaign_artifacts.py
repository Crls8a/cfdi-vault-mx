"""Coordinate external SAT package storage with durable database references."""

from __future__ import annotations

import codecs
import hashlib
import io
import stat
from datetime import datetime, timedelta, timezone
from pathlib import Path, PurePosixPath
from typing import Callable, Iterable
from xml.etree import ElementTree
from zipfile import BadZipFile, ZipFile

from cfdi_vault.domain import QueueMessage
from cfdi_vault.metadata_parser import FIELD_ALIASES, REQUIRED_METADATA_FIELDS
from cfdi_vault.sat_artifact_store import StoredArtifact, write_artifact
from cfdi_vault.sat_campaign_ledger_handoff import DurableArtifactJobHandoff
from cfdi_vault.sat_campaign_repository import SatCampaignRepository


class CampaignArtifactError(RuntimeError):
    """Expose a fixed reason when package persistence cannot complete."""

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


class SatCampaignArtifactCoordinator:
    """Persist package bytes externally, then register only safe metadata."""

    def __init__(self, repository: SatCampaignRepository, storage_root: str,
                 job_publisher: Callable[[QueueMessage], None] | None = None,
                 durable_handoff: DurableArtifactJobHandoff | None = None) -> None:
        self._repository = repository
        self._storage_root = storage_root
        self._job_publisher = job_publisher
        if durable_handoff is not None and job_publisher is not None:
            raise ValueError("durable handoff and legacy publisher are mutually exclusive")
        self._durable_handoff = durable_handoff

    def ensure_ready(self, *, require_handoff: bool = False) -> None:
        """Validate external storage and parsing handoff before SAT contact."""

        try:
            raw_root = str(self._storage_root).replace("\\", "/").rstrip("/")
            if raw_root == "/app" or raw_root.startswith("/app/"):
                raise ValueError
            root = Path(self._storage_root)
            if not root.is_absolute():
                raise ValueError
            resolved = root.resolve(strict=False)
            checkout = Path(__file__).resolve().parents[2]
            if resolved == checkout or checkout in resolved.parents:
                raise ValueError
            if resolved.exists() and not resolved.is_dir():
                raise ValueError
            if require_handoff and self._durable_handoff is not None:
                if not all(callable(getattr(self._durable_handoff, name, None))
                           for name in ("persist_on_connection", "publish_after_commit")):
                    raise ValueError
            elif require_handoff and not callable(self._job_publisher):
                raise ValueError
        except Exception:
            raise CampaignArtifactError("artifact-runtime-unavailable") from None

    def store_package(
        self,
        *,
        campaign_ref: str,
        work_ref: str,
        request_id: int,
        package_ref: str,
        ordinal: int,
        kind: str,
        chunks: Iterable[bytes],
        max_bytes: int,
        claim_ref: str | None = None,
        now: datetime | None = None,
    ) -> StoredArtifact:
        """Claim one download, write its bytes, and commit an opaque DB link.

        The external write happens only after the download claim is durable.
        PostgreSQL receives the storage key, hash, size, and validation state;
        package bytes never enter a SQL column.
        """

        if kind not in {"metadata_zip", "cfdi_zip"}:
            raise CampaignArtifactError("artifact-kind-invalid")
        if type(max_bytes) is not int or max_bytes <= 0 or max_bytes > 512 * 1024 * 1024:
            raise CampaignArtifactError("artifact-package-limit-invalid")
        if type(package_ref) is not str or not package_ref or len(package_ref) > 96:
            raise CampaignArtifactError("package-reference-invalid")
        if type(ordinal) is not int or ordinal <= 0:
            raise CampaignArtifactError("package-ordinal-invalid")
        current = _utc(now or datetime.now(timezone.utc))
        self.ensure_ready()
        request = self._repository.get_request(request_id)
        if request is None:
            raise CampaignArtifactError("request-not-found")
        if (
            request.work_ref != work_ref
            or self._repository.get_campaign_ref_for_request(request_id) != campaign_ref
        ):
            raise CampaignArtifactError("download-claim-invalid")
        atomic_record = getattr(self._repository, "record_artifact_with_durable_handoff", None)
        if self._durable_handoff is not None and not callable(atomic_record):
            # Fail before claiming or writing bytes; a durable handoff must
            # never leave an external ZIP without its database outbox rows.
            raise CampaignArtifactError("durable-handoff-transaction-unavailable")
        claim = None
        if claim_ref is None:
            claim = self._repository.claim_operation(
                campaign_ref=campaign_ref,
                window_ref=work_ref,
                request_id=request_id,
                operation_kind="download",
                idempotency_key=f"download:{package_ref}",
                worker_ref="sat-monitor",
                now=current,
                lease_until=current + timedelta(minutes=10),
                grant_ref=request.grant_ref,
                require_grant=request.grant_ref is not None,
            )
        else:
            claim = self._repository.get_claim(claim_ref)
            if (
                claim is None
                or claim.operation_kind != "download"
                or not claim.active
                or claim.campaign_id != request.campaign_id
                or claim.window_id != request.window_id
                or claim.request_id != request.id
            ):
                raise CampaignArtifactError("download-claim-invalid")
        suffix = ".zip"
        namespace = "metadata" if kind == "metadata_zip" else "cfdi"
        opaque_campaign = hashlib.sha256(campaign_ref.encode("utf-8")).hexdigest()[:24]
        opaque_work = hashlib.sha256(work_ref.encode("utf-8")).hexdigest()[:24]
        relative_dir = str(PurePosixPath(f"sat-{namespace}") / opaque_campaign / opaque_work / "packages")
        try:
            stored = write_artifact(
                storage_root=self._storage_root,
                relative_dir=relative_dir,
                ordinal=ordinal,
                suffix=suffix,
                chunks=chunks,
                max_bytes=max_bytes,
            )
            _validate_package_archive(
                Path(self._storage_root) / Path(stored.relative_key), kind,
            )
            artifact_ref = _campaign_artifact_ref(
                campaign_ref, work_ref, kind, stored.sha256,
            )
            use_txt_handoff = kind == "metadata_zip" and (
                self._durable_handoff is not None or self._job_publisher is not None
            )
            if use_txt_handoff:
                # The ZIP remains the package evidence; the worker consumes a
                # separately stored TXT reference, not a ZIP or its contents.
                artifact = self._repository.record_artifact(
                    campaign_ref=campaign_ref, window_ref=work_ref,
                    artifact_ref=artifact_ref, kind=kind,
                    storage_key=stored.relative_key, sha256=stored.sha256,
                    size_bytes=stored.byte_count, validation_status="valid",
                    counts={}, now=current,
                )
                package_artifact = artifact
                txt_artifacts = self._extract_metadata_txt(
                    archive_path=Path(self._storage_root) / Path(stored.relative_key),
                    campaign_ref=campaign_ref, work_ref=work_ref,
                    tenant_id=request.tenant_id, now=current,
                    atomic_record=atomic_record,
                )
                if not txt_artifacts:
                    raise CampaignArtifactError("artifact-txt-missing")
            elif self._durable_handoff is not None and callable(atomic_record):
                # The repository commits artifact metadata and ledger rows in
                # one transaction. Broker publication is intentionally after
                # this call returns, so a failed publish leaves a durable
                # outbox event for a later one-shot dispatcher.
                artifact = atomic_record(
                    campaign_ref=campaign_ref,
                    window_ref=work_ref,
                    artifact_ref=artifact_ref,
                    kind=kind,
                    storage_key=stored.relative_key,
                    sha256=stored.sha256,
                    size_bytes=stored.byte_count,
                    validation_status="valid",
                    counts={},
                    tenant_id=request.tenant_id,
                    handoff=self._durable_handoff,
                    now=current,
                )
                self._durable_handoff.publish_after_commit(now=current)
                package_artifact = artifact
            else:
                # Keep the explicit pre-V6 adapter path working for fakes.
                artifact = self._repository.record_artifact(
                    campaign_ref=campaign_ref,
                    window_ref=work_ref,
                    artifact_ref=artifact_ref,
                    kind=kind,
                    storage_key=stored.relative_key,
                    sha256=stored.sha256,
                    size_bytes=stored.byte_count,
                    validation_status="valid",
                    counts={},
                    now=current,
                )
                package_artifact = artifact
            if (self._durable_handoff is None and self._job_publisher is not None
                    and not use_txt_handoff):
                from cfdi_vault.sat_campaign_jobs import publish_artifact_parse_job

                publish_artifact_parse_job(
                    self._job_publisher,
                    tenant_id=request.tenant_id,
                    artifact_ref=package_artifact.artifact_ref,
                    kind=kind,
                    now=current,
                )
            self._repository.record_package(
                claim_ref=claim.claim_ref,
                id_paquete=package_ref,
                id_solicitud=request.id_solicitud,
                status="downloaded",
                ordinal=ordinal,
                artifact_id=package_artifact.id,
                download_state="downloaded",
                now=current,
            )
            return stored
        except CampaignArtifactError:
            self._repository.record_download_uncertain(claim_ref=claim.claim_ref, now=current)
            raise
        except Exception as exc:
            self._repository.record_download_uncertain(claim_ref=claim.claim_ref, now=current)
            raise CampaignArtifactError("artifact-persistence-failed") from exc

    def _extract_metadata_txt(
        self, *, archive_path: Path, campaign_ref: str, work_ref: str,
        tenant_id: str, now: datetime, atomic_record: Callable[..., object] | None,
    ) -> tuple[StoredArtifact, ...]:
        """Stream validated TXT members to opaque storage and enqueue references."""

        stored_artifacts: list[StoredArtifact] = []
        with ZipFile(archive_path) as archive:
            txt_infos = tuple(
                (ordinal, info) for ordinal, info in enumerate(archive.infolist(), 1)
                if info.filename.lower().endswith(".txt")
            )
            for ordinal, info in txt_infos:
                with archive.open(info, "r") as member:
                    stored = write_artifact(
                        storage_root=self._storage_root,
                        relative_dir=self._opaque_dir(campaign_ref, work_ref, "txt"),
                        ordinal=ordinal,
                        suffix=".txt",
                        chunks=_member_chunks(member),
                        max_bytes=1 * 1024 * 1024 * 1024,
                    )
                artifact_ref = _campaign_artifact_ref(
                    campaign_ref, work_ref, "metadata_txt", stored.sha256,
                )
                if self._durable_handoff is not None and callable(atomic_record):
                    artifact = atomic_record(
                        campaign_ref=campaign_ref, window_ref=work_ref,
                        artifact_ref=artifact_ref, kind="metadata_txt",
                        storage_key=stored.relative_key, sha256=stored.sha256,
                        size_bytes=stored.byte_count, validation_status="valid",
                        counts={}, tenant_id=tenant_id, handoff=self._durable_handoff,
                        now=now,
                    )
                    self._durable_handoff.publish_after_commit(now=now)
                else:
                    artifact = self._repository.record_artifact(
                        campaign_ref=campaign_ref, window_ref=work_ref,
                        artifact_ref=artifact_ref, kind="metadata_txt",
                        storage_key=stored.relative_key, sha256=stored.sha256,
                        size_bytes=stored.byte_count, validation_status="valid",
                        counts={}, now=now,
                    )
                    if self._job_publisher is not None:
                        from cfdi_vault.sat_campaign_jobs import publish_artifact_parse_job

                        publish_artifact_parse_job(
                            self._job_publisher, tenant_id=tenant_id,
                            artifact_ref=artifact.artifact_ref, kind="metadata_txt",
                            now=now,
                        )
                stored_artifacts.append(stored)
        return tuple(stored_artifacts)

    @staticmethod
    def _opaque_dir(campaign_ref: str, work_ref: str, leaf: str) -> str:
        campaign = hashlib.sha256(campaign_ref.encode("utf-8")).hexdigest()[:24]
        work = hashlib.sha256(work_ref.encode("utf-8")).hexdigest()[:24]
        namespace = "metadata"
        return str(PurePosixPath(f"sat-{namespace}") / campaign / work / leaf)


def _utc(value: datetime) -> datetime:
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)


def _campaign_artifact_ref(
    campaign_ref: str, work_ref: str, kind: str, content_sha256: str,
) -> str:
    """Build a stable opaque reference scoped to campaign work and content."""

    scope = hashlib.sha256(
        f"{campaign_ref}\0{work_ref}\0{kind}".encode("utf-8")
    ).hexdigest()[:24]
    return f"artifact-{scope}-{content_sha256[:24]}"


def _validate_package_archive(path: Path, kind: str) -> None:
    """Reject unsafe or structurally unexpected ZIP packages before registration."""

    expected_suffix = ".txt" if kind == "metadata_zip" else ".xml"
    total = 0
    names: set[str] = set()
    try:
        with ZipFile(path) as archive:
            infos = archive.infolist()
            max_files = 32 if kind == "metadata_zip" else 200_000
            max_member_bytes = 1 * 1024 * 1024 * 1024 if kind == "metadata_zip" else 64 * 1024 * 1024
            max_total_bytes = 2 * 1024 * 1024 * 1024 if kind == "metadata_zip" else 4 * 1024 * 1024 * 1024
            if not infos or len(infos) > max_files:
                raise CampaignArtifactError("artifact-zip-invalid")
            for info in infos:
                name = info.filename
                normalized = name.replace("\\", "/")
                mode = (info.external_attr >> 16) & 0o170000
                if (not name or name in names or name.startswith(("/", "\\")) or
                        ".." in normalized.split("/") or any(ord(char) < 32 for char in name) or
                        info.is_dir() or mode == stat.S_IFLNK or not name.lower().endswith(expected_suffix)):
                    raise CampaignArtifactError("artifact-zip-invalid")
                names.add(name)
                if info.file_size > max_member_bytes:
                    raise CampaignArtifactError("artifact-zip-invalid")
                if info.compress_size and info.file_size > info.compress_size * 200:
                    raise CampaignArtifactError("artifact-zip-invalid")
                total += info.file_size
                if total > max_total_bytes:
                    raise CampaignArtifactError("artifact-zip-invalid")
                with archive.open(info, "r") as member:
                    _validate_member_content(member, kind, max_member_bytes)
    except CampaignArtifactError:
        raise
    except (BadZipFile, OSError, ValueError) as exc:
        raise CampaignArtifactError("artifact-zip-invalid") from exc


def _member_chunks(member: io.BufferedIOBase) -> Iterable[bytes]:
    """Read one ZIP member in bounded blocks without retaining its contents."""

    while True:
        chunk = member.read(1024 * 1024)
        if not chunk:
            return
        yield chunk


def _validate_member_content(member: io.BufferedIOBase, kind: str, limit: int) -> None:
    """Check encoding/delimiter or XML safety without emitting member rows."""

    if kind == "metadata_zip":
        decoder = codecs.getincrementaldecoder("utf-8-sig")()
        first_line: str | None = None
        line_buffer = ""
        consumed = 0
        while consumed <= limit:
            chunk = member.read(min(1024 * 1024, limit + 1 - consumed))
            if not chunk:
                break
            consumed += len(chunk)
            try:
                decoded = decoder.decode(chunk)
            except UnicodeDecodeError as exc:
                raise CampaignArtifactError("artifact-txt-encoding-unsupported") from exc
            if first_line is None:
                line_buffer += decoded
                if len(line_buffer) > 1024 * 1024:
                    raise CampaignArtifactError("artifact-header-too-large")
                line_end = min((index for index in (line_buffer.find("\n"), line_buffer.find("\r"))
                                if index >= 0), default=-1)
                if line_end >= 0:
                    first_line = line_buffer[:line_end]
            if consumed > limit:
                raise CampaignArtifactError("artifact-member-too-large")
        try:
            decoder.decode(b"", final=True)
        except UnicodeDecodeError as exc:
            raise CampaignArtifactError("artifact-txt-encoding-unsupported") from exc
        first_line = first_line if first_line is not None else line_buffer
        if "~" not in first_line or not _metadata_header_compatible(first_line):
            raise CampaignArtifactError("artifact-txt-delimiter-invalid")
        return
    member.seek(0)
    _scan_xml_forbidden_tokens(member, limit)
    member.seek(0)
    try:
        ElementTree.parse(member)
    except (ElementTree.ParseError, ValueError) as exc:
        raise CampaignArtifactError("artifact-xml-invalid") from exc


def _metadata_header_compatible(header: str) -> bool:
    fields = {value.strip().casefold() for value in header.split("~")}
    return all(
        any(alias.casefold() in fields for alias in FIELD_ALIASES[field])
        for field in REQUIRED_METADATA_FIELDS
    )


def _scan_xml_forbidden_tokens(member: io.BufferedIOBase, limit: int) -> None:
    forbidden = (b"<!DOCTYPE", b"<!ENTITY")
    consumed = 0
    tail = b""
    while consumed <= limit:
        chunk = member.read(min(1024 * 1024, limit + 1 - consumed))
        if not chunk:
            return
        consumed += len(chunk)
        haystack = tail + chunk
        upper = haystack.upper()
        if any(token in upper for token in forbidden):
            raise CampaignArtifactError("artifact-xml-unsafe")
        tail = haystack[-16:]
        if consumed > limit:
            raise CampaignArtifactError("artifact-member-too-large")
