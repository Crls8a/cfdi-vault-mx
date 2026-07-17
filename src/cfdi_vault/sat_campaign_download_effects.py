"""Internal one-shot raw Metadata ZIP download effect; no TXT parsing or public export."""

from __future__ import annotations

import stat
from collections.abc import Callable, Iterable
from dataclasses import dataclass, fields, replace
from io import BytesIO
from pathlib import Path
from zipfile import BadZipFile, ZipFile

from cfdi_vault.ports import SatDownloadPort
from cfdi_vault.sat_artifact_store import write_artifact
from cfdi_vault.sat_campaign_manifest import CampaignWorkState
from cfdi_vault.sat_campaign_manifest_store import load_campaign_manifest
from cfdi_vault.sat_contract import SatDownloadResult
from cfdi_vault.sat_metadata_recovery import (
    PackageRecoveryStatus,
    RecoveryStatus,
    begin_package_download,
    record_package_download,
)
from cfdi_vault.sat_metadata_recovery_state import (
    MetadataRecoveryStateError,
    MetadataRecoveryStateRecord,
    load_metadata_recovery_state,
    metadata_recovery_operation_lock,
    save_metadata_recovery_state,
)
from cfdi_vault.sat_metadata_zip_state import MetadataZipReceipt

_MAX_BYTES = 512 * 1024 * 1024
_CHUNK_BYTES = 1024 * 1024


@dataclass(frozen=True, repr=False)
class CampaignMetadataZipDownloadResult:
    zip_downloaded: bool
    zip_valid: bool
    package_count: int
    next_check_at: str | None
    status: str
    error: str | None = None

    def __repr__(self) -> str:
        return (
            "CampaignMetadataZipDownloadResult("
            f"zip_downloaded={self.zip_downloaded!r}, zip_valid={self.zip_valid!r}, "
            f"package_count={self.package_count!r}, next_check_at={self.next_check_at!r}, "
            f"status={self.status!r}, error={self.error!r})"
        )


def execute_campaign_metadata_zip_download_once(
    *,
    storage_root: str | Path,
    repo_root: str | Path,
    campaign_ref: str,
    work_ref: str,
    downloader_factory: Callable[[], SatDownloadPort],
) -> CampaignMetadataZipDownloadResult:
    """Claim and attempt at most one raw Metadata ZIP download."""
    try:
        with metadata_recovery_operation_lock(storage_root, repo_root=repo_root):
            manifest = load_campaign_manifest(storage_root, campaign_ref, repo_root=repo_root)
            work = _work(manifest, work_ref)
            if work.state is not CampaignWorkState.OUTSTANDING or work.recovery_ref is None:
                return _empty("ineligible-work", "campaign-work-ineligible")
            record = load_metadata_recovery_state(
                storage_root, work.recovery_ref, repo_root=repo_root,
            )
            if record.recovery.recovery_ref != work.recovery_ref:
                raise MetadataRecoveryStateError("recovery-lineage-invalid")
            if record.recovery.status is RecoveryStatus.DOWNLOADING:
                return _from_record(record, False, False, "in-progress", "download-in-progress")
            package, binding, ordinal = _select(record)
            if package is None:
                if _already_downloaded(record):
                    return _from_record(record, True, True, "already-downloaded", None)
                return _from_record(record, False, False, "no-pending-package", "no-pending-package")
            claimed = begin_package_download(record.recovery, package.package_ref)
            claimed_record = replace(record, recovery=claimed)
            try:
                save_metadata_recovery_state(storage_root, claimed_record, repo_root=repo_root)
            except Exception:
                return _from_record(record, False, False, "state-failed", "state-save-failed")
    except Exception:
        return _empty("state-failed", "state-invalid")

    try:
        adapter = downloader_factory()
        download = adapter.download_package(binding.id_paquete)  # type: ignore[union-attr]
    except Exception:
        return _finish(storage_root, repo_root, work.recovery_ref, package.package_ref,
                       uncertain=True, error="download-uncertain")
    if not _valid_result(download, binding.id_paquete):
        return _finish_terminal(
            storage_root, repo_root, work.recovery_ref, package.package_ref,
            error="download-invalid",
        )
    content = download.content
    if not _valid_zip(content):
        return _finish_terminal(
            storage_root, repo_root, work.recovery_ref, package.package_ref,
            error="zip-invalid",
        )
    try:
        stored = write_artifact(
            storage_root=storage_root,
            relative_dir=f"sat-metadata/{campaign_ref}/{work_ref}/packages",
            ordinal=ordinal,
            suffix=".zip",
            chunks=_chunks(content),
            max_bytes=_MAX_BYTES,
        )
    except Exception:
        return _finish_terminal(
            storage_root, repo_root, work.recovery_ref, package.package_ref,
            error="storage-failed",
        )
    package_count, current = 1, None
    try:
        with metadata_recovery_operation_lock(storage_root, repo_root=repo_root):
            current = load_metadata_recovery_state(
                storage_root, work.recovery_ref, repo_root=repo_root,
            )
            package_count = len(current.recovery.packages)
            if _claimed(current, package.package_ref) is False:
                raise MetadataRecoveryStateError("recovery-state-conflict")
            recovery = record_package_download(
                current.recovery, package.package_ref, zip_valid=True, txt_count=0,
            )
            updated = _atomic_zip_record(
                current, recovery, package.package_ref, campaign_ref, work_ref, stored,
            )
            save_metadata_recovery_state(storage_root, updated, repo_root=repo_root)
            return _from_record(updated, True, True, "downloaded", None)
    except Exception:
        if current is not None:
            try:
                uncertain = replace(current, recovery=record_package_download(
                    current.recovery, package.package_ref, uncertain=True,
                ))
                save_metadata_recovery_state(storage_root, uncertain, repo_root=repo_root)
                return _from_record(uncertain, False, False, "uncertain", "state-save-uncertain")
            except Exception:
                pass
        return _empty("uncertain", "state-save-uncertain", package_count=package_count)


def _work(manifest: object, work_ref: str):
    matches = tuple(item for item in manifest.items if item.work_ref == work_ref)
    if len(matches) != 1:
        raise MetadataRecoveryStateError("campaign-work-invalid")
    return matches[0]


def _select(record: MetadataRecoveryStateRecord):
    if record.recovery.status is not RecoveryStatus.PACKAGES_READY:
        return None, None, 0
    bindings = {item.package_ref: (item, index)
                for index, item in enumerate(record.package_bindings, 1)}
    for item in record.recovery.packages:
        if item.status is PackageRecoveryStatus.PENDING:
            binding, ordinal = bindings.get(item.package_ref, (None, 0))
            if binding is None:
                raise MetadataRecoveryStateError("package-binding-invalid")
            return item, binding, ordinal
    return None, None, 0


def _already_downloaded(record: MetadataRecoveryStateRecord) -> bool:
    return bool(record.zip_receipts) or any(item.status is PackageRecoveryStatus.ZIP_DOWNLOADED_PENDING_PROCESSING for item in record.recovery.packages)


def _claimed(record: MetadataRecoveryStateRecord, package_ref_value: str) -> bool:
    return any(item.package_ref == package_ref_value and item.status is PackageRecoveryStatus.DOWNLOADING for item in record.recovery.packages)


def _atomic_zip_record(current: MetadataRecoveryStateRecord, recovery, package_ref_value: str,
                       campaign_ref: str, work_ref: str, stored) -> MetadataRecoveryStateRecord:
    receipt = MetadataZipReceipt(
        current.recovery.recovery_ref, package_ref_value, campaign_ref, work_ref,
        stored.sha256, stored.byte_count, True, stored.relative_key,
    )
    values = {field.name: getattr(current, field.name) for field in fields(current)}
    values.update(recovery=recovery, zip_receipts=(*current.zip_receipts, receipt))
    candidate = object.__new__(MetadataRecoveryStateRecord)
    for name, value in values.items():
        object.__setattr__(candidate, name, value)
    candidate.__post_init__()
    return candidate


def _valid_result(value: object, package_id: str) -> bool:
    return type(value) is SatDownloadResult and value.package_id == package_id and type(value.content) is bytes and 0 < len(value.content) <= _MAX_BYTES


def _valid_zip(content: bytes | None) -> bool:
    if type(content) is not bytes:
        return False
    try:
        with ZipFile(BytesIO(content)) as archive:
            entries = archive.infolist()
            if not entries:
                return False
            names: set[str] = set()
            for info in entries:
                name = info.filename
                if (
                    type(name) is not str or not name or name in names
                    or name.startswith(("/", "\\")) or "\\" in name
                    or "\x00" in name or ":" in name
                    or any(part in {"", ".", ".."} for part in name.split("/")[:-1])
                    or any(part in {".", ".."} for part in name.split("/"))
                    or (info.is_dir() and not name.endswith("/"))
                    or stat.S_ISLNK((info.external_attr >> 16) & 0o170000)
                ):
                    return False
                names.add(name)
            return True
    except (BadZipFile, OSError, RuntimeError, ValueError):
        return False


def _chunks(content: bytes) -> Iterable[bytes]:
    return (content[offset : offset + _CHUNK_BYTES] for offset in range(0, len(content), _CHUNK_BYTES))


def _finish(root, repo, recovery_ref, package_ref_value, *, uncertain, error):  # type: ignore[no-untyped-def]
    try:
        with metadata_recovery_operation_lock(root, repo_root=repo):
            record = load_metadata_recovery_state(root, recovery_ref, repo_root=repo)
            if not _claimed(record, package_ref_value):
                return _empty("uncertain", "state-save-uncertain")
            updated = replace(
                record,
                recovery=record_package_download(
                    record.recovery, package_ref_value, uncertain=uncertain,
                    zip_valid=False if not uncertain else None,
                ),
            )
            save_metadata_recovery_state(root, updated, repo_root=repo)
            return _from_record(updated, False, False,
                                "uncertain" if uncertain else "failed", error)
    except Exception:
        return _empty("uncertain", "state-save-uncertain")


def _finish_terminal(root, repo, recovery_ref, package_ref_value, *, error):  # type: ignore[no-untyped-def]
    return _finish(root, repo, recovery_ref, package_ref_value,
                   uncertain=False, error=error)


def _from_record(record, downloaded, valid, status, error):  # type: ignore[no-untyped-def]
    try:
        document = record.recovery.to_redacted_document()
        return CampaignMetadataZipDownloadResult(bool(downloaded), bool(valid), int(document["packageCount"]), document["nextCheckAt"] or None, status, error)
    except Exception:
        return _empty("state-invalid", "state-invalid")


def _empty(status: str, error: str, *, package_count: int = 0) -> CampaignMetadataZipDownloadResult:
    return CampaignMetadataZipDownloadResult(False, False, package_count, None, status, error)
