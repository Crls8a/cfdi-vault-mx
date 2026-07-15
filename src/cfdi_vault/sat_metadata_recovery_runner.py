"""Internal due-aware runner for one persisted SAT metadata recovery."""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime
from pathlib import Path

import cfdi_vault.sat_metadata_recovery as lifecycle
import cfdi_vault.sat_metadata_recovery_state as state
from cfdi_vault.domain import SatRequestState
from cfdi_vault.package_processor import PackageStorage
from cfdi_vault.ports import SatDownloadPort, SatVerificationPort
from cfdi_vault.sat_contract import SatDownloadResult, SatError, SatOutcomeAction, SatVerificationResult
from cfdi_vault.sat_metadata_artifact_state import MetadataPackageArtifactState
from cfdi_vault.sat_metadata_package import process_metadata_package
from cfdi_vault.sat_metadata_recovery import PackageRecoveryStatus, RecoveryStatus

_TERMINAL = frozenset({
    RecoveryStatus.COMPLETED, RecoveryStatus.NO_DATA, RecoveryStatus.PENDING_AFTER_BUDGET,
    RecoveryStatus.VERIFY_FAILED, RecoveryStatus.DOWNLOAD_UNCERTAIN, RecoveryStatus.DOWNLOAD_FAILED,
})


@dataclass(frozen=True)
class MetadataRecoveryAdvanceOutcome:
    """Expose only redacted recovery state and per-call safe counters."""

    recovery: dict[str, object] | None
    sat_contacted: bool
    verify_count: int
    download_attempts: int
    error_kind: str | None = None

def advance_metadata_recovery_once(
    *, storage_root: str | Path, recovery_ref: str, verifier: SatVerificationPort,
    downloader: SatDownloadPort, package_storage: PackageStorage, now: datetime,
    repo_root: str | Path | None = None,
) -> MetadataRecoveryAdvanceOutcome:
    """Advance one recovery while a crash-safe operation lock prevents duplicate SAT I/O."""
    try:
        with state.metadata_recovery_operation_lock(storage_root, repo_root=repo_root):
            return _advance(storage_root, recovery_ref, verifier, downloader, package_storage, now, repo_root)
    except state.MetadataRecoveryStateError as exc:
        kind = "busy" if exc.reason == "recovery-state-busy" else "state_failed"
        return MetadataRecoveryAdvanceOutcome(None, False, 0, 0, kind)
    except Exception:
        return MetadataRecoveryAdvanceOutcome(None, False, 0, 0, "runner_failed")


def _advance(root, recovery_ref, verifier, downloader, package_storage, now, repo_root):
    record = state.load_metadata_recovery_state(root, recovery_ref, repo_root=repo_root)
    recovery = record.recovery
    if recovery.status in _TERMINAL:
        return _out(record)
    expired = lifecycle.apply_recovery_deadline(recovery, now=now)
    if expired != recovery:
        record = replace(record, recovery=expired)
        state.save_metadata_recovery_state(root, record, repo_root=repo_root)
        return _out(record)
    claimed = next((item for item in recovery.packages
                    if item.status is PackageRecoveryStatus.DOWNLOADING), None)
    if claimed is not None:
        recovery = lifecycle.record_package_download(recovery, claimed.package_ref, uncertain=True)
        record = replace(record, recovery=recovery)
        state.save_metadata_recovery_state(root, record, repo_root=repo_root)
        return _out(record, error="download_uncertain")
    contacted = False
    verifies = 0
    downloads = 0
    error = None
    if recovery.status is RecoveryStatus.VERIFY_SCHEDULED:
        if recovery.next_check_at is None or now < recovery.next_check_at:
            return _out(record)
        contacted, verifies = True, 1
        try:
            result = verifier.verify_request(record.id_solicitud)
        except Exception as exc:
            if _retryable_verification(exc):
                recovery = lifecycle.record_pending_verification(recovery, checked_at=now)
                error = "verify_retryable"
            else:
                recovery = lifecycle.record_verification_failure(recovery, checked_at=now)
                error = "verify_failed"
            record = replace(record, recovery=recovery)
            state.save_metadata_recovery_state(root, record, repo_root=repo_root)
            return _out(record, contacted, verifies, error=error)
        record, error = _apply_verification(record, result, now)
        state.save_metadata_recovery_state(root, record, repo_root=repo_root)
        if record.recovery.status not in {RecoveryStatus.PACKAGES_READY, RecoveryStatus.DOWNLOADING}:
            return _out(record, contacted, verifies, error=error)
    for ordinal, binding in enumerate(record.package_bindings, start=1):
        package = next(item for item in record.recovery.packages
                       if item.package_ref == binding.package_ref)
        if package.status is not PackageRecoveryStatus.PENDING:
            continue
        recovery = lifecycle.begin_package_download(record.recovery, binding.package_ref)
        record = replace(record, recovery=recovery)
        state.save_metadata_recovery_state(root, record, repo_root=repo_root)
        contacted, downloads = True, downloads + 1
        try:
            result = downloader.download_package(binding.id_paquete)
        except Exception as exc:
            uncertain = getattr(exc, "effect_unknown", None) is not False
            record = _finish_download(record, binding.package_ref, uncertain=uncertain)
            state.save_metadata_recovery_state(root, record, repo_root=repo_root)
            return _out(record, contacted, verifies, downloads,
                        "download_uncertain" if uncertain else "download_failed")
        if not _valid_download(result, binding.id_paquete):
            record = _finish_download(record, binding.package_ref, uncertain=False)
            state.save_metadata_recovery_state(root, record, repo_root=repo_root)
            return _out(record, contacted, verifies, downloads, "download_failed")
        try:
            processed = process_metadata_package(recovery_ref, ordinal, result.content, package_storage)
            artifact = MetadataPackageArtifactState.from_processed(binding.package_ref, processed)
            recovery = lifecycle.record_package_download(
                record.recovery, binding.package_ref, zip_valid=True, txt_count=len(processed.texts),
            )
            record = replace(record, recovery=recovery,
                             artifact_bindings=(*record.artifact_bindings, artifact))
            state.save_metadata_recovery_state(root, record, repo_root=repo_root)
        except Exception:
            record = _finish_download(record, binding.package_ref, uncertain=False)
            state.save_metadata_recovery_state(root, record, repo_root=repo_root)
            return _out(record, contacted, verifies, downloads, "download_failed")
    return _out(record, contacted, verifies, downloads, error)


def _apply_verification(record, result, now):
    recovery = record.recovery
    valid = type(result) is SatVerificationResult and result.request_id == record.id_solicitud
    if valid and type(result.sat_code) is str and result.sat_code.strip() == "5004":
        return replace(record, recovery=lifecycle.record_finished_verification(
            recovery, checked_at=now, package_refs=(), record_count=0)), None
    pending = valid and result.state in {SatRequestState.ACCEPTED, SatRequestState.IN_PROCESS} \
        and result.action in {SatOutcomeAction.ACCEPTED, SatOutcomeAction.IN_PROGRESS, SatOutcomeAction.RETRY}
    if pending:
        return replace(record, recovery=lifecycle.record_pending_verification(
            recovery, checked_at=now)), None
    ids_valid = valid and type(result.package_ids) is tuple and all(
        type(item) is str and item == item.strip() and item for item in result.package_ids)
    ids = result.package_ids if ids_valid else ()
    refs = tuple(state.package_ref(item) for item in ids)
    finished = (valid and result.state is SatRequestState.FINISHED
                and result.action is SatOutcomeAction.FINISHED
                and ids_valid and len(ids) == len(set(ids)) == len(set(refs)))
    if finished:
        recovery = lifecycle.record_finished_verification(
            recovery, checked_at=now, package_refs=refs, record_count=0)
        bindings = tuple(state.PackageIdBinding(ref, raw) for ref, raw in zip(refs, ids, strict=True))
        return replace(record, recovery=recovery, package_bindings=bindings), None
    recovery = lifecycle.record_verification_failure(recovery, checked_at=now)
    return replace(record, recovery=recovery), "verify_failed"


def _retryable_verification(exc: Exception) -> bool:
    return bool(
        (isinstance(exc, SatError) and exc.retryable)
        or isinstance(exc, (TimeoutError, ConnectionError))
        or getattr(exc, "retryable", False) is True
        or getattr(exc, "failed_stage", None) == "verify_transport"
    )


def _valid_download(result: object, expected: str) -> bool:
    return bool(
        type(result) is SatDownloadResult and result.package_id == expected
        and result.action is SatOutcomeAction.FINISHED
        and type(result.content) is bytes and result.content
    )


def _finish_download(record, package_ref, *, uncertain):
    recovery = lifecycle.record_package_download(
        record.recovery, package_ref, uncertain=uncertain,
        **({} if uncertain else {"zip_valid": False}),
    )
    return replace(record, recovery=recovery)


def _out(record, contacted=False, verifies=0, downloads=0, error=None):
    return MetadataRecoveryAdvanceOutcome(
        record.to_redacted_document(), contacted, verifies, downloads, error,
    )
