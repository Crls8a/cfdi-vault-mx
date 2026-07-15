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
from cfdi_vault.sat_contract import (
    SatDownloadResult,
    SatError,
    SatOperation,
    SatOutcomeAction,
    SatVerificationResult,
)
from cfdi_vault.sat_metadata_artifact_state import MetadataPackageArtifactState
from cfdi_vault.sat_metadata_package import process_metadata_package
from cfdi_vault.sat_metadata_recovery import PackageRecoveryStatus, RecoveryStatus

_TERMINAL = frozenset({
    RecoveryStatus.COMPLETED, RecoveryStatus.NO_DATA, RecoveryStatus.PENDING_AFTER_BUDGET,
    RecoveryStatus.VERIFY_FAILED, RecoveryStatus.DOWNLOAD_UNCERTAIN, RecoveryStatus.DOWNLOAD_FAILED,
})
_VERIFIED_TERMINAL = frozenset({RecoveryStatus.PACKAGES_READY, RecoveryStatus.NO_DATA})
_TRANSIENT_VERIFY_ERROR_KINDS = frozenset({
    "connect_timeout",
    "timeout",
    "verify_read_timeout",
    "remote_closed_connection",
    "connection_reset_during_post",
    "proxy_connect_failed",
})
_AUTH_CONTACT_STAGES = frozenset({"auth_transport", "auth_response_parse", "token_extract"})
_OPERATION_CONTACT_STAGES = {
    SatOperation.VERIFY: frozenset({
        "verify_request_build", "verify_request_readiness", "verify_transport",
        "verify_response_parse",
    }),
    SatOperation.DOWNLOAD: frozenset({
        "package_download_build", "package_download_transport", "package_download_parse",
    }),
}


@dataclass(frozen=True)
class MetadataRecoveryAdvanceOutcome:
    """Expose only redacted recovery state and per-call safe counters."""

    recovery: dict[str, object] | None
    sat_contacted: bool
    verify_count: int
    download_attempts: int
    verify_contacts_not_before_due: int = 0
    verify_contacts_before_due: int = 0
    verify_contacts_due_unknown: int = 0
    terminal_status_received: bool = False
    error_kind: str | None = None
    requires_live: bool = False


@dataclass
class _SatCallAudit:
    """Retain call evidence even when later local processing or persistence fails."""

    sat_contacted: bool = False
    verify_count: int = 0
    download_attempts: int = 0
    verify_contacts_not_before_due: int = 0
    verify_contacts_before_due: int = 0
    verify_contacts_due_unknown: int = 0
    terminal_status_received: bool = False


def advance_metadata_recovery_once(
    *, storage_root: str | Path, recovery_ref: str, verifier: SatVerificationPort,
    downloader: SatDownloadPort, package_storage: PackageStorage, now: datetime,
    repo_root: str | Path | None = None,
) -> MetadataRecoveryAdvanceOutcome:
    """Advance one recovery while a crash-safe operation lock prevents duplicate SAT I/O."""
    audit = _SatCallAudit()
    try:
        with state.metadata_recovery_operation_lock(storage_root, repo_root=repo_root):
            return _advance(
                storage_root, recovery_ref, verifier, downloader, package_storage,
                now, repo_root, audit,
            )
    except state.MetadataRecoveryStateError as exc:
        kind = "busy" if exc.reason == "recovery-state-busy" else "state_failed"
        return _failed_out(audit, kind)
    except Exception:
        return _failed_out(audit, "runner_failed")


def settle_metadata_recovery_locally(
    *, storage_root: str | Path, recovery_ref: str, now: datetime,
    repo_root: str | Path | None = None,
) -> MetadataRecoveryAdvanceOutcome:
    """Persist local-only terminal transitions under the durable operation lock."""

    audit = _SatCallAudit()
    try:
        with state.metadata_recovery_operation_lock(storage_root, repo_root=repo_root):
            record = state.load_metadata_recovery_state(
                storage_root, recovery_ref, repo_root=repo_root,
            )
            record, error, requires_live = _settle_record(
                storage_root, record, now, repo_root,
            )
            return MetadataRecoveryAdvanceOutcome(
                recovery=record.to_redacted_document(), sat_contacted=False,
                verify_count=0, download_attempts=0, error_kind=error, requires_live=requires_live,
            )
    except state.MetadataRecoveryStateError as exc:
        kind = "busy" if exc.reason == "recovery-state-busy" else "state_failed"
        return _failed_out(audit, kind)
    except Exception:
        return _failed_out(audit, "runner_failed")


def _advance(root, recovery_ref, verifier, downloader, package_storage, now, repo_root, audit):
    record = state.load_metadata_recovery_state(root, recovery_ref, repo_root=repo_root)
    record, local_error, requires_live = _settle_record(root, record, now, repo_root)
    if not requires_live:
        return _out(record, audit, error=local_error)
    recovery = record.recovery
    error = None
    if recovery.status is RecoveryStatus.VERIFY_SCHEDULED:
        due_at = recovery.next_check_at
        if due_at is None or now < due_at:
            return _out(record, audit)
        audit.verify_count += 1
        try:
            result = verifier.verify_request(record.id_solicitud)
        except Exception as exc:
            contacted = _exception_confirms_sat_contact(exc, SatOperation.VERIFY)
            audit.sat_contacted = audit.sat_contacted or contacted
            if contacted:
                _record_verify_contact(audit, now, due_at)
            if _retryable_verification(exc):
                recovery = lifecycle.record_pending_verification(recovery, checked_at=now)
                error = "verify_retryable"
            else:
                recovery = lifecycle.record_verification_failure(recovery, checked_at=now)
                error = "verify_failed"
            record = replace(record, recovery=recovery)
            state.save_metadata_recovery_state(root, record, repo_root=repo_root)
            return _out(record, audit, error=error)
        audit.sat_contacted = True
        _record_verify_contact(audit, now, due_at)
        record, error = _apply_verification(record, result, now)
        audit.terminal_status_received = record.recovery.status in _VERIFIED_TERMINAL
        state.save_metadata_recovery_state(root, record, repo_root=repo_root)
        if record.recovery.status not in {RecoveryStatus.PACKAGES_READY, RecoveryStatus.DOWNLOADING}:
            return _out(record, audit, error=error)
    for ordinal, binding in enumerate(record.package_bindings, start=1):
        package = next(item for item in record.recovery.packages
                       if item.package_ref == binding.package_ref)
        if package.status is not PackageRecoveryStatus.PENDING:
            continue
        recovery = lifecycle.begin_package_download(record.recovery, binding.package_ref)
        record = replace(record, recovery=recovery)
        state.save_metadata_recovery_state(root, record, repo_root=repo_root)
        audit.download_attempts += 1
        try:
            result = downloader.download_package(binding.id_paquete)
        except Exception as exc:
            audit.sat_contacted = audit.sat_contacted or _exception_confirms_sat_contact(
                exc, SatOperation.DOWNLOAD,
            )
            uncertain = getattr(exc, "effect_unknown", None) is not False
            record = _finish_download(record, binding.package_ref, uncertain=uncertain)
            state.save_metadata_recovery_state(root, record, repo_root=repo_root)
            return _out(
                record, audit,
                error="download_uncertain" if uncertain else "download_failed",
            )
        audit.sat_contacted = True
        if not _valid_download(result, binding.id_paquete):
            record = _finish_download(record, binding.package_ref, uncertain=False)
            state.save_metadata_recovery_state(root, record, repo_root=repo_root)
            return _out(record, audit, error="download_failed")
        try:
            processed = process_metadata_package(recovery_ref, ordinal, result.content, package_storage)
            artifact = MetadataPackageArtifactState.from_processed(binding.package_ref, processed)
            recovery = lifecycle.record_package_download(
                record.recovery, binding.package_ref, zip_valid=True, txt_count=len(processed.texts),
            )
            record = replace(record, recovery=recovery,
                             artifact_bindings=(*record.artifact_bindings, artifact))
        except Exception:
            record = _finish_download(record, binding.package_ref, uncertain=False)
            state.save_metadata_recovery_state(root, record, repo_root=repo_root)
            return _out(record, audit, error="download_failed")
        state.save_metadata_recovery_state(root, record, repo_root=repo_root)
    return _out(record, audit, error=error)


def _settle_record(root, record, now, repo_root):
    recovery = record.recovery
    if recovery.status in _TERMINAL:
        return record, None, False
    expired = lifecycle.apply_recovery_deadline(recovery, now=now)
    if expired != recovery:
        record = replace(record, recovery=expired)
        state.save_metadata_recovery_state(root, record, repo_root=repo_root)
        return record, None, False
    claimed = next((item for item in recovery.packages
                    if item.status is PackageRecoveryStatus.DOWNLOADING), None)
    if claimed is not None:
        recovery = lifecycle.record_package_download(recovery, claimed.package_ref, uncertain=True)
        record = replace(record, recovery=recovery)
        state.save_metadata_recovery_state(root, record, repo_root=repo_root)
        return record, "download_uncertain", False
    return record, None, True


def _apply_verification(record, result, now):
    recovery = record.recovery
    valid = type(result) is SatVerificationResult and result.request_id == record.id_solicitud
    if valid and type(result.sat_code) is str and result.sat_code.strip() == "5004":
        return replace(record, recovery=lifecycle.record_finished_verification(
            recovery, checked_at=now, package_refs=(), record_count=None)), None
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
            recovery, checked_at=now, package_refs=refs, record_count=None)
        bindings = tuple(state.PackageIdBinding(ref, raw) for ref, raw in zip(refs, ids, strict=True))
        return replace(record, recovery=recovery, package_bindings=bindings), None
    recovery = lifecycle.record_verification_failure(recovery, checked_at=now)
    return replace(record, recovery=recovery), "verify_failed"


def _retryable_verification(exc: Exception) -> bool:
    error_kind = getattr(exc, "error_kind", None)
    return bool(
        (isinstance(exc, SatError) and exc.retryable)
        or isinstance(exc, (TimeoutError, ConnectionError))
        or getattr(exc, "retryable", False) is True
        or (type(error_kind) is str and error_kind in _TRANSIENT_VERIFY_ERROR_KINDS)
    )


def _exception_confirms_sat_contact(exc: Exception, operation: SatOperation) -> bool:
    """Confirm contact only from an explicit adapter stage or matching port contract."""
    failed_stage = getattr(exc, "failed_stage", None)
    if type(failed_stage) is str:
        return failed_stage in _AUTH_CONTACT_STAGES | _OPERATION_CONTACT_STAGES[operation]
    if isinstance(exc, SatError):
        return exc.operation is operation
    return isinstance(exc, (TimeoutError, ConnectionError))


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


def _failed_out(audit, error):
    return MetadataRecoveryAdvanceOutcome(
        recovery=None, sat_contacted=audit.sat_contacted, verify_count=audit.verify_count,
        download_attempts=audit.download_attempts, error_kind=error,
        verify_contacts_not_before_due=audit.verify_contacts_not_before_due,
        verify_contacts_before_due=audit.verify_contacts_before_due,
        verify_contacts_due_unknown=audit.verify_contacts_due_unknown,
        terminal_status_received=audit.terminal_status_received,
    )


def _out(record, audit, error=None):
    return MetadataRecoveryAdvanceOutcome(
        recovery=record.to_redacted_document(), sat_contacted=audit.sat_contacted,
        verify_count=audit.verify_count, download_attempts=audit.download_attempts, error_kind=error,
        verify_contacts_not_before_due=audit.verify_contacts_not_before_due,
        verify_contacts_before_due=audit.verify_contacts_before_due,
        verify_contacts_due_unknown=audit.verify_contacts_due_unknown,
        terminal_status_received=audit.terminal_status_received,
    )


def _record_verify_contact(audit, contacted_at, due_at):  # type: ignore[no-untyped-def]
    if due_at is None:
        audit.verify_contacts_due_unknown += 1
    elif contacted_at < due_at:
        audit.verify_contacts_before_due += 1
    else:
        audit.verify_contacts_not_before_due += 1
