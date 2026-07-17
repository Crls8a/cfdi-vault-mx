"""Pure lifecycle model for one gated SAT metadata recovery.

This internal module owns no transport, credentials, persistence, or raw SAT
identifiers. Adapters must provide irreversible local references.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from enum import StrEnum

_RECOVERY_REF_RE = re.compile(r"run-[0-9a-f]{12}")
_PACKAGE_REF_RE = re.compile(r"pkg-[0-9a-f]{12}")
_DEADLINE = timedelta(days=7)
_AFTER_ATTEMPT = (
    timedelta(minutes=15), timedelta(minutes=30), timedelta(hours=1), timedelta(hours=2), timedelta(hours=4)
)
_TERMINAL_STATUSES: frozenset[RecoveryStatus]


class MetadataRecoveryError(ValueError):
    """Report an invalid recovery transition without sensitive context."""

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


class RecoveryStatus(StrEnum):
    """Safe aggregate states for one metadata recovery."""

    VERIFY_SCHEDULED = "verify_scheduled"
    PACKAGES_READY = "packages_ready"
    DOWNLOADING = "downloading"
    ZIP_DOWNLOADED_PENDING_PROCESSING = "zip_downloaded_pending_processing"
    COMPLETED = "completed"
    NO_DATA = "no_data"
    PENDING_AFTER_BUDGET = "pending_after_budget"
    VERIFY_FAILED = "verify_failed"
    DOWNLOAD_UNCERTAIN = "download_uncertain"
    DOWNLOAD_FAILED = "download_failed"


class PackageRecoveryStatus(StrEnum):
    """Once-only state for one irreversibly referenced package."""

    PENDING = "pending"
    DOWNLOADING = "downloading"
    COMPLETED = "completed"
    ZIP_DOWNLOADED_PENDING_PROCESSING = "zip_downloaded_pending_processing"
    UNCERTAIN = "uncertain"
    FAILED = "failed"


_TERMINAL_STATUSES = frozenset({
    RecoveryStatus.COMPLETED, RecoveryStatus.NO_DATA, RecoveryStatus.PENDING_AFTER_BUDGET,
    RecoveryStatus.VERIFY_FAILED, RecoveryStatus.DOWNLOAD_UNCERTAIN, RecoveryStatus.DOWNLOAD_FAILED,
    RecoveryStatus.ZIP_DOWNLOADED_PENDING_PROCESSING,
})


@dataclass(frozen=True)
class PackageRecovery:
    """Redacted state for one package download attempt."""

    package_ref: str
    status: PackageRecoveryStatus = PackageRecoveryStatus.PENDING
    zip_valid: bool | None = None
    txt_count: int = 0


@dataclass(frozen=True)
class MetadataRecovery:
    """Immutable, redacted lifecycle state for one SAT request."""

    recovery_ref: str
    created_at: datetime
    deadline_at: datetime
    status: RecoveryStatus
    verify_attempts: int
    next_check_at: datetime | None
    record_count: int | None = None
    packages: tuple[PackageRecovery, ...] = ()

    @property
    def txt_count(self) -> int:
        return sum(package.txt_count for package in self.packages)

    def to_redacted_document(self) -> dict[str, object]:
        """Serialize only safe references, timestamps, states, and aggregates."""

        if not _RECOVERY_REF_RE.fullmatch(self.recovery_ref) or any(
            not _PACKAGE_REF_RE.fullmatch(package.package_ref) for package in self.packages
        ):
            raise MetadataRecoveryError("recovery-reference-invalid")
        completed = tuple(p for p in self.packages if p.status in {
            PackageRecoveryStatus.COMPLETED,
            PackageRecoveryStatus.ZIP_DOWNLOADED_PENDING_PROCESSING,
        })
        return {
            "schemaVersion": 1,
            "recoveryRef": self.recovery_ref,
            "status": self.status.value,
            "createdAt": _format_dt(self.created_at),
            "deadlineAt": _format_dt(self.deadline_at),
            "verifyAttempts": self.verify_attempts,
            "nextCheckAt": _format_dt(self.next_check_at) if self.next_check_at else "",
            "recordCount": "not_reported" if self.record_count is None else self.record_count,
            "packageCount": len(self.packages),
            "downloadedPackageCount": len(completed),
            "zipValidCount": sum(package.zip_valid is True for package in self.packages),
            "txtCount": self.txt_count,
            "packages": [
                {
                    "packageRef": package.package_ref,
                    "status": package.status.value,
                    "zipValid": package.zip_valid,
                    "txtCount": package.txt_count,
                }
                for package in self.packages
            ],
        }


def start_metadata_recovery(recovery_ref: str, *, created_at: datetime) -> MetadataRecovery:
    """Create one recovery with its first verification due in five minutes."""

    if not _RECOVERY_REF_RE.fullmatch(recovery_ref):
        raise MetadataRecoveryError("recovery-ref-invalid")
    created = _normalize_dt(created_at)
    return MetadataRecovery(
        recovery_ref=recovery_ref,
        created_at=created,
        deadline_at=created + _DEADLINE,
        status=RecoveryStatus.VERIFY_SCHEDULED,
        verify_attempts=0,
        next_check_at=created + timedelta(minutes=5),
    )


def apply_recovery_deadline(recovery: MetadataRecovery, *, now: datetime) -> MetadataRecovery:
    """Close a still-pending request when its local seven-day budget ends."""

    if recovery.status is RecoveryStatus.VERIFY_SCHEDULED and _normalize_dt(now) >= recovery.deadline_at:
        return replace(recovery, status=RecoveryStatus.PENDING_AFTER_BUDGET, next_check_at=None)
    return recovery


def record_pending_verification(
    recovery: MetadataRecovery,
    *,
    checked_at: datetime,
    sat_next_check_at: datetime | None = None,
) -> MetadataRecovery:
    """Record one pending result and schedule no earlier than SAT permits."""

    _require_active(recovery, RecoveryStatus.VERIFY_SCHEDULED)
    checked = _normalize_dt(checked_at)
    expired = apply_recovery_deadline(recovery, now=checked)
    if expired.status is RecoveryStatus.PENDING_AFTER_BUDGET:
        return expired
    attempts = recovery.verify_attempts + 1
    delay = _AFTER_ATTEMPT[attempts - 1] if attempts <= len(_AFTER_ATTEMPT) else timedelta(hours=8)
    local_due = checked + delay
    sat_due = _normalize_dt(sat_next_check_at) if sat_next_check_at else local_due
    return replace(recovery, verify_attempts=attempts, next_check_at=max(local_due, sat_due))


def record_verification_failure(
    recovery: MetadataRecovery,
    *,
    checked_at: datetime,
) -> MetadataRecovery:
    """Close one due verification after a definitive, redacted failure."""

    _require_active(recovery, RecoveryStatus.VERIFY_SCHEDULED)
    checked = _normalize_dt(checked_at)
    expired = apply_recovery_deadline(recovery, now=checked)
    if expired.status is RecoveryStatus.PENDING_AFTER_BUDGET:
        return expired
    if recovery.next_check_at is None or checked < recovery.next_check_at:
        raise MetadataRecoveryError("verification-not-due")
    return replace(
        recovery,
        status=RecoveryStatus.VERIFY_FAILED,
        verify_attempts=recovery.verify_attempts + 1,
        next_check_at=None,
    )


def record_finished_verification(
    recovery: MetadataRecovery,
    *,
    checked_at: datetime,
    package_refs: tuple[str, ...],
    record_count: int | None,
) -> MetadataRecovery:
    """Record SAT completion and initialize independent package states."""

    _require_active(recovery, RecoveryStatus.VERIFY_SCHEDULED)
    expired = apply_recovery_deadline(recovery, now=checked_at)
    if expired.status is RecoveryStatus.PENDING_AFTER_BUDGET:
        return expired
    if record_count is not None and (type(record_count) is not int or record_count < 0):
        raise MetadataRecoveryError("record-count-invalid")
    if len(set(package_refs)) != len(package_refs) or any(not _PACKAGE_REF_RE.fullmatch(ref) for ref in package_refs):
        raise MetadataRecoveryError("package-ref-invalid")
    if not package_refs and record_count not in {None, 0}:
        raise MetadataRecoveryError("finished-packages-required")
    status = RecoveryStatus.NO_DATA if not package_refs else RecoveryStatus.PACKAGES_READY
    return replace(
        recovery,
        status=status,
        verify_attempts=recovery.verify_attempts + 1,
        next_check_at=None,
        record_count=record_count,
        packages=tuple(PackageRecovery(ref) for ref in package_refs),
    )


def begin_package_download(recovery: MetadataRecovery, package_ref: str) -> MetadataRecovery:
    """Claim exactly one package for its single allowed download attempt."""

    _require_active(recovery, RecoveryStatus.PACKAGES_READY, RecoveryStatus.DOWNLOADING)
    package = _find_package(recovery, package_ref)
    if package.status is not PackageRecoveryStatus.PENDING:
        raise MetadataRecoveryError("package-download-already-attempted")
    return _replace_package(
        recovery,
        replace(package, status=PackageRecoveryStatus.DOWNLOADING),
        RecoveryStatus.DOWNLOADING,
    )


def record_package_download(
    recovery: MetadataRecovery,
    package_ref: str,
    *,
    zip_valid: bool | None = None,
    txt_count: int = 0,
    uncertain: bool = False,
) -> MetadataRecovery:
    """Record a definitive result or terminal ambiguous transport outcome."""

    _require_active(recovery, RecoveryStatus.DOWNLOADING)
    package = _find_package(recovery, package_ref)
    if package.status is not PackageRecoveryStatus.DOWNLOADING:
        raise MetadataRecoveryError("package-download-not-started")
    if uncertain:
        updated = replace(package, status=PackageRecoveryStatus.UNCERTAIN)
        return _replace_package(recovery, updated, RecoveryStatus.DOWNLOAD_UNCERTAIN)
    if (
        type(txt_count) is not int or txt_count < 0 or type(zip_valid) is not bool
        or (not zip_valid and txt_count != 0)
    ):
        raise MetadataRecoveryError("package-result-invalid")
    package_status = (
        PackageRecoveryStatus.ZIP_DOWNLOADED_PENDING_PROCESSING
        if zip_valid and txt_count == 0
        else PackageRecoveryStatus.COMPLETED if zip_valid else PackageRecoveryStatus.FAILED
    )
    updated = replace(package, status=package_status, zip_valid=zip_valid, txt_count=txt_count)
    candidate = _replace_package(recovery, updated, RecoveryStatus.DOWNLOADING)
    if not zip_valid:
        return replace(candidate, status=RecoveryStatus.DOWNLOAD_FAILED)
    if package_status is PackageRecoveryStatus.ZIP_DOWNLOADED_PENDING_PROCESSING:
        return replace(candidate, status=RecoveryStatus.ZIP_DOWNLOADED_PENDING_PROCESSING)
    if all(item.status in {
        PackageRecoveryStatus.COMPLETED,
        PackageRecoveryStatus.ZIP_DOWNLOADED_PENDING_PROCESSING,
    } for item in candidate.packages):
        final = RecoveryStatus.COMPLETED if candidate.txt_count else RecoveryStatus.DOWNLOAD_FAILED
        return replace(candidate, status=final)
    return candidate


def _require_active(recovery: MetadataRecovery, *allowed: RecoveryStatus) -> None:
    if recovery.status in _TERMINAL_STATUSES:
        raise MetadataRecoveryError("recovery-terminal")
    if recovery.status not in allowed:
        raise MetadataRecoveryError("recovery-transition-invalid")


def _find_package(recovery: MetadataRecovery, package_ref: str) -> PackageRecovery:
    for package in recovery.packages:
        if package.package_ref == package_ref:
            return package
    raise MetadataRecoveryError("package-ref-not-found")


def _replace_package(recovery: MetadataRecovery, updated: PackageRecovery, status: RecoveryStatus) -> MetadataRecovery:
    packages = tuple(updated if item.package_ref == updated.package_ref else item for item in recovery.packages)
    return replace(recovery, status=status, packages=packages)


def _normalize_dt(value: datetime) -> datetime:
    aware = value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)
    return aware.astimezone(timezone.utc)


def _format_dt(value: datetime) -> str:
    return _normalize_dt(value).isoformat().replace("+00:00", "Z")
