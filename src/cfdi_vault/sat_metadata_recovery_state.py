"""Private durable state for one resumable SAT metadata recovery."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import sys
import tempfile
from collections.abc import Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

import cfdi_vault.sat_metadata_recovery as lifecycle
from cfdi_vault.sat_metadata_artifact_state import (
    MetadataArtifactStateError,
    MetadataPackageArtifactState,
)
from cfdi_vault.sat_metadata_recovery import (
    MetadataRecovery,
    PackageRecovery,
    PackageRecoveryStatus,
    RecoveryStatus,
)

_SCHEMA_VERSION = 4
_LEGACY_SCHEMA_VERSION = 3
_STATE_KEYS = {"schemaVersion", "recoveries"}
_LEGACY_RECORD_KEYS = {
    "recovery", "idSolicitud", "profileId", "direction", "kind", "fechaInicial",
    "fechaFinal", "criteriaHash", "authorizationRef", "packages", "artifacts",
}
_RECORD_KEYS = _LEGACY_RECORD_KEYS | {"observationProvenance"}
_PROVENANCE_KEYS = {
    "projectionVersion", "testedCommit", "observedAt", "entryPoint",
    "verifyContactsNotBeforeDue", "verifyContactsBeforeDue", "verifyContactsDueUnknown",
}
_RECOVERY_KEYS = {
    "schemaVersion", "recoveryRef", "status", "createdAt", "deadlineAt", "verifyAttempts",
    "nextCheckAt", "recordCount", "packageCount", "downloadedPackageCount", "zipValidCount",
    "txtCount", "packages",
}
_HASH_RE = re.compile(r"[0-9a-f]{64}")
_COMMIT_RE = re.compile(r"[0-9a-f]{40}")
_OBSERVATION_ENTRY_POINTS = {"metadata-recover-live", "metadata-recovery-runner"}
_REPO_ROOT = Path(__file__).resolve().parents[2]


class MetadataRecoveryStateError(ValueError):
    """Report invalid private state without echoing sensitive values."""
    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


@dataclass(frozen=True, repr=False)
class PackageIdBinding:
    """Bind one safe package reference to its private SAT identifier."""
    package_ref: str
    id_paquete: str


@dataclass(frozen=True, repr=False)
class MetadataObservationProvenance:
    """Keep private, cumulative evidence for sanitized observation projection."""
    projection_version: int
    tested_commit: str
    observed_at: datetime
    entry_point: str
    verify_contacts_not_before_due: int = 0
    verify_contacts_before_due: int = 0
    verify_contacts_due_unknown: int = 0


@dataclass(frozen=True, repr=False)
class MetadataRecoveryStateRecord:
    """Keep private resume material beside the redacted lifecycle."""
    recovery: MetadataRecovery
    id_solicitud: str
    profile_id: str
    direction: str
    kind: str
    fecha_inicial: str
    fecha_final: str
    criteria_hash: str
    authorization_ref: str
    package_bindings: tuple[PackageIdBinding, ...] = ()
    artifact_bindings: tuple[MetadataPackageArtifactState, ...] = ()
    observation_provenance: MetadataObservationProvenance | None = None

    def __post_init__(self) -> None:
        _validate_record(self)

    def to_redacted_document(self) -> dict[str, object]:
        """Return status only; exclude every private resume value."""
        document = self.recovery.to_redacted_document()
        document["artifacts"] = [item.to_redacted_document() for item in self.artifact_bindings]
        return document

    def to_private_document(self) -> dict[str, object]:
        """Serialize private local state; callers must never print this document."""
        keys = ("idSolicitud", "profileId", "direction", "kind", "fechaInicial", "fechaFinal",
                "criteriaHash", "authorizationRef")
        values = (self.id_solicitud, self.profile_id, self.direction, self.kind, self.fecha_inicial,
                  self.fecha_final, self.criteria_hash, self.authorization_ref)
        document: dict[str, object] = dict(zip(keys, values, strict=True))
        document["recovery"] = self.recovery.to_redacted_document()
        document["packages"] = [{"packageRef": item.package_ref, "idPaquete": item.id_paquete}
                                for item in self.package_bindings]
        document["artifacts"] = [item.to_private_document() for item in self.artifact_bindings]
        document["observationProvenance"] = _provenance_document(self.observation_provenance)
        return document


def recovery_ref(profile_id: str, criteria_hash: str, id_solicitud: str) -> str:
    """Derive a non-reversible reference for one exact accepted request."""
    digest = hashlib.sha256(f"{profile_id}:{criteria_hash}:{id_solicitud}".encode()).hexdigest()
    return f"run-{digest[:12]}"


def package_ref(id_paquete: str) -> str:
    """Derive a non-reversible reference for one SAT package identifier."""
    return f"pkg-{hashlib.sha256(str(id_paquete).encode()).hexdigest()[:12]}"


def new_metadata_recovery_state(
    *, recovery: MetadataRecovery, id_solicitud: str, profile_id: str, direction: str,
    kind: str, fecha_inicial: str, fecha_final: str, criteria_hash: str,
    authorization_ref: str, package_ids: tuple[str, ...] = (),
    observation_provenance: MetadataObservationProvenance | None = None,
) -> MetadataRecoveryStateRecord:
    """Build validated private state and deterministic package bindings."""
    bindings = tuple(PackageIdBinding(package_ref(value), value) for value in package_ids)
    return MetadataRecoveryStateRecord(
        recovery, id_solicitud, profile_id, direction, kind, fecha_inicial,
        fecha_final, criteria_hash, authorization_ref, bindings, (), observation_provenance,
    )


def require_metadata_observation_provenance(
    record: MetadataRecoveryStateRecord,
) -> MetadataObservationProvenance:
    """Fail closed before live continuation of legacy state without provenance."""
    provenance = record.observation_provenance
    if provenance is None:
        raise MetadataRecoveryStateError("observation-provenance-required")
    return provenance


def metadata_recovery_state_path(
    storage_root: str | Path, *, repo_root: str | Path | None = None,
) -> Path:
    """Return the fixed, non-sensitive state path under configured storage."""
    root = _canonical_storage_root(storage_root, repo_root=repo_root)
    return root / "state" / "sat-metadata-recoveries.json"


@contextmanager
def metadata_recovery_operation_lock(
    storage_root: str | Path, *, repo_root: str | Path | None = None,
):
    """Hold the stable nonblocking lock for one complete recovery advance."""
    state_path = _resolved_state_path(storage_root, repo_root=repo_root, create_parent=True)
    anchor = state_path.with_name("sat-metadata-recovery-operation")
    with _exclusive_state_lock(anchor):
        yield


def save_metadata_recovery_state(
    storage_root: str | Path,
    record: MetadataRecoveryStateRecord,
    *,
    repo_root: str | Path | None = None,
) -> None:
    """Atomically insert or update one record without rebinding its request."""
    path = _resolved_state_path(storage_root, repo_root=repo_root, create_parent=True)
    with _exclusive_state_lock(path):
        records = list(_records_from_path(path))
        for current in records:
            if (current.id_solicitud == record.id_solicitud
                    and current.recovery.recovery_ref != record.recovery.recovery_ref):
                raise MetadataRecoveryStateError("request-already-bound")
            if (current.recovery.recovery_ref == record.recovery.recovery_ref
                    and _identity(current) != _identity(record)):
                raise MetadataRecoveryStateError("recovery-ref-conflict")
            if current.recovery.recovery_ref == record.recovery.recovery_ref:
                _validate_replacement(current, record)
        records = [item for item in records if item.recovery.recovery_ref != record.recovery.recovery_ref]
        records.append(record)
        records.sort(key=lambda item: item.recovery.created_at, reverse=True)
        _write_state(path, records)


def list_metadata_recovery_states(
    storage_root: str | Path, *, repo_root: str | Path | None = None,
) -> tuple[MetadataRecoveryStateRecord, ...]:
    """Load all private records, failing closed on malformed or duplicate state."""
    path = _resolved_state_path(storage_root, repo_root=repo_root, create_parent=False)
    return _records_from_path(path)


def _records_from_path(path: Path) -> tuple[MetadataRecoveryStateRecord, ...]:
    document = _read_state(path)
    schema_version = document["schemaVersion"]
    assert type(schema_version) is int
    records = tuple(
        _record_from_document(item, schema_version=schema_version)
        for item in document["recoveries"]
    )
    refs = tuple(item.recovery.recovery_ref for item in records)
    requests = tuple(item.id_solicitud for item in records)
    if len(set(refs)) != len(refs) or len(set(requests)) != len(requests):
        raise MetadataRecoveryStateError("recovery-state-duplicate")
    return records


def load_metadata_recovery_state(
    storage_root: str | Path,
    recovery_ref_value: str,
    *,
    repo_root: str | Path | None = None,
) -> MetadataRecoveryStateRecord:
    """Load one private record by safe recovery reference."""
    for record in list_metadata_recovery_states(storage_root, repo_root=repo_root):
        if record.recovery.recovery_ref == recovery_ref_value:
            return record
    raise MetadataRecoveryStateError("recovery-state-not-found")


def _validate_record(record: MetadataRecoveryStateRecord) -> None:
    _validate_recovery(record.recovery)
    _validate_observation_provenance(record)
    values = (record.id_solicitud, record.profile_id, record.authorization_ref)
    if any(not isinstance(value, str) or not value.strip() for value in values):
        raise MetadataRecoveryStateError("recovery-state-invalid")
    if record.direction not in {"issued", "received"} or record.kind != "metadata":
        raise MetadataRecoveryStateError("recovery-scope-invalid")
    if not _HASH_RE.fullmatch(record.criteria_hash):
        raise MetadataRecoveryStateError("criteria-hash-invalid")
    try:
        start, end = date.fromisoformat(record.fecha_inicial), date.fromisoformat(record.fecha_final)
    except (TypeError, ValueError):
        dates_invalid = True
    else:
        dates_invalid = False
    if dates_invalid:
        raise MetadataRecoveryStateError("recovery-dates-invalid")
    if start > end or record.recovery.recovery_ref != recovery_ref(
        record.profile_id, record.criteria_hash, record.id_solicitud
    ):
        raise MetadataRecoveryStateError("recovery-ref-mismatch")
    if type(record.package_bindings) is not tuple or any(
        type(item) is not PackageIdBinding for item in record.package_bindings
    ):
        raise MetadataRecoveryStateError("package-binding-invalid")
    raw_ids = tuple(item.id_paquete for item in record.package_bindings)
    refs = tuple(item.package_ref for item in record.package_bindings)
    expected = tuple(item.package_ref for item in record.recovery.packages)
    if (
        any(not isinstance(value, str) or not value.strip() for value in raw_ids)
        or len(set(raw_ids)) != len(raw_ids)
        or len(set(refs)) != len(refs)
        or refs != expected
        or any(item.package_ref != package_ref(item.id_paquete) for item in record.package_bindings)
    ):
        raise MetadataRecoveryStateError("package-binding-invalid")
    _validate_artifact_bindings(record)


def _validate_observation_provenance(record: MetadataRecoveryStateRecord) -> None:
    provenance = record.observation_provenance
    if provenance is None:
        return
    counters = _provenance_counters(provenance) if type(provenance) is MetadataObservationProvenance else ()
    if (
        type(provenance) is not MetadataObservationProvenance
        or type(provenance.projection_version) is not int
        or provenance.projection_version != 1
        or not isinstance(provenance.tested_commit, str)
        or _COMMIT_RE.fullmatch(provenance.tested_commit) is None
        or type(provenance.observed_at) is not datetime
        or provenance.observed_at.utcoffset() != timedelta(0)
        or provenance.observed_at < record.recovery.created_at
        or not isinstance(provenance.entry_point, str)
        or provenance.entry_point not in _OBSERVATION_ENTRY_POINTS
        or any(type(value) is not int or value < 0 for value in counters)
        or sum(counters) > record.recovery.verify_attempts
    ):
        raise MetadataRecoveryStateError("observation-provenance-invalid")


def _provenance_counters(provenance: MetadataObservationProvenance) -> tuple[int, int, int]:
    return (
        provenance.verify_contacts_not_before_due,
        provenance.verify_contacts_before_due,
        provenance.verify_contacts_due_unknown,
    )


def _validate_artifact_bindings(record: MetadataRecoveryStateRecord) -> None:
    artifacts = record.artifact_bindings
    if type(artifacts) is not tuple or any(
        type(item) is not MetadataPackageArtifactState for item in artifacts
    ):
        raise MetadataRecoveryStateError("artifact-binding-invalid")
    artifact_refs = tuple(item.package_ref for item in artifacts)
    completed = tuple(
        item for item in record.recovery.packages
        if item.status is PackageRecoveryStatus.COMPLETED
    )
    if (
        artifact_refs != tuple(item.package_ref for item in completed)
        or len(set(artifact_refs)) != len(artifact_refs)
    ):
        raise MetadataRecoveryStateError("artifact-binding-invalid")
    package_refs = {item.package_ref for item in record.package_bindings}
    package_ordinals = {
        item.package_ref: ordinal
        for ordinal, item in enumerate(record.package_bindings, start=1)
    }
    storage_keys: set[str] = set()
    for artifact, package in zip(artifacts, completed, strict=True):
        artifact_keys = (
            artifact.package_storage_key,
            *(text.storage_key for text in artifact.texts),
        )
        expected_ordinal = package_ordinals.get(artifact.package_ref)
        if (
            artifact.package_ref not in package_refs
            or package.zip_valid is not True
            or package.txt_count != len(artifact.texts)
            or not artifact.package_storage_key.startswith(
                f"sat-metadata/{record.recovery.recovery_ref}/packages/"
            )
            or expected_ordinal is None
            or any(_storage_key_ordinal(key) != expected_ordinal for key in artifact_keys)
            or any(key in storage_keys for key in artifact_keys)
        ):
            raise MetadataRecoveryStateError("artifact-binding-invalid")
        storage_keys.update(artifact_keys)


def _storage_key_ordinal(storage_key: str) -> int:
    """Read the ordinal from a key already validated by artifact state."""
    return int(storage_key.rsplit("/", 1)[1].split("-", 1)[0])


def _validate_recovery(recovery: MetadataRecovery) -> None:
    """Reject lifecycle values that no public transition can produce."""
    try:
        recovery.to_redacted_document()
    except ValueError:
        redaction_invalid = True
    else:
        redaction_invalid = False
    if redaction_invalid:
        raise MetadataRecoveryStateError("recovery-state-invalid")
    datetimes = (recovery.created_at, recovery.deadline_at, recovery.next_check_at)
    if (
        any(value is not None and value.utcoffset() is None for value in datetimes)
        or recovery.deadline_at != recovery.created_at + timedelta(days=7)
        or type(recovery.verify_attempts) is not int
        or recovery.verify_attempts < 0
        or (
            recovery.record_count is not None
            and (type(recovery.record_count) is not int or recovery.record_count < 0)
        )
    ):
        raise MetadataRecoveryStateError("recovery-state-invalid")
    for package in recovery.packages:
        neutral = package.status in {
            PackageRecoveryStatus.PENDING,
            PackageRecoveryStatus.DOWNLOADING,
            PackageRecoveryStatus.UNCERTAIN,
        }
        if package.txt_count < 0 or (neutral and (package.zip_valid is not None or package.txt_count)):
            raise MetadataRecoveryStateError("recovery-state-invalid")
        if package.status is PackageRecoveryStatus.COMPLETED and package.zip_valid is not True:
            raise MetadataRecoveryStateError("recovery-state-invalid")
        if package.status is PackageRecoveryStatus.FAILED and (package.zip_valid is not False or package.txt_count):
            raise MetadataRecoveryStateError("recovery-state-invalid")
    statuses = tuple(item.status for item in recovery.packages)
    no_packages = not statuses and recovery.record_count in {None, 0}
    pending = recovery.status is RecoveryStatus.VERIFY_SCHEDULED
    minimum_due = _minimum_next_check(recovery) if pending else None
    valid = {
        RecoveryStatus.VERIFY_SCHEDULED: no_packages and recovery.next_check_at is not None,
        RecoveryStatus.PENDING_AFTER_BUDGET: no_packages and recovery.next_check_at is None,
        RecoveryStatus.VERIFY_FAILED: no_packages
        and recovery.next_check_at is None
        and _verification_failure_possible(recovery),
        RecoveryStatus.NO_DATA: no_packages and recovery.next_check_at is None and recovery.verify_attempts > 0,
        RecoveryStatus.PACKAGES_READY: bool(statuses) and all(s is PackageRecoveryStatus.PENDING for s in statuses),
        RecoveryStatus.DOWNLOADING: bool(statuses)
        and statuses.count(PackageRecoveryStatus.DOWNLOADING) <= 1
        and any(s is not PackageRecoveryStatus.PENDING for s in statuses)
        and all(s in {PackageRecoveryStatus.PENDING, PackageRecoveryStatus.DOWNLOADING,
                      PackageRecoveryStatus.COMPLETED} for s in statuses)
        and not all(s is PackageRecoveryStatus.COMPLETED for s in statuses),
        RecoveryStatus.COMPLETED: bool(statuses)
        and all(s is PackageRecoveryStatus.COMPLETED for s in statuses) and recovery.txt_count > 0,
        RecoveryStatus.DOWNLOAD_UNCERTAIN: statuses.count(PackageRecoveryStatus.UNCERTAIN) == 1
        and all(s not in {PackageRecoveryStatus.DOWNLOADING, PackageRecoveryStatus.FAILED} for s in statuses),
        RecoveryStatus.DOWNLOAD_FAILED: bool(statuses)
        and all(s not in {PackageRecoveryStatus.DOWNLOADING, PackageRecoveryStatus.UNCERTAIN} for s in statuses)
        and (statuses.count(PackageRecoveryStatus.FAILED) == 1
             or (all(s is PackageRecoveryStatus.COMPLETED for s in statuses) and recovery.txt_count == 0)),
    }[recovery.status]
    if (
        not valid
        or (not pending and recovery.status not in {RecoveryStatus.PENDING_AFTER_BUDGET}
            and recovery.packages and (recovery.next_check_at is not None or recovery.verify_attempts == 0))
        or (pending and (minimum_due is None or recovery.next_check_at is None
                         or recovery.next_check_at < minimum_due))
    ):
        raise MetadataRecoveryStateError("recovery-state-invalid")


def _minimum_next_check(recovery: MetadataRecovery) -> datetime | None:
    probe = lifecycle.start_metadata_recovery(recovery.recovery_ref, created_at=recovery.created_at)
    for _ in range(recovery.verify_attempts):
        if probe.next_check_at is None:
            return None
        probe = lifecycle.record_pending_verification(probe, checked_at=probe.next_check_at)
        if probe.status is not RecoveryStatus.VERIFY_SCHEDULED:
            return None
    return probe.next_check_at


def _verification_failure_possible(recovery: MetadataRecovery) -> bool:
    """Confirm the failed attempt can occur before the seven-day deadline."""
    if recovery.verify_attempts < 1:
        return False
    probe = lifecycle.start_metadata_recovery(recovery.recovery_ref, created_at=recovery.created_at)
    for _ in range(recovery.verify_attempts - 1):
        if probe.next_check_at is None:
            return False
        probe = lifecycle.record_pending_verification(probe, checked_at=probe.next_check_at)
        if probe.status is not RecoveryStatus.VERIFY_SCHEDULED:
            return False
    return probe.next_check_at is not None and probe.next_check_at < recovery.deadline_at


def _validate_replacement(
    current: MetadataRecoveryStateRecord, candidate: MetadataRecoveryStateRecord,
) -> None:
    if current == candidate:
        return
    _validate_provenance_replacement(current, candidate)
    if current.package_bindings and current.package_bindings != candidate.package_bindings:
        raise MetadataRecoveryStateError("package-binding-immutable")
    previous_artifacts = current.artifact_bindings
    if (
        len(candidate.artifact_bindings) < len(previous_artifacts)
        or candidate.artifact_bindings[:len(previous_artifacts)] != previous_artifacts
    ):
        raise MetadataRecoveryStateError("artifact-binding-immutable")
    added_artifacts = candidate.artifact_bindings[len(previous_artifacts):]
    if len(added_artifacts) > 1:
        raise MetadataRecoveryStateError("artifact-binding-transition-invalid")
    before, after = current.recovery, candidate.recovery
    immutable = (before.recovery_ref, before.created_at, before.deadline_at)
    if immutable != (after.recovery_ref, after.created_at, after.deadline_at):
        raise MetadataRecoveryStateError("recovery-state-regression")
    try:
        expected = _exact_successor(before, after)
    except ValueError:
        expected = None
    if expected != after:
        raise MetadataRecoveryStateError("recovery-state-regression")
    if added_artifacts and not _artifact_matches_completion(
        before,
        after,
        added_artifacts[0].package_ref,
    ):
        raise MetadataRecoveryStateError("artifact-binding-transition-invalid")


def _validate_provenance_replacement(
    current: MetadataRecoveryStateRecord,
    candidate: MetadataRecoveryStateRecord,
) -> None:
    before, after = current.observation_provenance, candidate.observation_provenance
    if before is not None and after is None:
        raise MetadataRecoveryStateError("observation-provenance-required")
    if after is None:
        return
    attempt_delta = candidate.recovery.verify_attempts - current.recovery.verify_attempts
    if before is None:
        deltas = _provenance_counters(after)
        if attempt_delta != 1 or sum(deltas) > attempt_delta:
            raise MetadataRecoveryStateError("observation-provenance-transition-invalid")
        return
    old, new = _provenance_counters(before), _provenance_counters(after)
    if any(candidate_value < current_value for current_value, candidate_value in zip(old, new, strict=True)):
        raise MetadataRecoveryStateError("observation-provenance-regression")
    if after.observed_at < before.observed_at:
        raise MetadataRecoveryStateError("observation-provenance-regression")
    deltas = tuple(candidate_value - current_value for current_value, candidate_value in zip(old, new, strict=True))
    if (attempt_delta == 0 and after != before) or sum(deltas) > attempt_delta:
        raise MetadataRecoveryStateError("observation-provenance-transition-invalid")


def _artifact_matches_completion(
    before: MetadataRecovery,
    after: MetadataRecovery,
    package_ref_value: str,
) -> bool:
    changed = [
        (old, new)
        for old, new in zip(before.packages, after.packages, strict=True)
        if old != new
    ]
    return bool(
        len(changed) == 1
        and changed[0][0].package_ref == package_ref_value
        and changed[0][0].status is PackageRecoveryStatus.DOWNLOADING
        and changed[0][1].status is PackageRecoveryStatus.COMPLETED
    )


def _exact_successor(before: MetadataRecovery, after: MetadataRecovery) -> MetadataRecovery | None:
    """Recreate the sole legal one-step successor using lifecycle operations."""
    if before.status is RecoveryStatus.VERIFY_SCHEDULED and before.next_check_at is not None:
        if after.status is RecoveryStatus.VERIFY_SCHEDULED and after.next_check_at is not None:
            return lifecycle.record_pending_verification(
                before, checked_at=before.next_check_at, sat_next_check_at=after.next_check_at,
            )
        if after.status is RecoveryStatus.PENDING_AFTER_BUDGET:
            return lifecycle.apply_recovery_deadline(before, now=before.deadline_at)
        if after.status is RecoveryStatus.VERIFY_FAILED:
            return lifecycle.record_verification_failure(before, checked_at=before.next_check_at)
        if after.status in {RecoveryStatus.PACKAGES_READY, RecoveryStatus.NO_DATA}:
            return lifecycle.record_finished_verification(
                before,
                checked_at=before.next_check_at,
                package_refs=tuple(item.package_ref for item in after.packages),
                record_count=after.record_count,
            )
        return None
    if before.status not in {RecoveryStatus.PACKAGES_READY, RecoveryStatus.DOWNLOADING}:
        return None
    changed = [(old, new) for old, new in zip(before.packages, after.packages, strict=True) if old != new]
    if len(changed) != 1:
        return None
    old, new = changed[0]
    if old.package_ref != new.package_ref:
        return None
    if old.status is PackageRecoveryStatus.PENDING and new.status is PackageRecoveryStatus.DOWNLOADING:
        return lifecycle.begin_package_download(before, old.package_ref)
    if old.status is PackageRecoveryStatus.DOWNLOADING:
        return lifecycle.record_package_download(
            before,
            old.package_ref,
            zip_valid=new.zip_valid,
            txt_count=new.txt_count,
            uncertain=new.status is PackageRecoveryStatus.UNCERTAIN,
        )
    return None


def _record_from_document(
    value: object, *, schema_version: int,
) -> MetadataRecoveryStateRecord:
    keys = _LEGACY_RECORD_KEYS if schema_version == _LEGACY_SCHEMA_VERSION else _RECORD_KEYS
    document = _mapping(value, keys)
    packages = document["packages"]
    if not isinstance(packages, list):
        raise MetadataRecoveryStateError("recovery-state-invalid")
    bindings = tuple(
        PackageIdBinding(_string(item, "packageRef"), _string(item, "idPaquete"))
        for item in packages if _mapping(item, {"packageRef", "idPaquete"})
    )
    artifacts_value = document["artifacts"]
    if type(artifacts_value) is not list:
        raise MetadataRecoveryStateError("artifact-binding-invalid")
    try:
        artifacts = tuple(
            MetadataPackageArtifactState.from_private_document(item)
            for item in artifacts_value
        )
    except MetadataArtifactStateError:
        raise MetadataRecoveryStateError("artifact-binding-invalid") from None
    return MetadataRecoveryStateRecord(
        recovery=_recovery_from_document(document["recovery"]),
        id_solicitud=_string(document, "idSolicitud"), profile_id=_string(document, "profileId"),
        direction=_string(document, "direction"), kind=_string(document, "kind"),
        fecha_inicial=_string(document, "fechaInicial"), fecha_final=_string(document, "fechaFinal"),
        criteria_hash=_string(document, "criteriaHash"), authorization_ref=_string(document, "authorizationRef"),
        package_bindings=bindings,
        artifact_bindings=artifacts,
        observation_provenance=(
            None if schema_version == _LEGACY_SCHEMA_VERSION
            else _provenance_from_document(document["observationProvenance"])
        ),
    )


def _provenance_from_document(value: object) -> MetadataObservationProvenance | None:
    if value is None:
        return None
    try:
        document = _mapping(value, _PROVENANCE_KEYS)
        return MetadataObservationProvenance(
            projection_version=_integer(document, "projectionVersion"),
            tested_commit=_string(document, "testedCommit"),
            observed_at=_parse_datetime(_string(document, "observedAt")),
            entry_point=_string(document, "entryPoint"),
            verify_contacts_not_before_due=_integer(document, "verifyContactsNotBeforeDue"),
            verify_contacts_before_due=_integer(document, "verifyContactsBeforeDue"),
            verify_contacts_due_unknown=_integer(document, "verifyContactsDueUnknown"),
        )
    except (MetadataRecoveryStateError, TypeError, ValueError):
        raise MetadataRecoveryStateError("observation-provenance-invalid") from None


def _provenance_document(
    provenance: MetadataObservationProvenance | None,
) -> dict[str, object] | None:
    if provenance is None:
        return None
    return {
        "projectionVersion": provenance.projection_version,
        "testedCommit": provenance.tested_commit,
        "observedAt": provenance.observed_at.isoformat().replace("+00:00", "Z"),
        "entryPoint": provenance.entry_point,
        "verifyContactsNotBeforeDue": provenance.verify_contacts_not_before_due,
        "verifyContactsBeforeDue": provenance.verify_contacts_before_due,
        "verifyContactsDueUnknown": provenance.verify_contacts_due_unknown,
    }


def _recovery_from_document(value: object) -> MetadataRecovery:
    document = _mapping(value, _RECOVERY_KEYS)
    packages_value = document["packages"]
    if not isinstance(packages_value, list):
        raise MetadataRecoveryStateError("recovery-state-invalid")
    try:
        packages = tuple(PackageRecovery(
            _string(item, "packageRef"), PackageRecoveryStatus(_string(item, "status")),
            _optional_bool(item, "zipValid"), _integer(item, "txtCount"),
        ) for item in packages_value if _mapping(item, {"packageRef", "status", "zipValid", "txtCount"}))
        next_check = _string(document, "nextCheckAt")
        recovery = MetadataRecovery(
            _string(document, "recoveryRef"), _parse_datetime(_string(document, "createdAt")),
            _parse_datetime(_string(document, "deadlineAt")), RecoveryStatus(_string(document, "status")),
            _integer(document, "verifyAttempts"), _parse_datetime(next_check) if next_check else None,
            _record_count(document, "recordCount"), packages,
        )
        if recovery.to_redacted_document() != dict(document):
            raise MetadataRecoveryStateError("recovery-state-invalid")
    except ValueError:
        pass
    else:
        return recovery
    raise MetadataRecoveryStateError("recovery-state-invalid")


def _resolved_state_path(
    storage_root: str | Path,
    *,
    repo_root: str | Path | None,
    create_parent: bool,
) -> Path:
    root = _canonical_storage_root(storage_root, repo_root=repo_root)
    path = root / "state" / "sat-metadata-recoveries.json"
    repository = Path(repo_root).expanduser() if repo_root is not None else _REPO_ROOT
    try:
        if create_parent:
            path.parent.mkdir(parents=True, exist_ok=True)
        parent = path.parent.resolve(strict=False)
        resolved = path.resolve(strict=False)
        repository = repository.resolve(strict=False)
    except (OSError, RuntimeError):
        raise MetadataRecoveryStateError("recovery-state-path-invalid")
    if _is_within(parent, repository) or _is_within(resolved, repository):
        raise MetadataRecoveryStateError("storage-root-inside-repository")
    if not _is_within(parent, root) or not _is_within(resolved, root):
        raise MetadataRecoveryStateError("recovery-state-path-invalid")
    return resolved


@contextmanager
def _exclusive_state_lock(path: Path):
    """Hold a stable OS advisory lock across the full state transaction."""
    lock = path.with_name(f".{path.name}.lock")
    descriptor: int | None = None
    try:
        _validate_auxiliary_path(lock, path.parent)
        flags = os.O_CREAT | os.O_RDWR
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(lock, flags, 0o600)
        _validate_open_lock(lock, path.parent, descriptor)
        _acquire_advisory_lock(descriptor)
        if os.fstat(descriptor).st_size < 1:
            os.lseek(descriptor, 0, os.SEEK_SET)
            os.write(descriptor, b"\0")
            os.fsync(descriptor)
    except MetadataRecoveryStateError:
        if descriptor is not None:
            os.close(descriptor)
        raise
    except OSError:
        if descriptor is not None:
            os.close(descriptor)
        raise MetadataRecoveryStateError("recovery-state-lock-failed") from None
    try:
        yield
    finally:
        body_failed = sys.exc_info()[0] is not None
        release_failed = False
        try:
            _release_advisory_lock(descriptor)
        except OSError:
            release_failed = True
        try:
            os.close(descriptor)
        except OSError:
            release_failed = True
        if release_failed and not body_failed:
            raise MetadataRecoveryStateError("recovery-state-lock-release-failed") from None


def _canonical_storage_root(
    storage_root: str | Path, *, repo_root: str | Path | None,
) -> Path:
    root = Path(storage_root).expanduser()
    repository = Path(repo_root).expanduser() if repo_root is not None else _REPO_ROOT
    if not root.is_absolute() or not repository.is_absolute():
        raise MetadataRecoveryStateError("storage-root-not-absolute")
    try:
        root, repository = root.resolve(strict=False), repository.resolve(strict=False)
    except (OSError, RuntimeError):
        raise MetadataRecoveryStateError("recovery-state-path-invalid") from None
    if root == repository or repository in root.parents:
        raise MetadataRecoveryStateError("storage-root-inside-repository")
    return root


def _is_within(path: Path, root: Path) -> bool:
    return path == root or root in path.parents


def _validate_auxiliary_path(path: Path, parent: Path) -> None:
    try:
        if path.is_symlink() or not _is_within(path.resolve(strict=False), parent.resolve(strict=True)):
            raise MetadataRecoveryStateError("recovery-state-path-invalid")
    except (OSError, RuntimeError):
        raise MetadataRecoveryStateError("recovery-state-path-invalid") from None


def _validate_open_lock(path: Path, parent: Path, descriptor: int) -> None:
    """Reject a swapped or linked lock target after opening its descriptor."""
    _validate_auxiliary_path(path, parent)
    try:
        named, opened = os.stat(path, follow_symlinks=False), os.fstat(descriptor)
    except OSError:
        raise MetadataRecoveryStateError("recovery-state-path-invalid") from None
    if stat.S_ISLNK(named.st_mode) or (named.st_dev, named.st_ino) != (opened.st_dev, opened.st_ino):
        raise MetadataRecoveryStateError("recovery-state-path-invalid")


def _acquire_advisory_lock(descriptor: int) -> None:
    os.lseek(descriptor, 0, os.SEEK_SET)
    try:
        if os.name == "nt":
            import msvcrt

            msvcrt.locking(descriptor, msvcrt.LK_NBLCK, 1)
        else:
            import fcntl

            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except (BlockingIOError, PermissionError):
        raise MetadataRecoveryStateError("recovery-state-busy") from None
    except OSError:
        raise MetadataRecoveryStateError("recovery-state-lock-failed") from None


def _release_advisory_lock(descriptor: int) -> None:
    os.lseek(descriptor, 0, os.SEEK_SET)
    if os.name == "nt":
        import msvcrt

        msvcrt.locking(descriptor, msvcrt.LK_UNLCK, 1)
    else:
        import fcntl

        fcntl.flock(descriptor, fcntl.LOCK_UN)


def _read_state(path: Path) -> dict[str, object]:
    try:
        contents = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return {"schemaVersion": _SCHEMA_VERSION, "recoveries": []}
    except OSError:
        contents = None
    if contents is None:
        raise MetadataRecoveryStateError("recovery-state-unreadable")
    parse_failed = False
    try:
        document = json.loads(contents, object_pairs_hook=_unique_object)
    except json.JSONDecodeError:
        parse_failed = True
    if parse_failed:
        raise MetadataRecoveryStateError("recovery-state-unreadable")
    mapped = _mapping(document, _STATE_KEYS)
    if (
        type(mapped["schemaVersion"]) is not int
        or mapped["schemaVersion"] not in {_LEGACY_SCHEMA_VERSION, _SCHEMA_VERSION}
        or type(mapped["recoveries"]) is not list
    ):
        raise MetadataRecoveryStateError("recovery-state-unsupported")
    return dict(mapped)


def _write_state(path: Path, records: list[MetadataRecoveryStateRecord]) -> None:
    tmp: Path | None = None
    write_failed = False
    try:
        payload = {"schemaVersion": _SCHEMA_VERSION, "recoveries": [item.to_private_document() for item in records]}
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", newline="\n", prefix=f".{path.name}.tmp-", dir=path.parent, delete=False) as stream:
            tmp = Path(stream.name)
            stream.write(json.dumps(payload, indent=2, sort_keys=True) + "\n")
        _validate_auxiliary_path(tmp, path.parent)
        os.replace(tmp, path)
    except MetadataRecoveryStateError:
        if tmp is not None:
            tmp.unlink(missing_ok=True)
        raise
    except (OSError, TypeError, ValueError):
        write_failed = True
    if write_failed:
        if tmp is not None:
            try:
                tmp.unlink(missing_ok=True)
            except OSError:
                pass
        raise MetadataRecoveryStateError("recovery-state-write-failed")


def _identity(record: MetadataRecoveryStateRecord) -> tuple[str, ...]:
    return (record.id_solicitud, record.profile_id, record.direction, record.kind, record.fecha_inicial,
            record.fecha_final, record.criteria_hash, record.authorization_ref)


def _mapping(value: object, keys: set[str]) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or set(value) != keys:
        raise MetadataRecoveryStateError("recovery-state-invalid")
    return value


def _string(document: Mapping[str, object], key: str) -> str:
    value = document.get(key)
    if not isinstance(value, str):
        raise MetadataRecoveryStateError("recovery-state-invalid")
    return value


def _integer(document: Mapping[str, object], key: str) -> int:
    value = document.get(key)
    if isinstance(value, bool) or not isinstance(value, int):
        raise MetadataRecoveryStateError("recovery-state-invalid")
    return value


def _record_count(document: Mapping[str, object], key: str) -> int | None:
    value = document.get(key)
    if value == "not_reported":
        return None
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise MetadataRecoveryStateError("recovery-state-invalid")
    return value


def _optional_bool(document: Mapping[str, object], key: str) -> bool | None:
    value = document.get(key)
    if value is not None and not isinstance(value, bool):
        raise MetadataRecoveryStateError("recovery-state-invalid")
    return value


def _parse_datetime(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise MetadataRecoveryStateError("recovery-state-invalid")
    return parsed.astimezone(timezone.utc)


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    document: dict[str, object] = {}
    for key, value in pairs:
        if key in document:
            raise MetadataRecoveryStateError("recovery-state-duplicate-key")
        document[key] = value
    return document
