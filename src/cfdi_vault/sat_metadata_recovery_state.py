"""Private durable state for one resumable SAT metadata recovery."""

from __future__ import annotations

import hashlib
import json
import os
import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

from cfdi_vault.sat_metadata_recovery import (
    MetadataRecovery,
    PackageRecovery,
    PackageRecoveryStatus,
    RecoveryStatus,
)

_SCHEMA_VERSION = 1
_STATE_KEYS = {"schemaVersion", "recoveries"}
_RECORD_KEYS = {
    "recovery", "idSolicitud", "profileId", "direction", "kind", "fechaInicial",
    "fechaFinal", "criteriaHash", "authorizationRef", "packages",
}
_RECOVERY_KEYS = {
    "schemaVersion", "recoveryRef", "status", "createdAt", "deadlineAt", "verifyAttempts",
    "nextCheckAt", "recordCount", "packageCount", "downloadedPackageCount", "zipValidCount",
    "txtCount", "packages",
}
_HASH_RE = re.compile(r"[0-9a-f]{64}")
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

    def __post_init__(self) -> None:
        _validate_record(self)

    def to_redacted_document(self) -> dict[str, object]:
        """Return status only; exclude every private resume value."""
        return self.recovery.to_redacted_document()

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
) -> MetadataRecoveryStateRecord:
    """Build validated private state and deterministic package bindings."""
    bindings = tuple(PackageIdBinding(package_ref(value), value) for value in package_ids)
    return MetadataRecoveryStateRecord(
        recovery, id_solicitud, profile_id, direction, kind, fecha_inicial,
        fecha_final, criteria_hash, authorization_ref, bindings,
    )


def metadata_recovery_state_path(
    storage_root: str | Path, *, repo_root: str | Path | None = None,
) -> Path:
    """Return the fixed, non-sensitive state path under configured storage."""
    root = Path(storage_root).expanduser()
    repository = Path(repo_root).expanduser() if repo_root is not None else _REPO_ROOT
    if not root.is_absolute() or not repository.is_absolute():
        raise MetadataRecoveryStateError("storage-root-not-absolute")
    root, repository = root.resolve(), repository.resolve()
    if root == repository or repository in root.parents:
        raise MetadataRecoveryStateError("storage-root-inside-repository")
    return root / "state" / "sat-metadata-recoveries.json"


def save_metadata_recovery_state(
    storage_root: str | Path,
    record: MetadataRecoveryStateRecord,
    *,
    repo_root: str | Path | None = None,
) -> None:
    """Atomically insert or update one record without rebinding its request."""
    records = list(list_metadata_recovery_states(storage_root, repo_root=repo_root))
    for current in records:
        if current.id_solicitud == record.id_solicitud and current.recovery.recovery_ref != record.recovery.recovery_ref:
            raise MetadataRecoveryStateError("request-already-bound")
        if current.recovery.recovery_ref == record.recovery.recovery_ref and _identity(current) != _identity(record):
            raise MetadataRecoveryStateError("recovery-ref-conflict")
        if current.recovery.recovery_ref == record.recovery.recovery_ref:
            _validate_replacement(current, record)
    records = [item for item in records if item.recovery.recovery_ref != record.recovery.recovery_ref]
    records.append(record)
    records.sort(key=lambda item: item.recovery.created_at, reverse=True)
    _write_state(metadata_recovery_state_path(storage_root, repo_root=repo_root), records)


def list_metadata_recovery_states(
    storage_root: str | Path, *, repo_root: str | Path | None = None,
) -> tuple[MetadataRecoveryStateRecord, ...]:
    """Load all private records, failing closed on malformed or duplicate state."""
    document = _read_state(metadata_recovery_state_path(storage_root, repo_root=repo_root))
    records = tuple(_record_from_document(item) for item in document["recoveries"])
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
    values = (record.id_solicitud, record.profile_id, record.authorization_ref)
    if any(not isinstance(value, str) or not value.strip() for value in values):
        raise MetadataRecoveryStateError("recovery-state-invalid")
    if record.direction not in {"issued", "received"} or record.kind != "metadata":
        raise MetadataRecoveryStateError("recovery-scope-invalid")
    if not _HASH_RE.fullmatch(record.criteria_hash):
        raise MetadataRecoveryStateError("criteria-hash-invalid")
    try:
        start, end = date.fromisoformat(record.fecha_inicial), date.fromisoformat(record.fecha_final)
    except (TypeError, ValueError) as exc:
        raise MetadataRecoveryStateError("recovery-dates-invalid") from exc
    if start > end or record.recovery.recovery_ref != recovery_ref(
        record.profile_id, record.criteria_hash, record.id_solicitud
    ):
        raise MetadataRecoveryStateError("recovery-ref-mismatch")
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


def _validate_recovery(recovery: MetadataRecovery) -> None:
    """Reject lifecycle values that no public transition can produce."""
    try:
        recovery.to_redacted_document()
    except ValueError as exc:
        raise MetadataRecoveryStateError("recovery-state-invalid") from exc
    datetimes = (recovery.created_at, recovery.deadline_at, recovery.next_check_at)
    if (
        any(value is not None and value.utcoffset() is None for value in datetimes)
        or recovery.deadline_at != recovery.created_at + timedelta(days=7)
        or recovery.verify_attempts < 0
        or recovery.record_count < 0
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
    no_packages = not statuses and recovery.record_count == 0
    pending = recovery.status is RecoveryStatus.VERIFY_SCHEDULED
    valid = {
        RecoveryStatus.VERIFY_SCHEDULED: no_packages and recovery.next_check_at is not None,
        RecoveryStatus.PENDING_AFTER_BUDGET: no_packages and recovery.next_check_at is None,
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
        RecoveryStatus.DOWNLOAD_UNCERTAIN: PackageRecoveryStatus.UNCERTAIN in statuses
        and all(s not in {PackageRecoveryStatus.DOWNLOADING, PackageRecoveryStatus.FAILED} for s in statuses),
        RecoveryStatus.DOWNLOAD_FAILED: bool(statuses)
        and all(s not in {PackageRecoveryStatus.DOWNLOADING, PackageRecoveryStatus.UNCERTAIN} for s in statuses)
        and (PackageRecoveryStatus.FAILED in statuses
             or (all(s is PackageRecoveryStatus.COMPLETED for s in statuses) and recovery.txt_count == 0)),
    }[recovery.status]
    if (
        not valid
        or (not pending and recovery.status not in {RecoveryStatus.PENDING_AFTER_BUDGET}
            and recovery.packages and (recovery.next_check_at is not None or recovery.verify_attempts == 0))
        or (pending and recovery.next_check_at is not None and recovery.next_check_at < recovery.created_at)
    ):
        raise MetadataRecoveryStateError("recovery-state-invalid")


def _validate_replacement(
    current: MetadataRecoveryStateRecord, candidate: MetadataRecoveryStateRecord,
) -> None:
    if current == candidate:
        return
    if current.package_bindings and current.package_bindings != candidate.package_bindings:
        raise MetadataRecoveryStateError("package-binding-immutable")
    before, after = current.recovery, candidate.recovery
    allowed = {
        RecoveryStatus.VERIFY_SCHEDULED: {
            RecoveryStatus.VERIFY_SCHEDULED, RecoveryStatus.PACKAGES_READY,
            RecoveryStatus.NO_DATA, RecoveryStatus.PENDING_AFTER_BUDGET,
        },
        RecoveryStatus.PACKAGES_READY: {RecoveryStatus.DOWNLOADING},
        RecoveryStatus.DOWNLOADING: {
            RecoveryStatus.DOWNLOADING, RecoveryStatus.COMPLETED,
            RecoveryStatus.DOWNLOAD_UNCERTAIN, RecoveryStatus.DOWNLOAD_FAILED,
        },
    }
    immutable = (before.recovery_ref, before.created_at, before.deadline_at)
    if (
        after.status not in allowed.get(before.status, set())
        or immutable != (after.recovery_ref, after.created_at, after.deadline_at)
        or after.verify_attempts < before.verify_attempts
        or (before.status is RecoveryStatus.VERIFY_SCHEDULED
            and after.status is not RecoveryStatus.PENDING_AFTER_BUDGET
            and after.verify_attempts == before.verify_attempts)
        or (before.status is not RecoveryStatus.VERIFY_SCHEDULED
            and (after.verify_attempts != before.verify_attempts or after.record_count != before.record_count))
    ):
        raise MetadataRecoveryStateError("recovery-state-regression")
    if before.packages:
        transitions = {
            PackageRecoveryStatus.PENDING: {PackageRecoveryStatus.PENDING, PackageRecoveryStatus.DOWNLOADING},
            PackageRecoveryStatus.DOWNLOADING: {
                PackageRecoveryStatus.COMPLETED, PackageRecoveryStatus.UNCERTAIN, PackageRecoveryStatus.FAILED,
            },
            PackageRecoveryStatus.COMPLETED: {PackageRecoveryStatus.COMPLETED},
            PackageRecoveryStatus.UNCERTAIN: {PackageRecoveryStatus.UNCERTAIN},
            PackageRecoveryStatus.FAILED: {PackageRecoveryStatus.FAILED},
        }
        changed = 0
        for old, new in zip(before.packages, after.packages, strict=True):
            if new.status not in transitions[old.status] or old.package_ref != new.package_ref:
                raise MetadataRecoveryStateError("recovery-state-regression")
            changed += old != new
        if changed != 1:
            raise MetadataRecoveryStateError("recovery-state-regression")


def _record_from_document(value: object) -> MetadataRecoveryStateRecord:
    document = _mapping(value, _RECORD_KEYS)
    packages = document["packages"]
    if not isinstance(packages, list):
        raise MetadataRecoveryStateError("recovery-state-invalid")
    bindings = tuple(
        PackageIdBinding(_string(item, "packageRef"), _string(item, "idPaquete"))
        for item in packages if _mapping(item, {"packageRef", "idPaquete"})
    )
    return MetadataRecoveryStateRecord(
        recovery=_recovery_from_document(document["recovery"]),
        id_solicitud=_string(document, "idSolicitud"), profile_id=_string(document, "profileId"),
        direction=_string(document, "direction"), kind=_string(document, "kind"),
        fecha_inicial=_string(document, "fechaInicial"), fecha_final=_string(document, "fechaFinal"),
        criteria_hash=_string(document, "criteriaHash"), authorization_ref=_string(document, "authorizationRef"),
        package_bindings=bindings,
    )


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
            _integer(document, "recordCount"), packages,
        )
        if recovery.to_redacted_document() != dict(document):
            raise MetadataRecoveryStateError("recovery-state-invalid")
        return recovery
    except ValueError as exc:
        raise MetadataRecoveryStateError("recovery-state-invalid") from exc


def _read_state(path: Path) -> dict[str, object]:
    if not path.exists():
        return {"schemaVersion": _SCHEMA_VERSION, "recoveries": []}
    if not path.is_file():
        raise MetadataRecoveryStateError("recovery-state-unreadable")
    try:
        document = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_unique_object)
    except (OSError, json.JSONDecodeError) as exc:
        raise MetadataRecoveryStateError("recovery-state-unreadable") from exc
    mapped = _mapping(document, _STATE_KEYS)
    if mapped["schemaVersion"] != _SCHEMA_VERSION or not isinstance(mapped["recoveries"], list):
        raise MetadataRecoveryStateError("recovery-state-unsupported")
    return dict(mapped)


def _write_state(path: Path, records: list[MetadataRecoveryStateRecord]) -> None:
    tmp = path.with_name(f".{path.name}.tmp-{os.getpid()}")
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = {"schemaVersion": _SCHEMA_VERSION, "recoveries": [item.to_private_document() for item in records]}
        tmp.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        os.replace(tmp, path)
    except OSError as exc:
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            pass
        raise MetadataRecoveryStateError("recovery-state-write-failed") from exc


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
