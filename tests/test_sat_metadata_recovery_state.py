import json
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

import cfdi_vault.sat_metadata_recovery as lifecycle
import cfdi_vault.sat_metadata_recovery_state as subject

START = datetime(2026, 6, 30, tzinfo=timezone.utc)
CRITERIA_HASH = "a" * 64
REQUEST_ID = "synthetic-request-alpha"
PACKAGE_IDS = ("synthetic-package-alpha", "synthetic-package-beta")


def test_private_state_round_trips_exact_lifecycle_and_package_bindings(tmp_path) -> None:
    assert subject.list_metadata_recovery_states(tmp_path) == ()
    record = _ready_record()
    recovery = lifecycle.begin_package_download(record.recovery, subject.package_ref(PACKAGE_IDS[0]))
    recovery = lifecycle.record_package_download(recovery, subject.package_ref(PACKAGE_IDS[0]), zip_valid=True, txt_count=1)
    record = replace(record, recovery=recovery)
    subject.save_metadata_recovery_state(tmp_path, record)
    first = subject.metadata_recovery_state_path(tmp_path).read_bytes()
    subject.save_metadata_recovery_state(tmp_path, record)
    loaded = subject.load_metadata_recovery_state(tmp_path, record.recovery.recovery_ref)
    assert loaded == record
    assert loaded.recovery.to_redacted_document() == recovery.to_redacted_document()
    assert subject.list_metadata_recovery_states(tmp_path) == (record,)
    assert subject.metadata_recovery_state_path(tmp_path).name == "sat-metadata-recoveries.json"
    assert subject.metadata_recovery_state_path(tmp_path).read_bytes() == first


def test_redacted_state_excludes_all_private_resume_values() -> None:
    record = _ready_record()
    serialized = repr(record.to_redacted_document())
    for private in (record.id_solicitud, record.profile_id, record.criteria_hash, record.authorization_ref, *PACKAGE_IDS):
        assert private not in serialized


@pytest.mark.parametrize(
    "document",
    (
        "{",
        json.dumps({"schemaVersion": 2, "recoveries": []}),
        json.dumps({"schemaVersion": 1, "recoveries": [], "unexpected": True}),
    ),
)
def test_loader_fails_closed_for_invalid_or_unknown_state(tmp_path, document: str) -> None:
    path = subject.metadata_recovery_state_path(tmp_path)
    path.parent.mkdir(parents=True)
    path.write_text(document, encoding="utf-8")

    with pytest.raises(subject.MetadataRecoveryStateError):
        subject.list_metadata_recovery_states(tmp_path)


def test_rejects_duplicate_or_mismatched_package_bindings() -> None:
    ready = _ready_record()
    with pytest.raises(subject.MetadataRecoveryStateError, match="package-binding-invalid"):
        replace(ready, package_bindings=(ready.package_bindings[0],) * 2)


def test_same_sat_request_cannot_be_bound_to_a_different_scope(tmp_path) -> None:
    original = _pending_record()
    subject.save_metadata_recovery_state(tmp_path, original)
    other = subject.new_metadata_recovery_state(
        recovery=lifecycle.start_metadata_recovery(subject.recovery_ref("profile-other", CRITERIA_HASH, REQUEST_ID), created_at=START),
        id_solicitud=REQUEST_ID,
        profile_id="profile-other",
        direction="received",
        kind="metadata",
        fecha_inicial="2026-06-30",
        fecha_final="2026-06-30",
        criteria_hash=CRITERIA_HASH,
        authorization_ref="permit-other-synthetic",
    )

    with pytest.raises(subject.MetadataRecoveryStateError, match="request-already-bound"):
        subject.save_metadata_recovery_state(tmp_path, other)


def test_save_accepts_forward_lifecycle_and_rejects_stale_replacement(tmp_path) -> None:
    original = _pending_record()
    advanced = replace(
        original,
        recovery=lifecycle.record_pending_verification(original.recovery, checked_at=START),
    )
    subject.save_metadata_recovery_state(tmp_path, original)
    subject.save_metadata_recovery_state(tmp_path, advanced)

    with pytest.raises(subject.MetadataRecoveryStateError, match="recovery-state-regression"):
        subject.save_metadata_recovery_state(tmp_path, original)

    assert subject.load_metadata_recovery_state(tmp_path, original.recovery.recovery_ref) == advanced


@pytest.mark.parametrize("operation", ("remove", "reorder"))
def test_save_rejects_changes_to_observed_package_bindings(tmp_path, operation: str) -> None:
    original = _ready_record()
    subject.save_metadata_recovery_state(tmp_path, original)
    if operation == "remove":
        packages = original.recovery.packages[:1]
        bindings = original.package_bindings[:1]
    else:
        packages = tuple(reversed(original.recovery.packages))
        bindings = tuple(reversed(original.package_bindings))
    changed = replace(original, recovery=replace(original.recovery, packages=packages), package_bindings=bindings)

    with pytest.raises(subject.MetadataRecoveryStateError, match="package-binding-immutable"):
        subject.save_metadata_recovery_state(tmp_path, changed)


def test_package_binding_cannot_be_remapped() -> None:
    original = _ready_record()
    remapped = subject.PackageIdBinding(original.package_bindings[0].package_ref, "synthetic-package-other")

    with pytest.raises(subject.MetadataRecoveryStateError, match="package-binding-invalid"):
        replace(original, package_bindings=(remapped, original.package_bindings[1]))


def test_state_root_must_be_absolute_and_external_to_repository(tmp_path) -> None:
    repo_root = tmp_path / "checkout"
    repo_root.mkdir()
    with pytest.raises(subject.MetadataRecoveryStateError, match="storage-root-not-absolute"):
        subject.metadata_recovery_state_path(Path("relative-storage"), repo_root=repo_root)
    with pytest.raises(subject.MetadataRecoveryStateError, match="storage-root-inside-repository"):
        subject.metadata_recovery_state_path(repo_root / "private", repo_root=repo_root)

    external = tmp_path / "external"
    assert subject.metadata_recovery_state_path(external, repo_root=repo_root).is_relative_to(external)


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("verifyAttempts", -1),
        ("recordCount", -1),
        ("deadlineAt", (START + timedelta(days=8)).isoformat().replace("+00:00", "Z")),
        ("nextCheckAt", ""),
        ("status", "completed"),
    ),
)
def test_loader_rejects_semantically_impossible_lifecycle(tmp_path, field: str, value: object) -> None:
    document = _state_document(_pending_record())
    document["recoveries"][0]["recovery"][field] = value
    _write_document(tmp_path, document)

    with pytest.raises(subject.MetadataRecoveryStateError, match="recovery-state-invalid"):
        subject.list_metadata_recovery_states(tmp_path)


def test_loader_rejects_incoherent_package_status_aggregate(tmp_path) -> None:
    document = _state_document(_ready_record())
    document["recoveries"][0]["recovery"]["packages"][0]["status"] = "completed"
    _write_document(tmp_path, document)

    with pytest.raises(subject.MetadataRecoveryStateError, match="recovery-state-invalid"):
        subject.list_metadata_recovery_states(tmp_path)


def test_private_dataclass_repr_is_redacted() -> None:
    record = _ready_record()
    serialized = repr((record, *record.package_bindings))
    for private in (
        record.id_solicitud,
        record.profile_id,
        record.criteria_hash,
        record.authorization_ref,
        *PACKAGE_IDS,
    ):
        assert private not in serialized


@pytest.mark.parametrize(
    "document",
    (
        '{"schemaVersion":1,"schemaVersion":1,"recoveries":[]}',
        '{"schemaVersion":1,"recoveries":[{"recovery":{},"recovery":{}}]}',
    ),
)
def test_loader_rejects_duplicate_json_keys_at_any_level(tmp_path, document: str) -> None:
    path = subject.metadata_recovery_state_path(tmp_path)
    path.parent.mkdir(parents=True)
    path.write_text(document, encoding="utf-8")

    with pytest.raises(subject.MetadataRecoveryStateError, match="recovery-state-duplicate-key"):
        subject.list_metadata_recovery_states(tmp_path)


def _pending_record() -> subject.MetadataRecoveryStateRecord:
    recovery = lifecycle.start_metadata_recovery(subject.recovery_ref("profile-synthetic", CRITERIA_HASH, REQUEST_ID), created_at=START)
    return subject.new_metadata_recovery_state(
        recovery=recovery,
        id_solicitud=REQUEST_ID,
        profile_id="profile-synthetic",
        direction="received",
        kind="metadata",
        fecha_inicial="2026-06-30",
        fecha_final="2026-06-30",
        criteria_hash=CRITERIA_HASH,
        authorization_ref="permit-alpha-synthetic",
    )


def _ready_record() -> subject.MetadataRecoveryStateRecord:
    pending = _pending_record()
    recovery = lifecycle.record_finished_verification(
        pending.recovery,
        checked_at=START,
        package_refs=tuple(subject.package_ref(value) for value in PACKAGE_IDS),
        record_count=2,
    )
    return subject.new_metadata_recovery_state(
        recovery=recovery,
        id_solicitud=pending.id_solicitud,
        profile_id=pending.profile_id,
        direction=pending.direction,
        kind=pending.kind,
        fecha_inicial=pending.fecha_inicial,
        fecha_final=pending.fecha_final,
        criteria_hash=pending.criteria_hash,
        authorization_ref=pending.authorization_ref,
        package_ids=PACKAGE_IDS,
    )


def _state_document(record: subject.MetadataRecoveryStateRecord) -> dict[str, object]:
    return {"schemaVersion": 1, "recoveries": [record.to_private_document()]}


def _write_document(tmp_path: Path, document: dict[str, object]) -> None:
    path = subject.metadata_recovery_state_path(tmp_path)
    path.parent.mkdir(parents=True)
    path.write_text(json.dumps(document), encoding="utf-8")
