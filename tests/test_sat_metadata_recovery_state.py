import json
import multiprocessing
import os
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from threading import Event
from unittest.mock import Mock

import pytest

import cfdi_vault.sat_metadata_recovery as lifecycle
import cfdi_vault.sat_metadata_recovery_state as subject
from cfdi_vault.sat_metadata_artifact_state import (
    MetadataPackageArtifactState,
    MetadataTextArtifact,
)
from cfdi_vault.sat_metadata_package import MetadataTextInspection

START = datetime(2026, 6, 30, tzinfo=timezone.utc)
CRITERIA_HASH = "a" * 64
REQUEST_ID = "synthetic-request-alpha"
PACKAGE_IDS = ("synthetic-package-alpha", "synthetic-package-beta")


def test_private_state_round_trips_exact_lifecycle_and_package_bindings(tmp_path) -> None:
    assert subject.list_metadata_recovery_states(tmp_path) == ()
    pending = _pending_record()
    subject.save_metadata_recovery_state(tmp_path, pending)
    record = _ready_record()
    subject.save_metadata_recovery_state(tmp_path, record)
    recovery = lifecycle.begin_package_download(record.recovery, subject.package_ref(PACKAGE_IDS[0]))
    subject.save_metadata_recovery_state(tmp_path, replace(record, recovery=recovery))
    recovery = lifecycle.record_package_download(recovery, subject.package_ref(PACKAGE_IDS[0]), zip_valid=True, txt_count=1)
    artifact = _artifact(record, 0)
    record = replace(record, recovery=recovery, artifact_bindings=(artifact,))
    subject.save_metadata_recovery_state(tmp_path, record)
    first = subject.metadata_recovery_state_path(tmp_path).read_bytes()
    subject.save_metadata_recovery_state(tmp_path, record)
    loaded = subject.load_metadata_recovery_state(tmp_path, record.recovery.recovery_ref)
    assert loaded == record
    assert loaded.recovery.to_redacted_document() == recovery.to_redacted_document()
    assert subject.list_metadata_recovery_states(tmp_path) == (record,)
    assert subject.metadata_recovery_state_path(tmp_path).name == "sat-metadata-recoveries.json"
    assert subject.metadata_recovery_state_path(tmp_path).read_bytes() == first
    assert _lock_path(tmp_path).exists()


def test_redacted_state_excludes_all_private_resume_values() -> None:
    record = _completed_first_record()
    serialized = repr(record.to_redacted_document())
    artifact = record.artifact_bindings[0]
    for private in (
        record.id_solicitud,
        record.profile_id,
        record.criteria_hash,
        record.authorization_ref,
        artifact.package_sha256,
        artifact.package_storage_key,
        artifact.texts[0].sha256,
        artifact.texts[0].storage_key,
        *PACKAGE_IDS,
    ):
        assert private not in serialized
    assert record.to_redacted_document()["artifacts"] == [artifact.to_redacted_document()]


@pytest.mark.parametrize(
    "document",
    (
        "{",
        json.dumps({"schemaVersion": 1, "recoveries": []}),
        json.dumps({"schemaVersion": 2.0, "recoveries": []}),
        json.dumps({"schemaVersion": 3, "recoveries": []}),
        json.dumps({"schemaVersion": 2, "recoveries": [], "unexpected": True}),
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


def test_artifact_requires_matching_completed_package_and_text_count() -> None:
    ready = _ready_record()
    artifact = _artifact(ready, 0)
    with pytest.raises(subject.MetadataRecoveryStateError, match="artifact-binding-invalid"):
        replace(ready, artifact_bindings=(artifact,))

    downloading = replace(
        ready,
        recovery=lifecycle.begin_package_download(ready.recovery, artifact.package_ref),
    )
    completed = lifecycle.record_package_download(
        downloading.recovery,
        artifact.package_ref,
        zip_valid=True,
        txt_count=2,
    )
    with pytest.raises(subject.MetadataRecoveryStateError, match="artifact-binding-invalid"):
        replace(downloading, recovery=completed, artifact_bindings=(artifact,))
    with pytest.raises(subject.MetadataRecoveryStateError, match="artifact-binding-invalid"):
        replace(downloading, recovery=replace(completed, packages=completed.packages), artifact_bindings=())


def test_artifact_storage_ordinal_must_match_package_order() -> None:
    completed = _completed_first_record()
    artifact = completed.artifact_bindings[0]
    wrong_ordinal = replace(
        artifact,
        package_storage_key=artifact.package_storage_key.replace("/1-", "/2-"),
        texts=(
            replace(
                artifact.texts[0],
                storage_key=artifact.texts[0].storage_key.replace("/1-", "/2-"),
            ),
        ),
    )

    with pytest.raises(subject.MetadataRecoveryStateError, match="artifact-binding-invalid"):
        replace(completed, artifact_bindings=(wrong_ordinal,))


def test_two_package_refs_cannot_share_zip_or_text_storage_keys() -> None:
    completed = _completed_record()
    first, second = completed.artifact_bindings
    duplicate = replace(
        second,
        package_sha256=first.package_sha256,
        package_storage_key=first.package_storage_key,
        texts=(
            replace(
                second.texts[0],
                sha256=first.texts[0].sha256,
                storage_key=first.texts[0].storage_key,
            ),
        ),
    )

    with pytest.raises(subject.MetadataRecoveryStateError, match="artifact-binding-invalid"):
        replace(completed, artifact_bindings=(first, duplicate))


def test_duplicate_artifact_hashes_are_allowed_with_distinct_ordered_keys() -> None:
    completed = _completed_record()
    first, second = completed.artifact_bindings
    same_hashes = replace(
        second,
        package_sha256=first.package_sha256,
        package_storage_key=(
            f"sat-metadata/{completed.recovery.recovery_ref}/packages/"
            f"2-{first.package_sha256[:12]}.zip"
        ),
        texts=(
            replace(
                second.texts[0],
                sha256=first.texts[0].sha256,
                storage_key=(
                    f"sat-metadata/{completed.recovery.recovery_ref}/txt/"
                    f"2-{first.texts[0].sha256[:12]}.txt"
                ),
            ),
        ),
    )

    assert replace(completed, artifact_bindings=(first, same_hashes)).artifact_bindings[1] == same_hashes


def test_artifacts_round_trip_privately_and_advance_sequentially(tmp_path) -> None:
    first = _completed_first_record()
    ready = _ready_record()
    subject.save_metadata_recovery_state(tmp_path, ready)
    with pytest.raises(subject.MetadataRecoveryStateError, match="recovery-state-regression"):
        subject.save_metadata_recovery_state(tmp_path, first)
    downloading_first = replace(
        ready,
        recovery=lifecycle.begin_package_download(
            ready.recovery,
            ready.recovery.packages[0].package_ref,
        ),
    )
    subject.save_metadata_recovery_state(tmp_path, downloading_first)
    subject.save_metadata_recovery_state(tmp_path, first)

    downloading_second = replace(
        first,
        recovery=lifecycle.begin_package_download(first.recovery, first.recovery.packages[1].package_ref),
    )
    subject.save_metadata_recovery_state(tmp_path, downloading_second)
    second_artifact = _artifact(first, 1)
    completed = replace(
        downloading_second,
        recovery=lifecycle.record_package_download(
            downloading_second.recovery,
            second_artifact.package_ref,
            zip_valid=True,
            txt_count=1,
        ),
        artifact_bindings=first.artifact_bindings + (second_artifact,),
    )
    subject.save_metadata_recovery_state(tmp_path, completed)

    assert subject.load_metadata_recovery_state(tmp_path, completed.recovery.recovery_ref) == completed
    with pytest.raises(subject.MetadataRecoveryStateError, match="artifact-binding-invalid"):
        replace(completed, artifact_bindings=tuple(reversed(completed.artifact_bindings)))
    private = json.loads(subject.metadata_recovery_state_path(tmp_path).read_text(encoding="utf-8"))
    assert private["schemaVersion"] == 2
    assert private["recoveries"][0]["artifacts"] == [
        item.to_private_document() for item in completed.artifact_bindings
    ]


def test_save_rejects_removed_reordered_or_replaced_artifact(tmp_path) -> None:
    current = _completed_first_record()
    subject.save_metadata_recovery_state(tmp_path, current)
    original = current.artifact_bindings[0]
    replacement = replace(
        original,
        package_sha256="d" * 64,
        package_storage_key=(
            f"sat-metadata/{current.recovery.recovery_ref}/packages/1-{'d' * 12}.zip"
        ),
    )
    with pytest.raises(subject.MetadataRecoveryStateError, match="artifact-binding-invalid"):
        replace(current, artifact_bindings=())
    with pytest.raises(subject.MetadataRecoveryStateError, match="artifact-binding-immutable"):
        subject.save_metadata_recovery_state(
            tmp_path,
            replace(current, artifact_bindings=(replacement,)),
        )


def test_loader_rejects_mixed_or_malformed_artifact_schema(tmp_path) -> None:
    record = _completed_first_record()
    document = _state_document(record)
    del document["recoveries"][0]["artifacts"]
    _write_document(tmp_path, document)
    with pytest.raises(subject.MetadataRecoveryStateError):
        subject.list_metadata_recovery_states(tmp_path)

    document = _state_document(record)
    document["recoveries"][0]["artifacts"][0]["schemaVersion"] = 2
    _write_document(tmp_path, document)
    with pytest.raises(subject.MetadataRecoveryStateError, match="artifact-binding-invalid"):
        subject.list_metadata_recovery_states(tmp_path)


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
    checked_at = original.recovery.next_check_at
    assert checked_at is not None
    advanced = replace(
        original,
        recovery=lifecycle.record_pending_verification(original.recovery, checked_at=checked_at),
    )
    subject.save_metadata_recovery_state(tmp_path, original)
    subject.save_metadata_recovery_state(tmp_path, advanced)

    with pytest.raises(subject.MetadataRecoveryStateError, match="recovery-state-regression"):
        subject.save_metadata_recovery_state(tmp_path, original)

    assert subject.load_metadata_recovery_state(tmp_path, original.recovery.recovery_ref) == advanced


def test_save_rejects_non_exact_verification_successors(tmp_path) -> None:
    original = _pending_record()
    subject.save_metadata_recovery_state(tmp_path, original)
    candidates = (
        replace(
            original.recovery,
            verify_attempts=2,
            next_check_at=original.recovery.next_check_at + timedelta(hours=1),
        ),
        replace(
            original.recovery,
            verify_attempts=1,
            next_check_at=original.recovery.next_check_at,
        ),
        replace(
            lifecycle.apply_recovery_deadline(original.recovery, now=original.recovery.deadline_at),
            verify_attempts=1,
        ),
    )
    for recovery in candidates:
        with pytest.raises(subject.MetadataRecoveryStateError, match="recovery-state-(regression|invalid)"):
            subject.save_metadata_recovery_state(tmp_path, replace(original, recovery=recovery))


def test_verify_failed_round_trips_only_as_exact_monotonic_successor(tmp_path) -> None:
    original = _pending_record()
    due = original.recovery.next_check_at
    assert due is not None
    failed = replace(
        original,
        recovery=lifecycle.record_verification_failure(original.recovery, checked_at=due),
    )
    subject.save_metadata_recovery_state(tmp_path, original)
    subject.save_metadata_recovery_state(tmp_path, failed)
    subject.save_metadata_recovery_state(tmp_path, failed)

    assert subject.load_metadata_recovery_state(tmp_path, original.recovery.recovery_ref) == failed
    forged = replace(failed, recovery=replace(failed.recovery, verify_attempts=2))
    with pytest.raises(subject.MetadataRecoveryStateError, match="recovery-state-regression"):
        subject.save_metadata_recovery_state(tmp_path, forged)


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("verifyAttempts", 0),
        ("verifyAttempts", 27),
        ("nextCheckAt", (START + timedelta(minutes=5)).isoformat().replace("+00:00", "Z")),
        ("recordCount", 1),
    ),
)
def test_loader_rejects_malformed_verify_failed_lifecycle(
    tmp_path, field: str, value: object,
) -> None:
    original = _pending_record()
    due = original.recovery.next_check_at
    assert due is not None
    failed = replace(
        original,
        recovery=lifecycle.record_verification_failure(original.recovery, checked_at=due),
    )
    document = _state_document(failed)
    document["recoveries"][0]["recovery"][field] = value
    _write_document(tmp_path, document)

    with pytest.raises(subject.MetadataRecoveryStateError, match="recovery-state-invalid"):
        subject.list_metadata_recovery_states(tmp_path)


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


def test_save_rejects_state_directory_symlinked_into_repository(tmp_path) -> None:
    repo_root = tmp_path / "checkout"
    repo_root.mkdir()
    external = tmp_path / "external"
    external.mkdir()
    (external / "state").symlink_to(repo_root, target_is_directory=True)

    with pytest.raises(subject.MetadataRecoveryStateError, match="storage-root-inside-repository"):
        subject.save_metadata_recovery_state(external, _pending_record(), repo_root=repo_root)

    assert not (repo_root / "sat-metadata-recoveries.json").exists()


def test_configured_storage_root_symlink_uses_its_external_target(tmp_path) -> None:
    repo_root = tmp_path / "checkout"
    repo_root.mkdir()
    target = tmp_path / "canonical-storage"
    target.mkdir()
    configured = tmp_path / "configured-storage"
    configured.symlink_to(target, target_is_directory=True)

    subject.save_metadata_recovery_state(configured, _pending_record(), repo_root=repo_root)

    assert subject.metadata_recovery_state_path(configured, repo_root=repo_root).is_relative_to(target.resolve())
    assert subject.list_metadata_recovery_states(configured, repo_root=repo_root) == (_pending_record(),)


def test_save_rejects_state_directory_symlinked_to_other_external_root(tmp_path) -> None:
    repo_root = tmp_path / "checkout"
    repo_root.mkdir()
    storage = tmp_path / "storage"
    storage.mkdir()
    other = tmp_path / "other-external"
    other.mkdir()
    (storage / "state").symlink_to(other, target_is_directory=True)

    with pytest.raises(subject.MetadataRecoveryStateError, match="recovery-state-path-invalid"):
        subject.save_metadata_recovery_state(storage, _pending_record(), repo_root=repo_root)

    assert not (other / "sat-metadata-recoveries.json").exists()


def test_save_rejects_state_file_symlinked_to_other_external_root(tmp_path) -> None:
    repo_root = tmp_path / "checkout"
    repo_root.mkdir()
    storage = tmp_path / "storage"
    state = storage / "state"
    state.mkdir(parents=True)
    other = tmp_path / "other-external"
    other.mkdir()
    target = other / "private.json"
    target.write_text("synthetic sentinel", encoding="utf-8")
    (state / "sat-metadata-recoveries.json").symlink_to(target)

    with pytest.raises(subject.MetadataRecoveryStateError, match="recovery-state-path-invalid"):
        subject.save_metadata_recovery_state(storage, _pending_record(), repo_root=repo_root)

    assert target.read_text(encoding="utf-8") == "synthetic sentinel"


def test_save_lock_is_exclusive_for_the_entire_transaction(tmp_path, monkeypatch) -> None:
    first, second_id = _pending_record(), "synthetic-request-beta"
    second = replace(
        first,
        recovery=lifecycle.start_metadata_recovery(
            subject.recovery_ref("profile-beta", CRITERIA_HASH, second_id), created_at=START,
        ),
        id_solicitud=second_id,
        profile_id="profile-beta",
    )
    original_write = subject._write_state
    entered, release = Event(), Event()

    def blocked_write(path, records):
        entered.set()
        release.wait()
        original_write(path, records)

    monkeypatch.setattr(subject, "_write_state", blocked_write)
    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(subject.save_metadata_recovery_state, tmp_path, first)
        entered.wait()
        try:
            assert _lock_path(tmp_path).exists()
            with pytest.raises(subject.MetadataRecoveryStateError, match="recovery-state-busy"):
                subject.save_metadata_recovery_state(tmp_path, second)
        finally:
            release.set()
        future.result()

    assert subject.list_metadata_recovery_states(tmp_path) == (first,)
    assert _lock_path(tmp_path).exists()


@pytest.mark.skipif(os.name != "nt", reason="Windows byte-range lock regression")
def test_windows_empty_lock_contention_is_reported_busy(tmp_path) -> None:
    lock = _lock_path(tmp_path)
    lock.parent.mkdir(parents=True)
    lock.touch()
    context = multiprocessing.get_context("spawn")
    ready, release = context.Event(), context.Event()
    process = context.Process(
        target=_hold_empty_lock_in_process,
        args=(str(lock), ready, release),
    )
    process.start()
    try:
        assert ready.wait(timeout=5)
        with pytest.raises(subject.MetadataRecoveryStateError, match="recovery-state-busy"):
            subject.save_metadata_recovery_state(tmp_path, _pending_record())
    finally:
        release.set()
        process.join(timeout=5)
        if process.is_alive():
            process.terminate()
            process.join(timeout=5)

    assert process.exitcode == 0


def test_empty_lock_initialization_io_failure_is_lock_failed(tmp_path, monkeypatch) -> None:
    lock = _lock_path(tmp_path)
    lock.parent.mkdir(parents=True)
    lock.touch()
    monkeypatch.setattr(subject.os, "write", Mock(side_effect=PermissionError("synthetic denial")))

    with pytest.raises(subject.MetadataRecoveryStateError, match="recovery-state-lock-failed"):
        subject.save_metadata_recovery_state(tmp_path, _pending_record())


def test_sequential_save_reuses_and_retains_stable_lock_file(tmp_path) -> None:
    lock = _lock_path(tmp_path)
    lock.parent.mkdir(parents=True)
    lock.touch()

    subject.save_metadata_recovery_state(tmp_path, _pending_record())
    subject.save_metadata_recovery_state(tmp_path, _pending_record())

    assert lock.exists() and lock.stat().st_size >= 1
    assert subject.list_metadata_recovery_states(tmp_path) == (_pending_record(),)


def test_save_releases_ownership_but_retains_lock_after_exception(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(subject, "_write_state", Mock(side_effect=RuntimeError("synthetic write interruption")))
    with pytest.raises(RuntimeError, match="synthetic write interruption"):
        subject.save_metadata_recovery_state(tmp_path, _pending_record())

    assert _lock_path(tmp_path).exists()


def test_save_rejects_lock_file_symlinked_to_other_external_root(tmp_path) -> None:
    repo_root = tmp_path / "checkout"
    repo_root.mkdir()
    storage = tmp_path / "storage"
    lock = _lock_path(storage, repo_root=repo_root)
    lock.parent.mkdir(parents=True)
    other = tmp_path / "other-external"
    other.mkdir()
    target = other / "foreign.lock"
    target.write_bytes(b"x")
    lock.symlink_to(target)

    with pytest.raises(subject.MetadataRecoveryStateError, match="recovery-state-path-invalid"):
        subject.save_metadata_recovery_state(storage, _pending_record(), repo_root=repo_root)

    assert target.read_bytes() == b"x"


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


@pytest.mark.parametrize("terminal", ("uncertain", "failed"))
def test_loader_rejects_multiple_terminal_package_failures(tmp_path, terminal: str) -> None:
    ready = _ready_record()
    recovery = lifecycle.begin_package_download(ready.recovery, ready.recovery.packages[0].package_ref)
    kwargs = {"uncertain": True} if terminal == "uncertain" else {"zip_valid": False}
    recovery = lifecycle.record_package_download(recovery, recovery.packages[0].package_ref, **kwargs)
    document = _state_document(replace(ready, recovery=recovery))
    packages = document["recoveries"][0]["recovery"]["packages"]
    packages[1]["status"] = terminal
    if terminal == "failed":
        packages[1]["zipValid"] = False
    _write_document(tmp_path, document)

    with pytest.raises(subject.MetadataRecoveryStateError, match="recovery-state-invalid"):
        subject.list_metadata_recovery_states(tmp_path)


@pytest.mark.parametrize("failure", ("parse", "io"))
def test_loader_errors_retain_no_private_document_or_path(tmp_path, monkeypatch, failure: str) -> None:
    path = subject.metadata_recovery_state_path(tmp_path)
    path.parent.mkdir(parents=True)
    private = f"{REQUEST_ID}:{tmp_path.resolve()}"
    path.write_text(f'{{"private":"{private}"', encoding="utf-8")
    if failure == "io":
        monkeypatch.setattr(Path, "read_text", lambda *args, **kwargs: (_ for _ in ()).throw(OSError(private)))

    with pytest.raises(subject.MetadataRecoveryStateError) as captured:
        subject.list_metadata_recovery_states(tmp_path)

    assert str(captured.value) == "recovery-state-unreadable"
    assert captured.value.__cause__ is captured.value.__context__ is None
    assert private not in repr(captured.value)


def test_private_dataclass_repr_is_redacted() -> None:
    record = _completed_first_record()
    serialized = repr((record, *record.package_bindings, *record.artifact_bindings))
    artifact = record.artifact_bindings[0]
    for private in (
        record.id_solicitud,
        record.profile_id,
        record.criteria_hash,
        record.authorization_ref,
        artifact.package_sha256,
        artifact.package_storage_key,
        artifact.texts[0].sha256,
        artifact.texts[0].storage_key,
        *PACKAGE_IDS,
    ):
        assert private not in serialized


@pytest.mark.parametrize(
    "document",
    (
        '{"schemaVersion":2,"schemaVersion":2,"recoveries":[]}',
        '{"schemaVersion":2,"recoveries":[{"recovery":{},"recovery":{}}]}',
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


def _completed_first_record() -> subject.MetadataRecoveryStateRecord:
    ready = _ready_record()
    package_ref_value = ready.recovery.packages[0].package_ref
    recovery = lifecycle.begin_package_download(ready.recovery, package_ref_value)
    recovery = lifecycle.record_package_download(
        recovery,
        package_ref_value,
        zip_valid=True,
        txt_count=1,
    )
    return replace(ready, recovery=recovery, artifact_bindings=(_artifact(ready, 0),))


def _completed_record() -> subject.MetadataRecoveryStateRecord:
    first = _completed_first_record()
    second_ref = first.recovery.packages[1].package_ref
    downloading = lifecycle.begin_package_download(first.recovery, second_ref)
    recovery = lifecycle.record_package_download(
        downloading,
        second_ref,
        zip_valid=True,
        txt_count=1,
    )
    return replace(
        first,
        recovery=recovery,
        artifact_bindings=first.artifact_bindings + (_artifact(first, 1),),
    )


def _artifact(
    record: subject.MetadataRecoveryStateRecord,
    package_index: int,
) -> MetadataPackageArtifactState:
    ordinal = package_index + 1
    package_digest = ("b" if package_index == 0 else "d") * 64
    text_digest = ("c" if package_index == 0 else "e") * 64
    return MetadataPackageArtifactState(
        package_ref=record.package_bindings[package_index].package_ref,
        package_sha256=package_digest,
        package_storage_key=(
            f"sat-metadata/{record.recovery.recovery_ref}/packages/"
            f"{ordinal}-{package_digest[:12]}.zip"
        ),
        package_written=True,
        texts=(
            MetadataTextArtifact(
                sha256=text_digest,
                storage_key=(
                    f"sat-metadata/{record.recovery.recovery_ref}/txt/"
                    f"{ordinal}-{text_digest[:12]}.txt"
                ),
                written=True,
                inspection=MetadataTextInspection(
                    "utf-8-sig",
                    "~",
                    ("Uuid", "FechaEmision"),
                    2,
                    True,
                ),
            ),
        ),
    )


def _state_document(record: subject.MetadataRecoveryStateRecord) -> dict[str, object]:
    return {"schemaVersion": 2, "recoveries": [record.to_private_document()]}


def _write_document(tmp_path: Path, document: dict[str, object]) -> None:
    path = subject.metadata_recovery_state_path(tmp_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(document), encoding="utf-8")


def _lock_path(storage_root: Path, *, repo_root: Path | None = None) -> Path:
    path = subject.metadata_recovery_state_path(storage_root, repo_root=repo_root)
    return path.with_name(f".{path.name}.lock")


def _hold_empty_lock_in_process(lock_path: str, ready, release) -> None:
    descriptor = os.open(lock_path, os.O_RDWR)
    try:
        subject._acquire_advisory_lock(descriptor)
        ready.set()
        if not release.wait(timeout=10):
            raise RuntimeError("synthetic lock-holder timeout")
        subject._release_advisory_lock(descriptor)
    finally:
        os.close(descriptor)
