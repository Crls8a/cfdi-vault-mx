import json
from dataclasses import replace
from datetime import datetime, timezone

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
