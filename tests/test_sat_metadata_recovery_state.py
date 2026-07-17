import json
import multiprocessing
import os
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from enum import Enum
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
from cfdi_vault.sat_metadata_zip_state import MetadataZipReceipt

START = datetime(2026, 6, 30, tzinfo=timezone.utc)
CRITERIA_HASH = "a" * 64
REQUEST_ID = "synthetic-request-alpha"
PACKAGE_IDS = ("synthetic-package-alpha", "synthetic-package-beta")


def test_campaign_recovery_ref_is_deterministic_opaque_and_valid_state_identity() -> None:
    first = subject.campaign_metadata_recovery_ref("profile-private", CRITERIA_HASH)
    second = subject.campaign_metadata_recovery_ref("profile-private", CRITERIA_HASH)

    assert first == second
    assert first.startswith("run-") and len(first) == 16
    assert "profile-private" not in first and CRITERIA_HASH not in first
    legacy = _pending_record()
    campaign = replace(
        legacy,
        recovery=replace(legacy.recovery, recovery_ref=first),
        profile_id="profile-private",
    )
    assert campaign.recovery.recovery_ref == first


@pytest.mark.parametrize(
    ("profile", "criteria"),
    (("", CRITERIA_HASH), (" profile", CRITERIA_HASH), ("profile-private", "A" * 64)),
)
def test_campaign_recovery_ref_rejects_invalid_identity(profile: str, criteria: str) -> None:
    with pytest.raises(subject.MetadataRecoveryStateError, match="campaign-recovery-ref-invalid"):
        subject.campaign_metadata_recovery_ref(profile, criteria)


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


def test_raw_zip_receipt_round_trips_for_pending_processing_and_is_redacted(tmp_path) -> None:
    ready = _ready_record()
    package = ready.recovery.packages[0].package_ref
    recovery = lifecycle.record_package_download(
        lifecycle.begin_package_download(ready.recovery, package), package,
        zip_valid=True, txt_count=0,
    )
    receipt = MetadataZipReceipt(
        recovery.recovery_ref, package, "cmp-0123456789ab", "work-abcdef012345",
        "b" * 64, 123, True,
        "sat-metadata/cmp-0123456789ab/work-abcdef012345/packages/1-bbbbbbbbbbbb.zip",
    )
    record = replace(ready, recovery=recovery, zip_receipts=(receipt,))

    subject.save_metadata_recovery_state(tmp_path, ready)
    subject.save_metadata_recovery_state(
        tmp_path, replace(ready, recovery=lifecycle.begin_package_download(ready.recovery, package)),
    )
    subject.save_metadata_recovery_state(tmp_path, record)
    assert subject.load_metadata_recovery_state(tmp_path, record.recovery.recovery_ref) == record
    redacted = record.to_redacted_document()
    serialized = repr(redacted)
    assert redacted["zipReceipts"] == [{"zipValid": True, "byteCount": 123}]
    for private in (receipt.campaign_ref, receipt.work_ref, receipt.sha256, receipt.storage_key):
        assert private not in serialized


def test_raw_zip_receipt_changes_and_duplicates_are_rejected(tmp_path) -> None:
    ready = _ready_record()
    package = ready.recovery.packages[0].package_ref
    recovery = lifecycle.record_package_download(
        lifecycle.begin_package_download(ready.recovery, package), package,
        zip_valid=True, txt_count=0,
    )
    receipt = MetadataZipReceipt(
        recovery.recovery_ref, package, "cmp-0123456789ab", "work-abcdef012345",
        "b" * 64, 123, True,
        "sat-metadata/cmp-0123456789ab/work-abcdef012345/packages/1-bbbbbbbbbbbb.zip",
    )
    record = replace(ready, recovery=recovery, zip_receipts=(receipt,))
    subject.save_metadata_recovery_state(tmp_path, record)
    subject.save_metadata_recovery_state(tmp_path, record)
    conflict = replace(record, zip_receipts=(replace(receipt, byte_count=124),))
    with pytest.raises(subject.MetadataRecoveryStateError, match="zip-receipt-immutable"):
        subject.save_metadata_recovery_state(tmp_path, conflict)
    with pytest.raises(subject.MetadataRecoveryStateError, match="zip-receipt-duplicate"):
        replace(record, zip_receipts=(receipt, receipt))


def test_zero_txt_is_rejected_outside_pending_processing() -> None:
    ready = _ready_record()
    package = ready.recovery.packages[0].package_ref
    pending = lifecycle.record_package_download(
        lifecycle.begin_package_download(ready.recovery, package), package,
        zip_valid=True, txt_count=0,
    )
    forged = replace(pending, status=lifecycle.RecoveryStatus.COMPLETED)
    with pytest.raises(subject.MetadataRecoveryStateError, match="recovery-state-invalid"):
        replace(ready, recovery=forged)


@pytest.mark.parametrize("status", ("download_failed", None, 1))
def test_recovery_state_rejects_non_exact_status_types(status: object) -> None:
    ready = _ready_record()
    forged = replace(ready.recovery, status=status)  # type: ignore[arg-type]
    with pytest.raises(subject.MetadataRecoveryStateError, match="recovery-state-invalid"):
        replace(ready, recovery=forged)


@pytest.mark.parametrize(
    ("aggregate", "other_status", "other_zip"),
    (
        (lifecycle.RecoveryStatus.DOWNLOAD_FAILED, lifecycle.PackageRecoveryStatus.FAILED, False),
        (lifecycle.RecoveryStatus.DOWNLOAD_UNCERTAIN, lifecycle.PackageRecoveryStatus.UNCERTAIN, None),
    ),
)
def test_zip_pending_package_cannot_be_mixed_into_terminal_failure(
    aggregate: lifecycle.RecoveryStatus,
    other_status: lifecycle.PackageRecoveryStatus,
    other_zip: bool | None,
) -> None:
    ready = _ready_record()
    first, second = ready.recovery.packages
    pending = lifecycle.record_package_download(
        lifecycle.begin_package_download(ready.recovery, first.package_ref), first.package_ref,
        zip_valid=True, txt_count=0,
    )
    forged_packages = (
        pending.packages[0],
        replace(pending.packages[1], status=other_status, zip_valid=other_zip),
    )
    with pytest.raises(subject.MetadataRecoveryStateError, match="recovery-state-invalid"):
        replace(
            ready,
            recovery=replace(pending, status=aggregate, packages=forged_packages),
            zip_receipts=(_zip_receipt(ready, first.package_ref),),
        )


def test_observation_provenance_v4_round_trips_privately_only(tmp_path) -> None:
    record = replace(_pending_record(), observation_provenance=_provenance())

    subject.save_metadata_recovery_state(tmp_path, record)

    assert subject.load_metadata_recovery_state(tmp_path, record.recovery.recovery_ref) == record
    private = json.loads(subject.metadata_recovery_state_path(tmp_path).read_text(encoding="utf-8"))
    assert private["schemaVersion"] == 6
    assert private["recoveries"][0]["observationProvenance"] == {
        "projectionVersion": 1,
        "testedCommit": "f" * 40,
        "observedAt": "2026-06-30T00:00:00Z",
        "entryPoint": "metadata-recover-live",
        "verifyContactsNotBeforeDue": 0,
        "verifyContactsBeforeDue": 0,
        "verifyContactsDueUnknown": 0,
    }
    redacted = record.to_redacted_document()
    assert "observationProvenance" not in redacted
    assert "testedCommit" not in repr(redacted)
    assert "f" * 40 not in repr(redacted)


@pytest.mark.parametrize("schema_version", (3, 4))
def test_legacy_state_reads_without_claim_and_rewrites_v6(tmp_path, schema_version: int) -> None:
    record = _pending_record()
    if schema_version == 4:
        record = replace(record, observation_provenance=_provenance())
    document = _state_document(record)
    document["schemaVersion"] = schema_version
    del document["recoveries"][0]["verifyClaim"]
    del document["recoveries"][0]["lastVerifyErrorKind"]
    if schema_version == 3:
        del document["recoveries"][0]["observationProvenance"]
    _write_document(tmp_path, document)

    loaded = subject.load_metadata_recovery_state(tmp_path, record.recovery.recovery_ref)

    assert loaded.verify_claim is None
    assert (loaded.observation_provenance is None) is (schema_version == 3)
    subject.save_metadata_recovery_state(tmp_path, loaded)
    rewritten = json.loads(subject.metadata_recovery_state_path(tmp_path).read_text(encoding="utf-8"))
    assert rewritten["schemaVersion"] == 6
    assert rewritten["recoveries"][0]["verifyClaim"] is None
    assert rewritten["recoveries"][0]["lastVerifyErrorKind"] is None
    if schema_version == 3:
        with pytest.raises(subject.MetadataRecoveryStateError, match="observation-provenance-required"):
            subject.require_metadata_observation_provenance(loaded)


@pytest.mark.parametrize("kind", tuple(subject.MetadataVerifyErrorKind))
def test_verify_error_kind_v6_round_trips_privately(
    tmp_path, kind: subject.MetadataVerifyErrorKind,
) -> None:
    record = _persist_verify_error_resolution(tmp_path, kind)

    loaded = subject.load_metadata_recovery_state(tmp_path, record.recovery.recovery_ref)
    private = json.loads(subject.metadata_recovery_state_path(tmp_path).read_text(encoding="utf-8"))
    assert loaded.last_verify_error_kind is kind
    assert private["schemaVersion"] == 6
    assert private["recoveries"][0]["lastVerifyErrorKind"] == kind.value


def test_verify_error_kind_is_safe_in_redacted_projection(tmp_path) -> None:
    record = _persist_verify_error_resolution(
        tmp_path,
        subject.MetadataVerifyErrorKind.SAT_TOO_MANY_RESULTS,
    )

    redacted = record.to_redacted_document()

    assert redacted["lastVerifyErrorKind"] == "sat_too_many_results"
    serialized = repr(redacted)
    assert REQUEST_ID not in serialized
    assert record.profile_id not in serialized
    assert record.authorization_ref not in serialized


def test_schema_v5_decodes_without_error_kind_and_upgrades_on_save(tmp_path) -> None:
    record = _claimed_record(
        replace(_pending_record(), observation_provenance=_provenance()),
    )
    document = _state_document(record)
    document["schemaVersion"] = 5
    del document["recoveries"][0]["lastVerifyErrorKind"]
    _write_document(tmp_path, document)

    loaded = subject.load_metadata_recovery_state(tmp_path, record.recovery.recovery_ref)

    assert loaded.verify_claim == record.verify_claim
    assert loaded.last_verify_error_kind is None
    subject.save_metadata_recovery_state(tmp_path, loaded)
    rewritten = json.loads(subject.metadata_recovery_state_path(tmp_path).read_text(encoding="utf-8"))
    assert rewritten["schemaVersion"] == 6
    assert rewritten["recoveries"][0]["lastVerifyErrorKind"] is None


def test_verify_error_kind_rejects_string_and_enum_impostor() -> None:
    class Impostor(str, Enum):
        VERIFY_FAILED = "verify_failed"

    for value in ("verify_failed", Impostor.VERIFY_FAILED):
        with pytest.raises(subject.MetadataRecoveryStateError, match="verify-error-kind-invalid"):
            replace(_failed_record(), last_verify_error_kind=value)


@pytest.mark.parametrize("value", ("verification_failed", True))
def test_verify_error_kind_loader_rejects_unknown_or_non_string_value(
    tmp_path, value: object,
) -> None:
    record = _failed_record()
    document = _state_document(record)
    document["recoveries"][0]["lastVerifyErrorKind"] = value
    _write_document(tmp_path, document)

    with pytest.raises(subject.MetadataRecoveryStateError, match="verify-error-kind-invalid"):
        subject.list_metadata_recovery_states(tmp_path)


def test_verify_error_kind_rejects_value_before_completed_attempt() -> None:
    pending = _pending_record()
    claimed = _claimed_record(replace(pending, observation_provenance=_provenance()))

    for record in (pending, claimed):
        with pytest.raises(subject.MetadataRecoveryStateError, match="verify-error-kind-invalid"):
            replace(
                record,
                last_verify_error_kind=subject.MetadataVerifyErrorKind.VERIFY_RETRYABLE,
            )


def test_verify_error_kind_rejects_first_insert_without_persisted_claim(tmp_path) -> None:
    forged = _failed_record(
        last_verify_error_kind=subject.MetadataVerifyErrorKind.VERIFY_FAILED,
    )

    with pytest.raises(
        subject.MetadataRecoveryStateError,
        match="verify-error-kind-transition-invalid",
    ):
        subject.save_metadata_recovery_state(tmp_path, forged)

    assert subject.list_metadata_recovery_states(tmp_path) == ()


def test_verify_error_kind_cannot_mutate_without_exact_claim_resolution(tmp_path) -> None:
    current = _persist_verify_error_resolution(
        tmp_path,
        subject.MetadataVerifyErrorKind.VERIFY_FAILED,
    )

    for value in (None, subject.MetadataVerifyErrorKind.VERIFY_UNCERTAIN):
        with pytest.raises(
            subject.MetadataRecoveryStateError,
            match="verify-error-kind-transition-invalid",
        ):
            subject.save_metadata_recovery_state(
                tmp_path,
                replace(current, last_verify_error_kind=value),
            )


def test_verify_claim_creation_preserves_prior_error_kind(tmp_path) -> None:
    current = _persist_verify_error_resolution(
        tmp_path,
        subject.MetadataVerifyErrorKind.VERIFY_RETRYABLE,
        pending=True,
    )
    claimed = _claimed_record(current)

    with pytest.raises(
        subject.MetadataRecoveryStateError,
        match="verify-error-kind-transition-invalid",
    ):
        subject.save_metadata_recovery_state(
            tmp_path,
            replace(
                claimed,
                last_verify_error_kind=subject.MetadataVerifyErrorKind.VERIFY_FAILED,
            ),
        )
    subject.save_metadata_recovery_state(tmp_path, claimed)

    loaded = subject.load_metadata_recovery_state(tmp_path, current.recovery.recovery_ref)
    assert loaded.last_verify_error_kind is subject.MetadataVerifyErrorKind.VERIFY_RETRYABLE


def test_exact_claim_resolution_sets_error_kind_and_clears_it_on_success(tmp_path) -> None:
    initial = replace(_pending_record(), observation_provenance=_provenance())
    claimed = _claimed_record(initial)
    due = claimed.verify_claim.due_at
    failed = replace(
        claimed,
        recovery=lifecycle.record_verification_failure(initial.recovery, checked_at=due),
        verify_claim=None,
        last_verify_error_kind=subject.MetadataVerifyErrorKind.VERIFY_FAILED,
    )
    subject.save_metadata_recovery_state(tmp_path, initial)
    subject.save_metadata_recovery_state(tmp_path, claimed)
    subject.save_metadata_recovery_state(tmp_path, failed)
    assert subject.load_metadata_recovery_state(
        tmp_path, initial.recovery.recovery_ref,
    ).last_verify_error_kind is subject.MetadataVerifyErrorKind.VERIFY_FAILED

    second_root = tmp_path / "second"
    retry = _persist_verify_error_resolution(
        second_root,
        subject.MetadataVerifyErrorKind.VERIFY_RETRYABLE,
        pending=True,
    )
    retry_claimed = _claimed_record(retry)
    retry_due = retry_claimed.verify_claim.due_at
    successful = replace(
        retry_claimed,
        recovery=lifecycle.record_finished_verification(
            retry.recovery,
            checked_at=retry_due,
            package_refs=(),
            record_count=0,
        ),
        observation_provenance=replace(
            retry_claimed.observation_provenance,
            verify_contacts_not_before_due=1,
        ),
        verify_claim=None,
        last_verify_error_kind=None,
    )
    subject.save_metadata_recovery_state(second_root, retry_claimed)
    subject.save_metadata_recovery_state(second_root, successful)
    assert subject.load_metadata_recovery_state(
        second_root, retry.recovery.recovery_ref,
    ).last_verify_error_kind is None


def test_verify_claim_requires_exact_attempt_and_contact_bucket_on_success(tmp_path) -> None:
    current = replace(_pending_record(), observation_provenance=_provenance())
    due = current.recovery.next_check_at
    assert due is not None
    claimed = replace(
        current,
        recovery=replace(current.recovery, verify_attempts=1),
        observation_provenance=replace(current.observation_provenance, observed_at=due),
        verify_claim=subject.MetadataVerifyClaim(1, due, due),
    )
    subject.save_metadata_recovery_state(tmp_path, current)
    subject.save_metadata_recovery_state(tmp_path, claimed)
    assert subject.load_metadata_recovery_state(tmp_path, current.recovery.recovery_ref).verify_claim == claimed.verify_claim
    assert claimed.observation_provenance == replace(current.observation_provenance, observed_at=due)
    assert "verifyClaim" not in claimed.to_redacted_document()

    finished = lifecycle.record_finished_verification(
        current.recovery, checked_at=due, package_refs=(), record_count=None,
    )
    without_bucket = replace(claimed, recovery=finished, verify_claim=None)
    with pytest.raises(subject.MetadataRecoveryStateError, match="verify-claim-transition-invalid"):
        subject.save_metadata_recovery_state(tmp_path, without_bucket)
    resolved = replace(
        without_bucket,
        observation_provenance=replace(
            without_bucket.observation_provenance,
            verify_contacts_not_before_due=1,
        ),
    )
    subject.save_metadata_recovery_state(tmp_path, resolved)
    assert subject.load_metadata_recovery_state(tmp_path, current.recovery.recovery_ref) == resolved


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("projection_version", True),
        ("projection_version", 2),
        ("tested_commit", "F" * 40),
        ("tested_commit", "f" * 39),
        ("observed_at", START - timedelta(seconds=1)),
        ("observed_at", START.replace(tzinfo=None)),
        ("entry_point", "metadata-recovery-status"),
        ("entry_point", []),
        ("verify_contacts_not_before_due", True),
        ("verify_contacts_before_due", -1),
        ("verify_contacts_due_unknown", 1),
    ),
)
def test_observation_provenance_rejects_invalid_values(field: str, value: object) -> None:
    provenance = replace(_provenance(), **{field: value})

    with pytest.raises(subject.MetadataRecoveryStateError, match="observation-provenance-invalid"):
        replace(_pending_record(), observation_provenance=provenance)


def test_provenance_is_monotonic_across_verification_transitions(tmp_path) -> None:
    current = replace(_pending_record(), observation_provenance=_provenance())
    due = current.recovery.next_check_at
    assert due is not None
    advanced = replace(
        current,
        recovery=lifecycle.record_pending_verification(current.recovery, checked_at=due),
        observation_provenance=replace(
            current.observation_provenance,
            observed_at=due,
            entry_point="metadata-recovery-runner",
            verify_contacts_not_before_due=1,
        ),
    )
    subject.save_metadata_recovery_state(tmp_path, current)
    subject.save_metadata_recovery_state(tmp_path, advanced)

    with pytest.raises(subject.MetadataRecoveryStateError, match="observation-provenance-regression"):
        subject.save_metadata_recovery_state(
            tmp_path,
            replace(advanced, observation_provenance=_provenance()),
        )
    with pytest.raises(subject.MetadataRecoveryStateError, match="observation-provenance-regression"):
        subject.save_metadata_recovery_state(
            tmp_path,
            replace(
                advanced,
                observation_provenance=replace(
                    advanced.observation_provenance,
                    observed_at=advanced.observation_provenance.observed_at - timedelta(seconds=1),
                ),
            ),
        )
    with pytest.raises(subject.MetadataRecoveryStateError, match="observation-provenance-required"):
        subject.save_metadata_recovery_state(tmp_path, replace(advanced, observation_provenance=None))


def test_provenance_delta_cannot_exceed_verification_attempt_delta(tmp_path) -> None:
    initial = _pending_record()
    first_due = initial.recovery.next_check_at
    assert first_due is not None
    first = replace(
        initial,
        recovery=lifecycle.record_pending_verification(initial.recovery, checked_at=first_due),
        observation_provenance=_provenance(observed_at=first_due),
    )
    second_due = first.recovery.next_check_at
    assert second_due is not None
    second = replace(
        first,
        recovery=lifecycle.record_pending_verification(first.recovery, checked_at=second_due),
        observation_provenance=replace(
            first.observation_provenance,
            observed_at=second_due,
            verify_contacts_not_before_due=1,
            verify_contacts_due_unknown=1,
        ),
    )
    subject.save_metadata_recovery_state(tmp_path, first)

    with pytest.raises(subject.MetadataRecoveryStateError, match="observation-provenance-transition-invalid"):
        subject.save_metadata_recovery_state(tmp_path, second)


def test_nonverify_transitions_preserve_provenance_counters(tmp_path) -> None:
    ready = replace(_ready_record(), observation_provenance=_provenance())
    downloading = replace(
        ready,
        recovery=lifecycle.begin_package_download(
            ready.recovery,
            ready.recovery.packages[0].package_ref,
        ),
    )
    changed = replace(
        downloading,
        observation_provenance=replace(
            downloading.observation_provenance,
            verify_contacts_due_unknown=1,
        ),
    )
    subject.save_metadata_recovery_state(tmp_path, ready)
    subject.save_metadata_recovery_state(tmp_path, downloading)

    assert subject.load_metadata_recovery_state(tmp_path, ready.recovery.recovery_ref) == downloading
    with pytest.raises(subject.MetadataRecoveryStateError, match="observation-provenance-transition-invalid"):
        subject.save_metadata_recovery_state(tmp_path, changed)


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
        json.dumps({"schemaVersion": 2, "recoveries": []}),
        json.dumps({"schemaVersion": 3.0, "recoveries": []}),
        json.dumps({"schemaVersion": 4.0, "recoveries": []}),
        json.dumps({"schemaVersion": 7, "recoveries": []}),
        json.dumps({"schemaVersion": 6, "recoveries": [], "unexpected": True}),
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
    assert private["schemaVersion"] == 6
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


@pytest.mark.parametrize("value", ("unknown", "", True, -1))
def test_loader_rejects_invalid_record_count_representations(tmp_path, value: object) -> None:
    document = _state_document(_pending_record())
    document["recoveries"][0]["recovery"]["recordCount"] = value
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
        '{"schemaVersion":5,"schemaVersion":5,"recoveries":[]}',
        '{"schemaVersion":5,"recoveries":[{"recovery":{},"recovery":{}}]}',
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


def test_record_count_round_trips_not_reported_and_known_integer(tmp_path) -> None:
    initial = _pending_record()
    due = initial.recovery.next_check_at
    assert due is not None
    pending = replace(
        initial,
        recovery=lifecycle.record_pending_verification(initial.recovery, checked_at=due),
    )
    unknown_ready = _finished_record(initial, PACKAGE_IDS, None)
    unknown_no_data = _finished_record(initial, (), None)
    known_ready = _ready_record()

    for record, expected in (
        (initial, "not_reported"),
        (pending, "not_reported"),
        (unknown_ready, "not_reported"),
        (unknown_no_data, "not_reported"),
        (known_ready, 2),
    ):
        document = _state_document(record)
        assert document["recoveries"][0]["recovery"]["recordCount"] == expected
        _write_document(tmp_path, document)
        assert subject.list_metadata_recovery_states(tmp_path) == (record,)


def _finished_record(
    pending: subject.MetadataRecoveryStateRecord,
    package_ids: tuple[str, ...],
    record_count: int | None,
) -> subject.MetadataRecoveryStateRecord:
    recovery = lifecycle.record_finished_verification(
        pending.recovery,
        checked_at=START,
        package_refs=tuple(subject.package_ref(value) for value in package_ids),
        record_count=record_count,
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
        package_ids=package_ids,
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


def _failed_record(
    *,
    last_verify_error_kind: subject.MetadataVerifyErrorKind | None = None,
) -> subject.MetadataRecoveryStateRecord:
    pending = _pending_record()
    due = pending.recovery.next_check_at
    assert due is not None
    return replace(
        pending,
        recovery=lifecycle.record_verification_failure(pending.recovery, checked_at=due),
        last_verify_error_kind=last_verify_error_kind,
    )


def _persist_verify_error_resolution(
    storage_root: Path,
    kind: subject.MetadataVerifyErrorKind,
    *,
    pending: bool = False,
) -> subject.MetadataRecoveryStateRecord:
    initial = replace(_pending_record(), observation_provenance=_provenance())
    claimed = _claimed_record(initial)
    due = claimed.verify_claim.due_at
    recovery = (
        lifecycle.record_pending_verification(initial.recovery, checked_at=due)
        if pending
        else lifecycle.record_verification_failure(initial.recovery, checked_at=due)
    )
    resolved = replace(
        claimed,
        recovery=recovery,
        verify_claim=None,
        last_verify_error_kind=kind,
    )
    subject.save_metadata_recovery_state(storage_root, initial)
    subject.save_metadata_recovery_state(storage_root, claimed)
    subject.save_metadata_recovery_state(storage_root, resolved)
    return resolved


def _claimed_record(
    current: subject.MetadataRecoveryStateRecord,
) -> subject.MetadataRecoveryStateRecord:
    due = current.recovery.next_check_at
    assert due is not None
    return replace(
        current,
        recovery=replace(
            current.recovery,
            verify_attempts=current.recovery.verify_attempts + 1,
        ),
        observation_provenance=replace(current.observation_provenance, observed_at=due),
        verify_claim=subject.MetadataVerifyClaim(
            current.recovery.verify_attempts + 1,
            due,
            due,
        ),
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


def _zip_receipt(record: subject.MetadataRecoveryStateRecord, package_ref: str) -> MetadataZipReceipt:
    return MetadataZipReceipt(
        record.recovery.recovery_ref, package_ref, "cmp-0123456789ab", "work-abcdef012345",
        "b" * 64, 123, True,
        "sat-metadata/cmp-0123456789ab/work-abcdef012345/packages/1-bbbbbbbbbbbb.zip",
    )


def _state_document(record: subject.MetadataRecoveryStateRecord) -> dict[str, object]:
    return {"schemaVersion": 6, "recoveries": [record.to_private_document()]}


def _provenance(
    *, observed_at: datetime = START,
) -> subject.MetadataObservationProvenance:
    return subject.MetadataObservationProvenance(
        projection_version=1,
        tested_commit="f" * 40,
        observed_at=observed_at,
        entry_point="metadata-recover-live",
    )


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
