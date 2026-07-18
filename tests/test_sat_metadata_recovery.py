from datetime import datetime, timedelta, timezone

import pytest

import cfdi_vault.sat_metadata_recovery as subject

START = datetime(2026, 6, 30, tzinfo=timezone.utc)
RUN_REF = "run-0123456789ab"
PACKAGE_A = "pkg-0123456789ab"
PACKAGE_B = "pkg-abcdef012345"


def test_verification_schedule_uses_exact_delays_then_repeats_eight_hours() -> None:
    recovery = _start()
    assert recovery.next_check_at == START + timedelta(minutes=5)
    delays = (15 * 60, 30 * 60, 60 * 60, 2 * 60 * 60, 4 * 60 * 60, 8 * 60 * 60, 8 * 60 * 60)
    for seconds in delays:
        checked_at = recovery.next_check_at
        assert checked_at is not None
        recovery = subject.record_pending_verification(recovery, checked_at=checked_at)
        assert recovery.next_check_at == checked_at + timedelta(seconds=seconds)
    assert recovery.verify_attempts == 7


def test_sat_next_check_never_shortens_local_schedule() -> None:
    recovery = _start()
    checked_at = recovery.next_check_at
    assert checked_at is not None
    sat_due = checked_at + timedelta(hours=3)
    recovery = subject.record_pending_verification(recovery, checked_at=checked_at, sat_next_check_at=sat_due)
    assert recovery.next_check_at == sat_due
    recovery = subject.record_pending_verification(
        recovery,
        checked_at=sat_due,
        sat_next_check_at=sat_due + timedelta(minutes=1),
    )
    assert recovery.next_check_at == sat_due + timedelta(minutes=30)


def test_new_48_hour_window_closes_pending_without_replacement() -> None:
    recovery = subject.apply_recovery_deadline(_start(), now=START + timedelta(days=2))
    assert recovery.status is subject.RecoveryStatus.SERVICE_WINDOW_EXCEEDED
    assert recovery.next_check_at is None
    document = recovery.to_redacted_document()
    assert document["serviceWindowExpiresAt"] == "2026-07-02T00:00:00Z"
    assert "replacementRequest" not in document
    assert "retryRequest" not in document
    with pytest.raises(subject.MetadataRecoveryError, match="recovery-terminal"):
        subject.record_pending_verification(recovery, checked_at=START + timedelta(days=2))


def test_legacy_deadline_remains_pending_after_budget() -> None:
    legacy = subject.MetadataRecovery(
        RUN_REF, START, START + timedelta(days=7),
        subject.RecoveryStatus.VERIFY_SCHEDULED, 0,
        START + timedelta(minutes=5), None,
    )

    expired = subject.apply_recovery_deadline(legacy, now=START + timedelta(days=7))

    assert expired.status is subject.RecoveryStatus.PENDING_AFTER_BUDGET
    assert expired.to_redacted_document()["serviceWindowExpiresAt"] == ""


def test_verification_failure_requires_due_check_and_is_terminal() -> None:
    recovery = _start()
    due = recovery.next_check_at
    assert due is not None

    with pytest.raises(subject.MetadataRecoveryError, match="verification-not-due"):
        subject.record_verification_failure(recovery, checked_at=due - timedelta(seconds=1))

    failed = subject.record_verification_failure(recovery, checked_at=due)
    assert failed.status is subject.RecoveryStatus.VERIFY_FAILED
    assert failed.verify_attempts == 1
    assert failed.next_check_at is None
    assert failed.record_count is None
    assert failed.packages == ()
    with pytest.raises(subject.MetadataRecoveryError, match="recovery-terminal"):
        subject.record_verification_failure(failed, checked_at=due)


@pytest.mark.parametrize("elapsed", (timedelta(days=2), timedelta(days=3)))
def test_deadline_wins_over_verification_failure(elapsed: timedelta) -> None:
    recovery = subject.record_verification_failure(_start(), checked_at=START + elapsed)

    assert recovery.status is subject.RecoveryStatus.SERVICE_WINDOW_EXCEEDED
    assert recovery.verify_attempts == 0
    assert recovery.next_check_at is None


@pytest.mark.parametrize("record_count", (None, 0))
def test_finished_without_packages_or_records_is_no_data(record_count: int | None) -> None:
    recovery = subject.record_finished_verification(
        _start(),
        checked_at=START + timedelta(minutes=5),
        package_refs=(),
        record_count=record_count,
    )
    assert recovery.status is subject.RecoveryStatus.NO_DATA
    assert recovery.record_count is record_count
    assert recovery.packages == ()


def test_not_reported_record_count_remains_unknown_with_packages() -> None:
    recovery = subject.record_finished_verification(
        _start(),
        checked_at=START + timedelta(minutes=5),
        package_refs=(PACKAGE_A,),
        record_count=None,
    )

    assert recovery.status is subject.RecoveryStatus.PACKAGES_READY
    assert recovery.record_count is None
    assert recovery.to_redacted_document()["recordCount"] == "not_reported"


@pytest.mark.parametrize("record_count", (True, -1, "not_reported"))
def test_finished_rejects_invalid_record_counts(record_count: object) -> None:
    with pytest.raises(subject.MetadataRecoveryError, match="record-count-invalid"):
        subject.record_finished_verification(
            _start(),
            checked_at=START + timedelta(minutes=5),
            package_refs=(PACKAGE_A,),
            record_count=record_count,  # type: ignore[arg-type]
        )


def test_positive_record_count_without_packages_is_rejected() -> None:
    with pytest.raises(subject.MetadataRecoveryError, match="finished-packages-required"):
        subject.record_finished_verification(
            _start(),
            checked_at=START + timedelta(minutes=5),
            package_refs=(),
            record_count=1,
        )


def test_packages_are_independent_once_only_and_complete_with_txt() -> None:
    recovery = subject.begin_package_download(_ready(), PACKAGE_A)
    recovery = subject.record_package_download(recovery, PACKAGE_A, zip_valid=True, txt_count=1)
    assert recovery.status is subject.RecoveryStatus.DOWNLOADING
    assert recovery.packages[0].status is subject.PackageRecoveryStatus.COMPLETED
    assert recovery.packages[1].status is subject.PackageRecoveryStatus.PENDING
    with pytest.raises(subject.MetadataRecoveryError, match="package-download-already-attempted"):
        subject.begin_package_download(recovery, PACKAGE_A)
    recovery = subject.begin_package_download(recovery, PACKAGE_B)
    recovery = subject.record_package_download(recovery, PACKAGE_B, zip_valid=True, txt_count=2)
    assert recovery.status is subject.RecoveryStatus.COMPLETED
    assert recovery.txt_count == 3


def test_ambiguous_download_is_terminal_and_never_retried() -> None:
    recovery = subject.begin_package_download(_ready(), PACKAGE_A)
    recovery = subject.record_package_download(recovery, PACKAGE_A, uncertain=True)
    assert recovery.status is subject.RecoveryStatus.DOWNLOAD_UNCERTAIN
    assert recovery.packages[0].status is subject.PackageRecoveryStatus.UNCERTAIN
    assert recovery.packages[1].status is subject.PackageRecoveryStatus.PENDING
    with pytest.raises(subject.MetadataRecoveryError, match="recovery-terminal"):
        subject.begin_package_download(recovery, PACKAGE_B)


def test_invalid_zip_is_terminal_but_valid_zip_without_txt_waits_for_processing() -> None:
    recovery = subject.record_finished_verification(
        _start(),
        checked_at=START + timedelta(minutes=5),
        package_refs=(PACKAGE_A,),
        record_count=1,
    )
    recovery = subject.begin_package_download(recovery, PACKAGE_A)
    recovery = subject.record_package_download(recovery, PACKAGE_A, zip_valid=False, txt_count=0)
    assert recovery.status is subject.RecoveryStatus.DOWNLOAD_FAILED

    recovery = subject.begin_package_download(_ready(), PACKAGE_A)
    pending = subject.record_package_download(recovery, PACKAGE_A, zip_valid=True, txt_count=0)
    assert pending.status is subject.RecoveryStatus.ZIP_DOWNLOADED_PENDING_PROCESSING
    assert pending.packages[0].status is subject.PackageRecoveryStatus.ZIP_DOWNLOADED_PENDING_PROCESSING
    assert pending.packages[0].zip_valid is True
    with pytest.raises(subject.MetadataRecoveryError, match="recovery-terminal"):
        subject.begin_package_download(pending, PACKAGE_B)


def test_redacted_document_has_only_safe_references_and_aggregates() -> None:
    document = _ready().to_redacted_document()
    assert document["recoveryRef"] == RUN_REF
    assert document["status"] == "packages_ready"
    assert document["deadlineAt"] == "2026-07-02T00:00:00Z"
    assert document["packageCount"] == 2
    assert document["packages"] == [
        {"packageRef": PACKAGE_A, "status": "pending", "zipValid": None, "txtCount": 0},
        {"packageRef": PACKAGE_B, "status": "pending", "zipValid": None, "txtCount": 0},
    ]
    serialized = repr(document).lower()
    for forbidden in ("rfc", "idsolicitud", "idpaquete", "path", "row", "raw"):
        assert forbidden not in serialized


def test_initial_and_pending_redaction_never_invent_zero_records() -> None:
    initial = _start()
    checked_at = initial.next_check_at
    assert checked_at is not None
    pending = subject.record_pending_verification(initial, checked_at=checked_at)

    assert initial.to_redacted_document()["recordCount"] == "not_reported"
    assert pending.to_redacted_document()["recordCount"] == "not_reported"


def test_raw_or_duplicate_references_are_rejected() -> None:
    with pytest.raises(subject.MetadataRecoveryError, match="recovery-ref-invalid"):
        subject.start_metadata_recovery("real-request-id", created_at=START)
    with pytest.raises(subject.MetadataRecoveryError, match="package-ref-invalid"):
        subject.record_finished_verification(
            _start(),
            checked_at=START + timedelta(minutes=5),
            package_refs=(PACKAGE_A, PACKAGE_A),
            record_count=2,
        )


def _start() -> subject.MetadataRecovery:
    return subject.start_metadata_recovery(RUN_REF, created_at=START)


def _ready() -> subject.MetadataRecovery:
    return subject.record_finished_verification(
        _start(),
        checked_at=START + timedelta(minutes=5),
        package_refs=(PACKAGE_A, PACKAGE_B),
        record_count=3,
    )
