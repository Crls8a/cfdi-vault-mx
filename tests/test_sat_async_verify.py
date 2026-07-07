from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
import inspect

from cfdi_vault import sat_async_verify
from cfdi_vault.domain import DateTimePeriod, DownloadDirection, DownloadQuery, RequestType, SatRequestState
from cfdi_vault.sat_async_verify import VerifyBackoffPolicy, run_verify_due
from cfdi_vault.sat_contract import SatOutcomeAction, SatVerificationResult
from cfdi_vault.sat_live_request_state import (
    PACKAGE_READY,
    VERIFY_EXPIRED,
    VERIFY_FAILED_PERMANENT,
    VERIFY_FAILED_RETRYABLE,
    VERIFY_IN_PROGRESS_SAT,
    VERIFY_NO_DATA,
    VERIFY_REJECTED,
    list_live_metadata_requests,
    persist_live_metadata_request,
    upsert_live_metadata_request,
)

CREATED_AT = datetime(2026, 7, 6, 0, 0, tzinfo=timezone.utc)
DUE_AT = CREATED_AT + timedelta(minutes=5)
REQUEST_ID = "SYNTHETIC-SCHEDULER-REQUEST-0001"


def test_accepted_verification_schedules_next_check(tmp_path: Path) -> None:
    _persist_due(tmp_path)
    verifier = _Verifier(_verification(SatRequestState.ACCEPTED, SatOutcomeAction.ACCEPTED))

    report = run_verify_due(storage_root=tmp_path, profile_id="default", verifier=verifier, now=DUE_AT)

    record = _only_record(tmp_path)
    assert report.processed_count == 1
    assert verifier.calls == [REQUEST_ID]
    assert record.status == VERIFY_IN_PROGRESS_SAT
    assert record.attempt_count == 1
    assert record.next_check_at == "2026-07-06T00:20:00Z"


def test_in_progress_verification_schedules_next_check(tmp_path: Path) -> None:
    _persist_due(tmp_path)
    verifier = _Verifier(_verification(SatRequestState.IN_PROCESS, SatOutcomeAction.IN_PROGRESS))

    run_verify_due(storage_root=tmp_path, profile_id="default", verifier=verifier, now=DUE_AT)

    record = _only_record(tmp_path)
    assert record.status == VERIFY_IN_PROGRESS_SAT
    assert record.sat_estado_solicitud == "in_process"
    assert record.next_check_at == "2026-07-06T00:20:00Z"


def test_finished_marks_package_ready_without_download(tmp_path: Path) -> None:
    _persist_due(tmp_path)
    verifier = _Verifier(
        _verification(
            SatRequestState.FINISHED,
            SatOutcomeAction.FINISHED,
            package_ids=("SYN-PKG-001", "SYN-PKG-002"),
        )
    )

    run_verify_due(storage_root=tmp_path, profile_id="default", verifier=verifier, now=DUE_AT)

    record = _only_record(tmp_path)
    assert record.status == PACKAGE_READY
    assert record.next_check_at == ""
    assert record.numero_cfdis == 2
    assert len(record.package_refs_redacted) == 2
    assert all(item.startswith("pkg-") for item in record.package_refs_redacted)
    assert verifier.download_calls == []


def test_no_data_is_terminal(tmp_path: Path) -> None:
    _persist_due(tmp_path)
    verifier = _Verifier(
        _verification(
            SatRequestState.ERROR,
            SatOutcomeAction.PERMANENT_FAILURE,
            sat_code="5004",
            message="Synthetic no data",
        )
    )

    run_verify_due(storage_root=tmp_path, profile_id="default", verifier=verifier, now=DUE_AT)

    record = _only_record(tmp_path)
    assert record.status == VERIFY_NO_DATA
    assert record.next_check_at == ""


def test_rejected_is_terminal(tmp_path: Path) -> None:
    _persist_due(tmp_path)
    verifier = _Verifier(_verification(SatRequestState.REJECTED, SatOutcomeAction.PERMANENT_FAILURE))

    run_verify_due(storage_root=tmp_path, profile_id="default", verifier=verifier, now=DUE_AT)

    record = _only_record(tmp_path)
    assert record.status == VERIFY_REJECTED
    assert record.last_error_kind == "rejected"
    assert record.next_check_at == ""


def test_expired_sat_state_is_terminal(tmp_path: Path) -> None:
    _persist_due(tmp_path)
    verifier = _Verifier(_verification(SatRequestState.EXPIRED, SatOutcomeAction.EXPIRED))

    run_verify_due(storage_root=tmp_path, profile_id="default", verifier=verifier, now=DUE_AT)

    record = _only_record(tmp_path)
    assert record.status == VERIFY_EXPIRED
    assert record.next_check_at == ""


def test_transport_timeout_is_retryable_with_backoff(tmp_path: Path) -> None:
    _persist_due(tmp_path)
    verifier = _TimeoutVerifier()

    run_verify_due(storage_root=tmp_path, profile_id="default", verifier=verifier, now=DUE_AT)

    record = _only_record(tmp_path)
    assert record.status == VERIFY_FAILED_RETRYABLE
    assert record.attempt_count == 1
    assert record.last_error_kind == "transport_timeout"
    assert record.next_check_at == "2026-07-06T00:20:00Z"


def test_unauthorized_is_permanent_failure(tmp_path: Path) -> None:
    _persist_due(tmp_path)
    verifier = _Verifier(_verification(SatRequestState.ERROR, SatOutcomeAction.UNAUTHORIZED, sat_code="5001"))

    run_verify_due(storage_root=tmp_path, profile_id="default", verifier=verifier, now=DUE_AT)

    record = _only_record(tmp_path)
    assert record.status == VERIFY_FAILED_PERMANENT
    assert record.last_error_kind == "unauthorized"
    assert record.next_check_at == ""


def test_max_attempts_reached_is_permanent_failure(tmp_path: Path) -> None:
    record = _persist_due(tmp_path)
    upsert_live_metadata_request(storage_root=tmp_path, record=replace(record, attempt_count=11))
    verifier = _Verifier(_verification(SatRequestState.IN_PROCESS, SatOutcomeAction.IN_PROGRESS))

    run_verify_due(storage_root=tmp_path, profile_id="default", verifier=verifier, now=DUE_AT, policy=VerifyBackoffPolicy(max_attempts=12))

    record = _only_record(tmp_path)
    assert record.status == VERIFY_FAILED_PERMANENT
    assert record.attempt_count == 12
    assert record.last_error_kind == "max_attempts_reached"
    assert record.next_check_at == ""


def test_expired_request_is_terminal_without_calling_verifier(tmp_path: Path) -> None:
    record = _persist_due(tmp_path)
    upsert_live_metadata_request(
        storage_root=tmp_path,
        record=replace(record, expires_at="2026-07-06T00:04:00Z"),
    )
    verifier = _Verifier(_verification(SatRequestState.IN_PROCESS, SatOutcomeAction.IN_PROGRESS))

    run_verify_due(storage_root=tmp_path, profile_id="default", verifier=verifier, now=DUE_AT)

    record = _only_record(tmp_path)
    assert verifier.calls == []
    assert record.status == VERIFY_EXPIRED
    assert record.last_error_kind == "expired_request"


def test_dry_run_does_not_verify_or_mutate(tmp_path: Path) -> None:
    _persist_due(tmp_path)
    verifier = _Verifier(_verification(SatRequestState.FINISHED, SatOutcomeAction.FINISHED))

    report = run_verify_due(storage_root=tmp_path, profile_id="default", verifier=verifier, now=DUE_AT, dry_run=True)

    record = _only_record(tmp_path)
    assert report.due_count == 1
    assert report.selected_count == 1
    assert report.processed_count == 0
    assert verifier.calls == []
    assert record.attempt_count == 0


def test_limit_prevents_busy_loop(tmp_path: Path) -> None:
    _persist_due(tmp_path, request_id=REQUEST_ID)
    _persist_due(tmp_path, request_id="SYNTHETIC-SCHEDULER-REQUEST-0002")
    verifier = _Verifier(_verification(SatRequestState.IN_PROCESS, SatOutcomeAction.IN_PROGRESS))

    report = run_verify_due(storage_root=tmp_path, profile_id="default", verifier=verifier, now=DUE_AT, limit=1)

    assert report.due_count == 2
    assert report.processed_count == 1
    assert len(verifier.calls) == 1


def test_request_ref_targets_one_due_request(tmp_path: Path) -> None:
    first = _persist_due(tmp_path, request_id=REQUEST_ID)
    second = _persist_due(tmp_path, request_id="SYNTHETIC-SCHEDULER-REQUEST-0002")
    verifier = _Verifier(_verification(SatRequestState.IN_PROCESS, SatOutcomeAction.IN_PROGRESS))

    report = run_verify_due(
        storage_root=tmp_path,
        profile_id="default",
        verifier=verifier,
        now=DUE_AT,
        request_ref=second.request_ref,
    )

    assert report.due_count == 1
    assert report.selected_count == 1
    assert report.processed_count == 1
    assert report.items[0].request_ref == second.request_ref
    assert verifier.calls == [second.id_solicitud]
    stored = {record.request_ref: record for record in list_live_metadata_requests(tmp_path)}
    assert stored[first.request_ref].attempt_count == 0
    assert stored[second.request_ref].attempt_count == 1


def test_scheduler_source_has_no_sleep_call() -> None:
    assert "sleep(" not in inspect.getsource(sat_async_verify)


def _persist_due(root: Path, *, request_id: str = REQUEST_ID):
    return persist_live_metadata_request(
        storage_root=root,
        profile_id="default",
        query=_query(),
        operation="SolicitaDescargaRecibidos",
        id_solicitud=request_id,
        sat_code="5000",
        sat_message="Accepted",
        source_command="sat metadata-request-smoke",
        permit_ref=None,
        now=CREATED_AT,
    )


def _only_record(root: Path):
    records = list_live_metadata_requests(root)
    assert len(records) == 1
    return records[0]


def _query() -> DownloadQuery:
    return DownloadQuery(
        "default",
        "XAXX010101000",
        DownloadDirection.RECEIVED,
        RequestType.METADATA,
        DateTimePeriod(
            datetime(2024, 1, 1, tzinfo=timezone.utc),
            datetime(2024, 1, 1, 0, 0, 2, tzinfo=timezone.utc),
        ),
    )


def _verification(
    state: SatRequestState,
    action: SatOutcomeAction,
    *,
    sat_code: str = "5000",
    message: str = "Synthetic verify result",
    package_ids: tuple[str, ...] = (),
) -> SatVerificationResult:
    return SatVerificationResult(
        request_id=REQUEST_ID,
        state=state,
        sat_code=sat_code,
        message=message,
        action=action,
        package_ids=package_ids,
    )


class _Verifier:
    def __init__(self, result: SatVerificationResult) -> None:
        self.result = result
        self.calls: list[str] = []
        self.download_calls: list[str] = []

    def verify_request(self, request_id: str) -> SatVerificationResult:
        self.calls.append(request_id)
        return replace(self.result, request_id=request_id)

    def download_package(self, package_id: str) -> bytes:
        self.download_calls.append(package_id)
        return b"synthetic"


class _TimeoutVerifier:
    def verify_request(self, request_id: str) -> SatVerificationResult:
        raise TimeoutError(f"synthetic timeout for {request_id}")
