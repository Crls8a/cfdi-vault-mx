from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from cfdi_vault.domain import DateTimePeriod, DownloadDirection, DownloadQuery, RequestType, SatRequestState
from cfdi_vault.sat_contract import SatOutcomeAction, SatVerificationResult
from cfdi_vault.sat_live_request_state import list_live_metadata_requests, persist_live_metadata_request
from cfdi_vault.sat_scheduled_verify import run_scheduled_verify, scheduler_state_lock_path
from cfdi_vault.sat_scheduler_grant import (
    SchedulerGrantError,
    create_scheduler_grant,
    load_scheduler_grant,
)
from cfdi_vault.sat_scheduler_lock import LocalFileLock, SchedulerLockError

NOW = datetime(2026, 7, 14, 12, 0, tzinfo=timezone.utc)


def test_dry_run_does_not_verify_mutate_or_consume_grant(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    _persist_due(tmp_path, "SYNTHETIC-SCHEDULER-REQUEST-0001")
    grant = _grant(tmp_path, repo)
    before = list_live_metadata_requests(tmp_path)
    verifier = _Verifier()

    result = run_scheduled_verify(
        storage_root=tmp_path,
        profile_id="default",
        repo_root=repo,
        verifier=verifier,
        grant_ref=grant.grant_id,
        dry_run=True,
        now=NOW,
    )

    assert result.report.due_count == 1
    assert result.report.processed_count == 0
    assert result.grant_consumed is False
    assert verifier.calls == []
    assert list_live_metadata_requests(tmp_path) == before
    assert load_scheduler_grant(tmp_path, grant.grant_id).consumed_invocations == 0


def test_authorized_run_verifies_at_most_one_due_request(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    _persist_due(tmp_path, "SYNTHETIC-SCHEDULER-REQUEST-0001")
    _persist_due(tmp_path, "SYNTHETIC-SCHEDULER-REQUEST-0002")
    grant = _grant(tmp_path, repo)
    verifier = _Verifier()

    result = run_scheduled_verify(
        storage_root=tmp_path,
        profile_id="default",
        repo_root=repo,
        verifier=verifier,
        grant_ref=grant.grant_id,
        now=NOW,
    )

    assert result.report.selected_count == 1
    assert result.report.processed_count == 1
    assert len(verifier.calls) == 1
    assert load_scheduler_grant(tmp_path, grant.grant_id).consumed_invocations == 1
    attempts = sorted(record.attempt_count for record in list_live_metadata_requests(tmp_path))
    assert attempts == [0, 1]


def test_run_requires_scheduler_grant_before_verification(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    _persist_due(tmp_path, "SYNTHETIC-SCHEDULER-REQUEST-0001")
    verifier = _Verifier()

    with pytest.raises(SchedulerGrantError, match="scheduler-grant-required"):
        run_scheduled_verify(
            storage_root=tmp_path,
            profile_id="default",
            repo_root=repo,
            verifier=verifier,
            now=NOW,
        )
    assert verifier.calls == []
    assert scheduler_state_lock_path(tmp_path).exists()
    released = LocalFileLock(scheduler_state_lock_path(tmp_path), now=NOW)
    released.acquire()
    released.release()


def test_state_lock_blocks_overlap_without_consuming_grant(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    grant = _grant(tmp_path, repo)
    lock = LocalFileLock(scheduler_state_lock_path(tmp_path), now=NOW)
    lock.acquire()
    try:
        with pytest.raises(SchedulerLockError, match="scheduler-lock-held"):
            run_scheduled_verify(
                storage_root=tmp_path,
                profile_id="default",
                repo_root=repo,
                verifier=_Verifier(),
                grant_ref=grant.grant_id,
                now=NOW,
            )
    finally:
        lock.release()
    assert load_scheduler_grant(tmp_path, grant.grant_id).consumed_invocations == 0


def _repo(root: Path) -> Path:
    repo = root / "repo"
    repo.mkdir()
    return repo


def _grant(root: Path, repo: Path):
    return create_scheduler_grant(
        storage_root=root,
        profile_id="default",
        repo_root=repo,
        max_invocations=1,
        expires_in=timedelta(hours=1),
        now=NOW,
    )


def _persist_due(root: Path, request_id: str) -> None:
    query = DownloadQuery(
        "default",
        "XAXX010101000",
        DownloadDirection.RECEIVED,
        RequestType.METADATA,
        DateTimePeriod(
            datetime(2024, 1, 1, tzinfo=timezone.utc),
            datetime(2024, 1, 1, 0, 0, 2, tzinfo=timezone.utc),
        ),
    )
    persist_live_metadata_request(
        storage_root=root,
        profile_id="default",
        query=query,
        operation="SolicitaDescargaRecibidos",
        id_solicitud=request_id,
        sat_code="5000",
        sat_message="Accepted",
        source_command="test",
        permit_ref=None,
        now=NOW - timedelta(minutes=5),
    )


class _Verifier:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def verify_request(self, request_id: str) -> SatVerificationResult:
        self.calls.append(request_id)
        return replace(
            SatVerificationResult(
                request_id=request_id,
                state=SatRequestState.IN_PROCESS,
                sat_code="5000",
                message="Synthetic verify result",
                action=SatOutcomeAction.IN_PROGRESS,
            ),
            request_id=request_id,
        )
