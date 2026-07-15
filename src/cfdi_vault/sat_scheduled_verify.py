"""Locked, grant-bounded one-shot orchestration for due SAT verification."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from cfdi_vault.ports import SatVerificationPort
from cfdi_vault.sat_async_verify import VerifyBackoffPolicy, VerifyDueReport, run_verify_due
from cfdi_vault.sat_scheduler_grant import (
    MAX_ATTEMPTS_PER_REQUEST,
    SchedulerGrantError,
    claim_scheduler_grant,
)
from cfdi_vault.sat_scheduler_lock import LocalFileLock


@dataclass(frozen=True)
class ScheduledVerifyResult:
    """Redacted result of one locked scheduler invocation."""

    report: VerifyDueReport
    grant_consumed: bool


def scheduler_state_lock_path(storage_root: str | Path) -> Path:
    """Return the lock that serializes the full shared-state cycle."""

    return Path(storage_root).expanduser() / "state" / "sat-verify-due.lock"


def run_scheduled_verify(
    *,
    storage_root: str | Path,
    profile_id: str,
    repo_root: str | Path,
    verifier: SatVerificationPort,
    grant_ref: str | Path | None = None,
    dry_run: bool = False,
    now: datetime | None = None,
) -> ScheduledVerifyResult:
    """Check at most one due request while holding the shared-state lock.

    Dry runs do not claim a grant or mutate request state. Authorized runs
    consume one scheduler-grant invocation before the injected verifier is
    allowed to run. The hard-coded batch limit is one.
    """

    with LocalFileLock(scheduler_state_lock_path(storage_root), now=now):
        grant_consumed = False
        if not dry_run:
            if grant_ref is None or not str(grant_ref).strip():
                raise SchedulerGrantError("scheduler-grant-required")
            claim_scheduler_grant(
                storage_root=storage_root,
                grant_ref=grant_ref,
                profile_id=profile_id,
                repo_root=repo_root,
                now=now,
            )
            grant_consumed = True
        report = run_verify_due(
            storage_root=str(storage_root),
            profile_id=profile_id,
            verifier=verifier,
            limit=1,
            dry_run=dry_run,
            now=now,
            policy=VerifyBackoffPolicy(max_attempts=MAX_ATTEMPTS_PER_REQUEST),
        )
        return ScheduledVerifyResult(report=report, grant_consumed=grant_consumed)
