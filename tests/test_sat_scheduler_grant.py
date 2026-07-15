from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from multiprocessing import get_context
from pathlib import Path

import pytest

from cfdi_vault.sat_scheduler_grant import (
    SchedulerGrantError,
    claim_scheduler_grant,
    create_scheduler_grant,
    load_scheduler_grant,
)

NOW = datetime(2026, 7, 14, 12, 0, tzinfo=timezone.utc)


def test_scheduler_grant_is_bounded_and_consumed_atomically(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    grant = create_scheduler_grant(
        storage_root=tmp_path,
        profile_id="default",
        repo_root=repo,
        max_invocations=2,
        expires_in=timedelta(hours=1),
        now=NOW,
    )

    claim_scheduler_grant(
        storage_root=tmp_path,
        grant_ref=grant.grant_id,
        profile_id="default",
        repo_root=repo,
        now=NOW,
    )
    claimed = claim_scheduler_grant(
        storage_root=tmp_path,
        grant_ref=grant.grant_id,
        profile_id="default",
        repo_root=repo,
        now=NOW,
    )

    assert claimed.consumed_invocations == 2
    with pytest.raises(SchedulerGrantError, match="scheduler-grant-exhausted"):
        claim_scheduler_grant(
            storage_root=tmp_path,
            grant_ref=grant.grant_id,
            profile_id="default",
            repo_root=repo,
            now=NOW,
        )


@pytest.mark.parametrize(
    ("profile_id", "repo_name", "at", "reason"),
    [
        ("other", "repo", NOW, "scheduler-grant-profile-mismatch"),
        ("default", "other-repo", NOW, "scheduler-grant-repo-mismatch"),
        ("default", "repo", NOW + timedelta(hours=2), "scheduler-grant-expired"),
    ],
)
def test_scheduler_grant_fails_closed_outside_scope(
    tmp_path: Path,
    profile_id: str,
    repo_name: str,
    at: datetime,
    reason: str,
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    grant = create_scheduler_grant(
        storage_root=tmp_path,
        profile_id="default",
        repo_root=repo,
        max_invocations=1,
        expires_in=timedelta(hours=1),
        now=NOW,
    )
    candidate_repo = tmp_path / repo_name
    candidate_repo.mkdir(exist_ok=True)

    with pytest.raises(SchedulerGrantError, match=reason):
        claim_scheduler_grant(
            storage_root=tmp_path,
            grant_ref=grant.grant_id,
            profile_id=profile_id,
            repo_root=candidate_repo,
            now=at,
        )
    assert load_scheduler_grant(tmp_path, grant.grant_id).consumed_invocations == 0


def test_scheduler_grant_cannot_broaden_authority(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    grant = create_scheduler_grant(
        storage_root=tmp_path,
        profile_id="default",
        repo_root=repo,
        max_invocations=1,
        expires_in=timedelta(hours=1),
        now=NOW,
    )
    document = json.loads(grant.path.read_text(encoding="utf-8"))
    document["allowDownload"] = True
    grant.path.write_text(json.dumps(document), encoding="utf-8")

    with pytest.raises(SchedulerGrantError, match="scheduler-grant-authority-invalid"):
        claim_scheduler_grant(
            storage_root=tmp_path,
            grant_ref=grant.grant_id,
            profile_id="default",
            repo_root=repo,
            now=NOW,
        )


@pytest.mark.parametrize(
    ("changes", "reason"),
    [
        ({"consumedInvocations": -1}, "scheduler-grant-policy-invalid"),
        ({"consumedInvocations": 3}, "scheduler-grant-policy-invalid"),
        ({"scope": "request_create"}, "scheduler-grant-scope-mismatch"),
        ({"maxAttemptsPerRequest": 13}, "scheduler-grant-policy-invalid"),
        ({"redactionRequired": False}, "scheduler-grant-authority-invalid"),
        ({"createdAt": "2026-07-14T12:05:00Z"}, "scheduler-grant-window-invalid"),
        (
            {"createdAt": "2026-07-14T13:00:00Z", "expiresAt": "2026-07-14T12:30:00Z"},
            "scheduler-grant-window-invalid",
        ),
        ({"expiresAt": "2026-08-14T12:00:00Z"}, "scheduler-grant-lifetime-invalid"),
    ],
)
def test_scheduler_grant_rejects_corrupted_persisted_windows(
    tmp_path: Path,
    changes: dict[str, object],
    reason: str,
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    grant = create_scheduler_grant(
        storage_root=tmp_path,
        profile_id="default",
        repo_root=repo,
        max_invocations=2,
        expires_in=timedelta(hours=1),
        now=NOW,
    )
    document = json.loads(grant.path.read_text(encoding="utf-8"))
    document.update(changes)
    grant.path.write_text(json.dumps(document), encoding="utf-8")

    with pytest.raises(SchedulerGrantError, match=reason):
        claim_scheduler_grant(
            storage_root=tmp_path,
            grant_ref=grant.grant_id,
            profile_id="default",
            repo_root=repo,
            now=NOW,
        )


def test_scheduler_grant_claim_is_atomic_across_processes(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    grant = create_scheduler_grant(
        storage_root=tmp_path,
        profile_id="default",
        repo_root=repo,
        max_invocations=1,
        expires_in=timedelta(hours=1),
        now=NOW,
    )
    context = get_context("spawn")
    start = context.Event()
    results = context.Queue()
    workers = [
        context.Process(target=_claim_grant, args=(tmp_path, repo, grant.grant_id, start, results))
        for _ in range(2)
    ]
    for worker in workers:
        worker.start()
    start.set()
    outcomes = sorted(results.get(timeout=10) for _ in workers)
    for worker in workers:
        worker.join(timeout=10)
        assert worker.exitcode == 0

    assert outcomes.count("ok") == 1
    assert next(item for item in outcomes if item != "ok") in {
        "scheduler-grant-claim-busy",
        "scheduler-grant-exhausted",
    }
    assert load_scheduler_grant(tmp_path, grant.grant_id).consumed_invocations == 1


def _claim_grant(storage_root: Path, repo_root: Path, grant_id: str, start: object, results: object) -> None:
    start.wait(timeout=10)
    try:
        claim_scheduler_grant(
            storage_root=storage_root,
            grant_ref=grant_id,
            profile_id="default",
            repo_root=repo_root,
            now=NOW,
        )
    except SchedulerGrantError as exc:
        results.put(exc.reason)
    else:
        results.put("ok")
