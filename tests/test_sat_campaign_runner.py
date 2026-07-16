from __future__ import annotations

import ast
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from threading import Barrier, Event, Lock
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

import cfdi_vault.sat_campaign_grant as grants
import cfdi_vault.sat_campaign_manifest_store as manifests
import cfdi_vault.sat_campaign_runner as subject
import cfdi_vault.sat_metadata_submission as submissions
import cfdi_vault.secure_state_file as secure_state
from cfdi_vault.domain import DateTimePeriod, DownloadQuery, RequestType
from cfdi_vault.sat_campaign_manifest import (
    CampaignWorkState,
    SatCampaignManifest,
    build_campaign_manifest,
)
from cfdi_vault.sat_contract import SatOutcomeAction, SatRequestResult

NOW = datetime(2026, 7, 16, 12, tzinfo=timezone.utc)
PROFILE, COMMIT = "profile-synthetic", "a" * 40
REPO = Path(__file__).resolve().parents[1]


def _setup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    manifest: SatCampaignManifest | None = None,
):
    storage = tmp_path / "private"
    current = build_campaign_manifest(PROFILE) if manifest is None else manifest
    monkeypatch.setattr(grants, "_repository_context", lambda _: (REPO, COMMIT))
    manifests.initialize_campaign_manifest(storage, current, repo_root=REPO)
    grant = grants.create_campaign_grant(
        storage, current, current.profile_id, COMMIT, REPO, "metadata proof",
        timedelta(days=14), now=NOW,
    )
    return storage, current, grant


def _reserve(storage: Path, manifest: SatCampaignManifest, grant: grants.CampaignGrant,
             invocation: int = 1):
    return subject.reserve_metadata_campaign_capacity_once(
        storage_root=storage,
        repo_root=REPO,
        campaign_ref=manifest.campaign_ref,
        grant_ref=grant.grant_ref,
        profile_id=manifest.profile_id,
        invocation_ref=f"inv-{invocation:024x}",
        now=NOW,
    )


def _queries(manifest: SatCampaignManifest) -> dict[str, DownloadQuery]:
    return {
        item.work_ref: DownloadQuery(
            PROFILE, "RFC-SYNTHETIC", item.direction, RequestType.METADATA,
            DateTimePeriod(
                datetime.combine(item.start, datetime.min.time(), tzinfo=timezone.utc),
                datetime.combine(item.end, datetime.max.time(), tzinfo=timezone.utc),
            ),
        )
        for item in manifest.items
        if item.state is CampaignWorkState.OUTSTANDING
    }


def _prepare(
    storage, manifest, grant, queries, invocation=None, *, max_new_submissions=2,
):
    return subject.prepare_reserved_metadata_submissions_once(
        storage_root=storage, repo_root=REPO, campaign_ref=manifest.campaign_ref,
        grant_ref=grant.grant_ref, profile_id=PROFILE, queries_by_work=queries,
        invocation_ref=invocation, max_new_submissions=max_new_submissions, now=NOW,
    )


def test_reserves_exact_chronological_first_two_and_repeat_adds_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    storage, manifest, grant = _setup(tmp_path, monkeypatch)
    first = _reserve(storage, manifest, grant)
    assert first.outstanding_work_refs == tuple(item.work_ref for item in manifest.items[:2])
    assert tuple(item.work_ref for item in first.actions) == first.outstanding_work_refs
    assert {item.action for item in first.actions} == {
        subject.CampaignCapacityAction.RESERVED_WITHOUT_CONTACT,
    }

    repeated = _reserve(storage, manifest, grant, 2)
    assert repeated.outstanding_work_refs == first.outstanding_work_refs
    assert repeated.actions == ()
    assert PROFILE not in repr(first)


def test_one_existing_outstanding_reserves_only_one_more(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    initial = build_campaign_manifest(PROFILE)
    one = replace(initial, items=(
        replace(initial.items[0], state=CampaignWorkState.OUTSTANDING),
        *initial.items[1:],
    ))
    storage, manifest, grant = _setup(tmp_path, monkeypatch, manifest=one)
    result = _reserve(storage, manifest, grant)
    assert result.outstanding_work_refs == tuple(item.work_ref for item in manifest.items[:2])
    assert tuple(item.work_ref for item in result.actions) == (manifest.items[1].work_ref,)


def test_no_planned_leaf_returns_no_capacity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    initial = build_campaign_manifest(PROFILE)
    finished = replace(initial, items=tuple(
        replace(item, state=CampaignWorkState.NO_DATA, recovery_ref=f"run-{index:012x}")
        for index, item in enumerate(initial.items)
    ))
    storage, manifest, grant = _setup(tmp_path, monkeypatch, manifest=finished)
    result = _reserve(storage, manifest, grant)
    assert result.outstanding_work_refs == ()
    assert result.actions == ()


def test_rejects_grant_and_profile_lineage_before_claim(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    storage, manifest, grant = _setup(tmp_path, monkeypatch)
    other = build_campaign_manifest("other-profile")
    manifests.initialize_campaign_manifest(storage, other, repo_root=REPO)
    other_grant = grants.create_campaign_grant(
        storage, other, other.profile_id, COMMIT, REPO, "metadata proof",
        timedelta(days=14), now=NOW,
    )
    with pytest.raises(subject.CampaignRunnerError, match="^campaign-authority-lineage-invalid$"):
        _reserve(storage, manifest, other_grant)
    with pytest.raises(subject.CampaignRunnerError, match="^campaign-authority-lineage-invalid$"):
        subject.reserve_metadata_campaign_capacity_once(
            storage_root=storage, repo_root=REPO, campaign_ref=manifest.campaign_ref,
            grant_ref=grant.grant_ref, profile_id="other-profile",
            invocation_ref="inv-" + "3" * 24, now=NOW,
        )
    assert grants.load_campaign_grant(
        storage, grant.grant_ref, REPO, now=NOW,
    ).invocation_claims == ()


@pytest.mark.parametrize(
    ("commit", "now", "reason"),
    [("b" * 40, NOW, "campaign-grant-state-invalid"),
     (COMMIT, NOW + timedelta(days=14), "campaign-grant-expired")],
)
def test_rejects_current_commit_or_expiry_mismatch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    commit: str, now: datetime, reason: str,
) -> None:
    storage, manifest, grant = _setup(tmp_path, monkeypatch)
    monkeypatch.setattr(grants, "_repository_context", lambda _: (REPO, commit))
    with pytest.raises(grants.CampaignGrantError, match=f"^{reason}$"):
        subject.reserve_metadata_campaign_capacity_once(
            storage_root=storage, repo_root=REPO, campaign_ref=manifest.campaign_ref,
            grant_ref=grant.grant_ref, profile_id=PROFILE,
            invocation_ref="inv-" + "4" * 24, now=now,
        )


def test_concurrent_contention_retries_without_exceeding_two(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    storage, manifest, grant = _setup(tmp_path, monkeypatch)
    reservation_barrier, reserving, partial_seen = Barrier(2), Event(), Event()
    original_read, original_reserve, held = (
        secure_state._read, subject.reserve_campaign_manifest_capacity, False  # noqa: SLF001
    )

    def hold_first_read(*args: object, **kwargs: object) -> bytes | None:
        nonlocal held
        if reserving.is_set() and not held:
            held = True
            assert partial_seen.wait(2)
        return original_read(*args, **kwargs)  # type: ignore[arg-type]

    def race_reservation(*args: object, **kwargs: object):
        reservation_barrier.wait()
        reserving.set()
        return original_reserve(*args, **kwargs)

    monkeypatch.setattr(secure_state, "_read", hold_first_read)
    monkeypatch.setattr(subject, "reserve_campaign_manifest_capacity", race_reservation)

    def run(index: int):
        for _ in range(100):
            try:
                return _reserve(storage, manifest, grant, index)
            except subject.CampaignRunnerError as error:
                assert (error.committed, error.retry_safe) == (True, False)
                partial_seen.set()
                return error
            except (grants.CampaignGrantError, manifests.CampaignManifestStoreError) as error:
                if not error.retry_safe:
                    raise
                time.sleep(0.002)
        raise AssertionError("secure state remained busy")

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = tuple(pool.map(run, (1, 2)))
    stored = manifests.load_campaign_manifest(storage, manifest.campaign_ref, repo_root=REPO)
    partials = tuple(item for item in results if isinstance(item, subject.CampaignRunnerError))
    successes = tuple(item for item in results if isinstance(item, subject.CampaignCapacityResult))
    loaded = grants.load_campaign_grant(storage, grant.grant_ref, REPO, now=NOW)
    assert len(partials) == len(successes) == 1 and partial_seen.is_set()
    assert sum(item.state is CampaignWorkState.OUTSTANDING for item in stored.items) <= 2
    assert sum(len(result.actions) for result in successes) == 2
    assert len(loaded.invocation_claims) == 2 and loaded.submission_claims == ()


@pytest.mark.parametrize("underlying_uncertain", [False, True])
def test_reservation_failure_after_new_claim_reports_partial_commit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, underlying_uncertain: bool,
) -> None:
    storage, manifest, grant = _setup(tmp_path, monkeypatch)
    failure = manifests.CampaignManifestStoreError(
        "campaign-state-failed", committed=underlying_uncertain, uncertain=underlying_uncertain,
    )
    monkeypatch.setattr(
        subject, "reserve_campaign_manifest_capacity", lambda *args, **kwargs: (_ for _ in ()).throw(failure),
    )
    with pytest.raises(subject.CampaignRunnerError) as caught:
        _reserve(storage, manifest, grant)
    error = caught.value
    assert (error.reason, error.committed, error.uncertain, error.retry_safe) == (
        "campaign-invocation-claimed-capacity-failed", True, underlying_uncertain, False,
    )
    loaded = grants.load_campaign_grant(storage, grant.grant_ref, REPO, now=NOW)
    assert len(loaded.invocation_claims) == 1 and loaded.submission_claims == ()
    stored = manifests.load_campaign_manifest(storage, manifest.campaign_ref, repo_root=REPO)
    assert not any(item.state is CampaignWorkState.OUTSTANDING for item in stored.items)


def test_import_graph_has_only_internal_campaign_dependencies() -> None:
    tree = ast.parse(Path(subject.__file__).read_text(encoding="utf-8"))
    imported = {
        alias.name for node in ast.walk(tree) if isinstance(node, ast.Import)
        for alias in node.names
    } | {
        node.module for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module is not None
    }
    forbidden = ("adapter", "credential", "transport", "common", "experimental")
    assert not any(part in name for name in imported for part in forbidden)


def test_prepares_same_process_reserved_work_without_second_invocation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    storage, manifest, grant = _setup(tmp_path, monkeypatch)
    reserved = _reserve(storage, manifest, grant)
    current = manifests.load_campaign_manifest(storage, manifest.campaign_ref, repo_root=REPO)

    queries = _queries(current)
    result = _prepare(storage, manifest, grant, queries, reserved.invocation_ref)

    actions = tuple(action.action for action in result.actions)
    assert actions.count(subject.CampaignSubmissionAction.RECOVERY_LINKED) == 2
    assert actions.count(subject.CampaignSubmissionAction.SUBMISSION_ALLOWED) == 2
    loaded = grants.load_campaign_grant(storage, grant.grant_ref, REPO, now=NOW)
    assert len(loaded.invocation_claims) == 1
    replay = _prepare(
        storage, manifest, grant, queries, reserved.invocation_ref,
        max_new_submissions=1,
    )
    assert all(item.action is subject.CampaignSubmissionAction.ORPHAN_UNCERTAIN
               for item in replay.actions)
    recover = subject.campaign_metadata_recovery_ref
    by_recovery = {recover(PROFILE, query.criteria_hash()): query for query in queries.values()}

    def accepted(_root, recovery_ref, **_kwargs):
        query, period = by_recovery[recovery_ref], by_recovery[recovery_ref].period
        return SimpleNamespace(
            recovery=SimpleNamespace(recovery_ref=recovery_ref), profile_id=PROFILE,
            criteria_hash=query.criteria_hash(), direction=query.direction.value,
            kind=query.request_type.value, fecha_inicial=period.start.date().isoformat(),
            fecha_final=period.end.date().isoformat(), authorization_ref=grant.grant_ref,
        )

    monkeypatch.setattr(subject, "load_metadata_recovery_state", accepted)
    accepted_replay = _prepare(storage, manifest, grant, queries, reserved.invocation_ref)
    assert all(item.action is subject.CampaignSubmissionAction.CLAIMED_REPLAY
               for item in accepted_replay.actions)


def test_submission_limit_one_claims_only_first_chronological_work(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    storage, manifest, grant = _setup(tmp_path, monkeypatch)
    _reserve(storage, manifest, grant)
    current = manifests.load_campaign_manifest(storage, manifest.campaign_ref, repo_root=REPO)

    result = _prepare(
        storage, manifest, grant, _queries(current), max_new_submissions=1,
    )

    by_work = {
        item.work_ref: [action.action for action in result.actions
                        if action.work_ref == item.work_ref]
        for item in current.items[:2]
    }
    assert by_work[current.items[0].work_ref] == [
        subject.CampaignSubmissionAction.RECOVERY_LINKED,
        subject.CampaignSubmissionAction.SUBMISSION_ALLOWED,
    ]
    assert by_work[current.items[1].work_ref] == [
        subject.CampaignSubmissionAction.RECOVERY_LINKED,
        subject.CampaignSubmissionAction.SUBMISSION_DEFERRED,
    ]
    stored = manifests.load_campaign_manifest(storage, manifest.campaign_ref, repo_root=REPO)
    assert all(item.recovery_ref is not None for item in stored.items[:2])
    claims = grants.load_campaign_grant(
        storage, grant.grant_ref, REPO, now=NOW,
    ).submission_claims
    assert tuple(claim.work_ref for claim in claims) == (current.items[0].work_ref,)


def test_submission_limit_advances_only_after_accepted_recovery(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    storage, manifest, grant = _setup(tmp_path, monkeypatch)
    _reserve(storage, manifest, grant)
    current = manifests.load_campaign_manifest(storage, manifest.campaign_ref, repo_root=REPO)
    queries = _queries(current)
    _prepare(storage, manifest, grant, queries, max_new_submissions=1)

    blocked = _prepare(storage, manifest, grant, queries, max_new_submissions=1)
    assert [item.action for item in blocked.actions] == [
        subject.CampaignSubmissionAction.ORPHAN_UNCERTAIN,
        subject.CampaignSubmissionAction.SUBMISSION_DEFERRED,
    ]
    assert len(grants.load_campaign_grant(
        storage, grant.grant_ref, REPO, now=NOW,
    ).submission_claims) == 1

    first_query = queries[current.items[0].work_ref]
    first_period = first_query.period
    assert first_period is not None

    def accepted(_root, recovery_ref, **_kwargs):
        return SimpleNamespace(
            recovery=SimpleNamespace(recovery_ref=recovery_ref), profile_id=PROFILE,
            criteria_hash=first_query.criteria_hash(),
            direction=first_query.direction.value, kind=first_query.request_type.value,
            fecha_inicial=first_period.start.date().isoformat(),
            fecha_final=first_period.end.date().isoformat(),
            authorization_ref=grant.grant_ref,
        )

    monkeypatch.setattr(subject, "load_metadata_recovery_state", accepted)
    advanced = _prepare(storage, manifest, grant, queries, max_new_submissions=1)
    assert [item.action for item in advanced.actions] == [
        subject.CampaignSubmissionAction.CLAIMED_REPLAY,
        subject.CampaignSubmissionAction.SUBMISSION_ALLOWED,
    ]
    claims = grants.load_campaign_grant(
        storage, grant.grant_ref, REPO, now=NOW,
    ).submission_claims
    assert tuple(claim.work_ref for claim in claims) == tuple(
        item.work_ref for item in current.items[:2]
    )


@pytest.mark.parametrize(
    ("outcome", "replay_action", "next_action"),
    (
        (SatRequestResult("", "5003", "private", SatOutcomeAction.PERMANENT_FAILURE),
         subject.CampaignSubmissionAction.FAILED_REPLAY,
         subject.CampaignSubmissionAction.SUBMISSION_ALLOWED),
        (RuntimeError("private"), subject.CampaignSubmissionAction.ORPHAN_UNCERTAIN,
         subject.CampaignSubmissionAction.SUBMISSION_DEFERRED),
        (SatRequestResult("synthetic-request", "5000", "private", SatOutcomeAction.ACCEPTED),
         subject.CampaignSubmissionAction.CLAIMED_REPLAY,
         subject.CampaignSubmissionAction.SUBMISSION_ALLOWED),
    ),
)
def test_persisted_submission_outcome_controls_exact_replay(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, outcome, replay_action, next_action,
) -> None:
    storage, manifest, grant = _setup(tmp_path, monkeypatch)
    _reserve(storage, manifest, grant)
    current = manifests.load_campaign_manifest(storage, manifest.campaign_ref, repo_root=REPO)
    queries = _queries(current)
    first = _prepare(storage, manifest, grant, queries, max_new_submissions=1)
    query = queries[first.actions[0].work_ref]
    recovery_ref = subject.campaign_metadata_recovery_ref(PROFILE, query.criteria_hash())
    requester = Mock(submit_request=Mock(
        side_effect=outcome if isinstance(outcome, Exception) else None,
        return_value=None if isinstance(outcome, Exception) else outcome,
    ))
    submissions.submit_metadata_recovery_once(
        requester=requester, query=query, now=NOW, storage_root=storage,
        profile_id=PROFILE, criteria_hash=query.criteria_hash(),
        authorization_ref=grant.grant_ref, expected_recovery_ref=recovery_ref,
        tested_commit=COMMIT, entry_point="sat-campaign", repo_root=REPO,
    )

    replay = _prepare(storage, manifest, grant, queries, max_new_submissions=1)

    assert [item.action for item in replay.actions] == [replay_action, next_action]


@pytest.mark.parametrize("invalid_limit", [0, 3, True, 1.0, None])
def test_submission_limit_rejects_invalid_value_before_mutation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, invalid_limit: object,
) -> None:
    storage, manifest, grant = _setup(tmp_path, monkeypatch)
    _reserve(storage, manifest, grant)
    before_manifest = manifests.load_campaign_manifest(
        storage, manifest.campaign_ref, repo_root=REPO,
    )
    before_grant = grants.load_campaign_grant(storage, grant.grant_ref, REPO, now=NOW)

    with pytest.raises(
        subject.CampaignRunnerError,
        match="^campaign-new-submission-limit-invalid$",
    ):
        _prepare(
            storage, manifest, grant, _queries(before_manifest),
            invocation="inv-" + "f" * 24,
            max_new_submissions=invalid_limit,
        )

    assert manifests.load_campaign_manifest(
        storage, manifest.campaign_ref, repo_root=REPO,
    ) == before_manifest
    assert grants.load_campaign_grant(
        storage, grant.grant_ref, REPO, now=NOW,
    ) == before_grant


def test_restart_after_reserve_claims_new_invocation_without_more_capacity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    storage, manifest, grant = _setup(tmp_path, monkeypatch)
    reserved = _reserve(storage, manifest, grant)
    current = manifests.load_campaign_manifest(storage, manifest.campaign_ref, repo_root=REPO)
    result = _prepare(storage, manifest, grant, _queries(current))
    loaded = grants.load_campaign_grant(storage, grant.grant_ref, REPO, now=NOW)
    stored = manifests.load_campaign_manifest(storage, manifest.campaign_ref, repo_root=REPO)
    assert result.invocation_ref != reserved.invocation_ref
    assert len(loaded.invocation_claims) == 2 and len(loaded.submission_claims) == 2
    assert sum(item.state is CampaignWorkState.OUTSTANDING for item in stored.items) == 2


def test_restart_after_bind_resumes_claim_without_rebinding(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    storage, manifest, grant = _setup(tmp_path, monkeypatch)
    _reserve(storage, manifest, grant)
    current = manifests.load_campaign_manifest(storage, manifest.campaign_ref, repo_root=REPO)
    queries = _queries(current)
    first = current.items[0]
    recovery_ref = subject.campaign_metadata_recovery_ref(PROFILE, queries[first.work_ref].criteria_hash())
    manifests.bind_campaign_manifest_recovery(
        storage, manifest.campaign_ref, first.work_ref, recovery_ref, repo_root=REPO,
    )
    result = _prepare(storage, manifest, grant, queries)
    first_actions = [item.action for item in result.actions if item.work_ref == first.work_ref]
    assert first_actions == [subject.CampaignSubmissionAction.SUBMISSION_ALLOWED]


@pytest.mark.parametrize("change", ["direction", "period", "criteria"])
def test_rejects_query_lineage_before_bind_or_submission_claim(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, change: str,
) -> None:
    storage, manifest, grant = _setup(tmp_path, monkeypatch)
    _reserve(storage, manifest, grant)
    current = manifests.load_campaign_manifest(storage, manifest.campaign_ref, repo_root=REPO)
    queries = _queries(current)
    first = current.items[0]
    query = queries[first.work_ref]
    if change == "direction":
        query = replace(query, direction=current.items[1].direction)
    elif change == "period":
        assert query.period is not None
        query = replace(query, period=replace(query.period, end=query.period.end - timedelta(seconds=1)))
    else:
        query = replace(query, document_type="I")
    queries[first.work_ref] = query
    with pytest.raises(subject.CampaignRunnerError, match="^campaign-query-lineage-invalid$"):
        _prepare(storage, manifest, grant, queries)
    stored = manifests.load_campaign_manifest(storage, manifest.campaign_ref, repo_root=REPO)
    assert not any(item.recovery_ref for item in stored.items)
    loaded = grants.load_campaign_grant(storage, grant.grant_ref, REPO, now=NOW)
    assert loaded.submission_claims == ()


@pytest.mark.parametrize("target", ["bind", "claim"])
@pytest.mark.parametrize("uncertain", [False, True])
def test_partial_failure_is_committed_non_retry_safe_without_permission(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, target: str, uncertain: bool,
) -> None:
    storage, manifest, grant = _setup(tmp_path, monkeypatch)
    reserved = _reserve(storage, manifest, grant)
    current = manifests.load_campaign_manifest(storage, manifest.campaign_ref, repo_root=REPO)
    if target == "bind":
        error = manifests.CampaignManifestStoreError("failed", uncertain=uncertain)
        attribute = "bind_campaign_manifest_recovery"
    else:
        error = grants.CampaignGrantError("failed", uncertain=uncertain)
        attribute = "claim_campaign_grant_submission"
    monkeypatch.setattr(subject, attribute, lambda *a, **k: (_ for _ in ()).throw(error))
    with pytest.raises(subject.CampaignRunnerError) as caught:
        _prepare(storage, manifest, grant, _queries(current), reserved.invocation_ref)
    assert caught.value.committed and caught.value.uncertain is uncertain
    assert not caught.value.retry_safe
    assert grants.load_campaign_grant(
        storage, grant.grant_ref, REPO, now=NOW,
    ).submission_claims == ()


def test_concurrent_preparation_allows_each_submission_at_most_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    storage, manifest, grant = _setup(tmp_path, monkeypatch)
    first = _reserve(storage, manifest, grant).invocation_ref
    current = manifests.load_campaign_manifest(storage, manifest.campaign_ref, repo_root=REPO)
    queries, barrier, gate = _queries(current), Barrier(2), Lock()
    original = subject.claim_campaign_grant_submission
    for item in current.items[:2]:
        recovery = subject.campaign_metadata_recovery_ref(PROFILE, queries[item.work_ref].criteria_hash())
        manifests.bind_campaign_manifest_recovery(
            storage, manifest.campaign_ref, item.work_ref, recovery, repo_root=REPO,
        )
    current = manifests.load_campaign_manifest(storage, manifest.campaign_ref, repo_root=REPO)

    def race(*args, **kwargs):
        if args[4] == current.items[0].work_ref:
            barrier.wait()
        with gate:
            return original(*args, **kwargs)

    monkeypatch.setattr(subject, "claim_campaign_grant_invocation", lambda *a, **k: None)
    monkeypatch.setattr(subject, "load_campaign_manifest", lambda *a, **k: current)
    original_load = subject.load_campaign_grant

    def load_grant(*args, **kwargs):
        with gate:
            return original_load(*args, **kwargs)

    monkeypatch.setattr(subject, "load_campaign_grant", load_grant)
    monkeypatch.setattr(subject, "claim_campaign_grant_submission", race)
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = tuple(pool.map(
            lambda invocation: _prepare(storage, manifest, grant, queries, invocation),
            (first, first),
        ))
    allowed = [item.work_ref for result in results for item in result.actions
               if item.action is subject.CampaignSubmissionAction.SUBMISSION_ALLOWED]
    withheld = [item.work_ref for result in results for item in result.actions
                if item.action in {
                    subject.CampaignSubmissionAction.ORPHAN_UNCERTAIN,
                    subject.CampaignSubmissionAction.SUBMISSION_DEFERRED,
                }]
    assert all(allowed.count(item.work_ref) == 1 for item in current.items[:2])
    assert all(withheld.count(item.work_ref) == 1 for item in current.items[:2])
    loaded = grants.load_campaign_grant(storage, grant.grant_ref, REPO, now=NOW)
    assert len(loaded.submission_claims) == 2
