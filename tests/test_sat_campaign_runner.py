from __future__ import annotations

import ast
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from threading import Barrier, Event

import pytest

import cfdi_vault.sat_campaign_grant as grants
import cfdi_vault.sat_campaign_manifest_store as manifests
import cfdi_vault.sat_campaign_runner as subject
import cfdi_vault.secure_state_file as secure_state
from cfdi_vault.sat_campaign_manifest import (
    CampaignWorkState,
    SatCampaignManifest,
    build_campaign_manifest,
)

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
    assert "cfdi_vault.domain" not in imported
