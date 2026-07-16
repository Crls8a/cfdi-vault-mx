from __future__ import annotations

import re
from dataclasses import FrozenInstanceError, replace
from datetime import date, timedelta

import pytest

from cfdi_vault.sat_campaign_manifest import (
    CampaignManifestError,
    CampaignWorkState,
    SatCampaignManifest,
    build_campaign_manifest,
    campaign_redacted_summary,
    record_campaign_result,
    reserve_campaign_work,
    split_campaign_work,
)

PROFILE = "profile-synthetic"
RUN_REF = "run-000000000000"
SECOND_RUN_REF = "run-000000000001"


class _EvidenceImpostor:
    def __eq__(self, other: object) -> bool:
        raise RuntimeError("hostile equality")


class _EvidenceAlias(str):
    pass


class _CampaignRefImpostor:
    def __eq__(self, other: object) -> bool:
        raise RuntimeError("hostile campaign ref equality")


class _CampaignRefAlias(str):
    pass


def _work(manifest, ref):  # type: ignore[no-untyped-def]
    return next(item for item in manifest.items if item.work_ref == ref)
def test_fixed_campaign_builds_exact_deterministic_base_manifest() -> None:
    manifest = build_campaign_manifest(PROFILE)
    same = build_campaign_manifest(PROFILE)
    windows = tuple((date(2026, 1, 1) + timedelta(days=14 * index), date(2026, 1, 14) + timedelta(days=14 * index)) for index in range(14))
    assert (manifest.schema_version, manifest.policy_version, manifest.profile_id) == (1, 1, PROFILE)
    assert (manifest.start, manifest.end, manifest.window_days) == (date(2026, 1, 1), date(2026, 7, 15), 14)
    assert tuple(item.value for item in manifest.directions) == ("received", "issued")
    assert (manifest.kind.value, manifest.max_outstanding, manifest.max_split_depth) == ("metadata", 2, 1)
    assert len(manifest.items) == 28 and manifest.items == same.items
    assert build_campaign_manifest("profile-other").campaign_ref != manifest.campaign_ref
    assert re.fullmatch(r"cmp-[0-9a-f]{12}", manifest.campaign_ref)
    assert len({item.work_ref for item in manifest.items}) == 28
    assert all(re.fullmatch(r"work-[0-9a-f]{12}", item.work_ref) for item in manifest.items)
    assert [(item.start, item.end, item.direction.value) for item in manifest.items] == [
        (start, end, direction) for start, end in windows for direction in ("received", "issued")
    ]
    assert PROFILE not in repr(manifest)
def test_reservation_and_results_are_pure_bounded_and_recovery_ref_is_immutable() -> None:
    original = build_campaign_manifest(PROFILE)
    reserved = reserve_campaign_work(original)
    outstanding = tuple(item for item in reserved.items if item.state is CampaignWorkState.OUTSTANDING)
    assert [item.direction.value for item in outstanding] == ["received", "issued"]
    assert all(item.start == date(2026, 1, 1) for item in outstanding)
    assert reserve_campaign_work(reserved) == reserved
    assert all(item.state is CampaignWorkState.PLANNED for item in original.items)
    completed = record_campaign_result(reserved, outstanding[0].work_ref, CampaignWorkState.COMPLETED, recovery_ref=RUN_REF)
    assert _work(completed, outstanding[0].work_ref).recovery_ref == RUN_REF
    assert _work(reserved, outstanding[0].work_ref).recovery_ref is None
    refilled = reserve_campaign_work(completed)
    assert sum(item.state is CampaignWorkState.OUTSTANDING for item in refilled.items) == 2
    with pytest.raises(CampaignManifestError, match="work-not-outstanding"):
        record_campaign_result(completed, outstanding[0].work_ref, CampaignWorkState.NO_DATA, recovery_ref="run-111111111111")
def test_threshold_split_creates_exact_children_and_children_cannot_split() -> None:
    reserved = reserve_campaign_work(build_campaign_manifest(PROFILE))
    parent = next(item for item in reserved.items if item.direction.value == "received")
    blocked = record_campaign_result(
        reserved, parent.work_ref, CampaignWorkState.THRESHOLD_BLOCKED,
        recovery_ref=RUN_REF, evidence="sat_too_many_results",
    )
    split = split_campaign_work(blocked, parent.work_ref)
    parent_after = _work(split, parent.work_ref)
    children = tuple(item for item in split.items if item.parent_ref == parent.work_ref)
    assert parent_after.state is CampaignWorkState.SPLIT and parent_after.recovery_ref == RUN_REF
    assert [(item.start, item.end, item.depth) for item in children] == [
        (date(2026, 1, 1), date(2026, 1, 7), 1), (date(2026, 1, 8), date(2026, 1, 14), 1)]
    assert len(split.items) == 30
    child_outstanding = next(item for item in reserve_campaign_work(split).items
                             if item.parent_ref == parent.work_ref and item.state is CampaignWorkState.OUTSTANDING)
    child_blocked = record_campaign_result(
        reserve_campaign_work(split), child_outstanding.work_ref,
        CampaignWorkState.THRESHOLD_BLOCKED, recovery_ref="run-111111111111",
        evidence="sat_too_many_results",
    )
    with pytest.raises(CampaignManifestError, match="split-depth-invalid"):
        split_campaign_work(child_blocked, child_outstanding.work_ref)
def test_all_approved_splits_stop_at_eighty_four_requests_and_fifty_six_leaves() -> None:
    manifest = build_campaign_manifest(PROFILE)
    run_number = 0
    while any(item.depth == 0 and item.state is CampaignWorkState.PLANNED for item in manifest.items):
        manifest = reserve_campaign_work(manifest)
        for item in tuple(i for i in manifest.items if i.state is CampaignWorkState.OUTSTANDING):
            state = CampaignWorkState.THRESHOLD_BLOCKED if item.depth == 0 else CampaignWorkState.NO_DATA
            manifest = record_campaign_result(
                manifest, item.work_ref, state, recovery_ref=f"run-{run_number:012x}",
                evidence="sat_too_many_results" if item.depth == 0 else None,
            )
            run_number += 1
            if item.depth == 0:
                manifest = split_campaign_work(manifest, item.work_ref)
    while any(item.state is CampaignWorkState.PLANNED for item in manifest.items):
        manifest = reserve_campaign_work(manifest)
        for item in tuple(i for i in manifest.items if i.state is CampaignWorkState.OUTSTANDING):
            manifest = record_campaign_result(
                manifest, item.work_ref, CampaignWorkState.NO_DATA,
                recovery_ref=f"run-{run_number:012x}",
            )
            run_number += 1
    summary = campaign_redacted_summary(manifest)
    assert (summary["baseCount"], summary["splitCount"], summary["leafCount"], summary["totalCount"]) == (28, 28, 56, 84)
    assert summary["outstandingCount"] == 0 and summary["terminalCount"] == 84
@pytest.mark.parametrize("bad_profile", (True, "", "x" * 65, "profile/unsafe"))
def test_hostile_types_and_mutated_snapshots_fail_closed(bad_profile: object) -> None:
    with pytest.raises(CampaignManifestError):
        build_campaign_manifest(bad_profile)  # type: ignore[arg-type]
    manifest = build_campaign_manifest(PROFILE)
    with pytest.raises(FrozenInstanceError):
        manifest.profile_id = "changed"  # type: ignore[misc]
    object.__setattr__(manifest.items[0], "depth", True)
    with pytest.raises(CampaignManifestError):
        campaign_redacted_summary(manifest)
def test_invalid_transitions_and_redacted_summary_exclude_all_private_dimensions() -> None:
    manifest = build_campaign_manifest(PROFILE)
    first = manifest.items[0]
    with pytest.raises(CampaignManifestError, match="work-not-outstanding"):
        record_campaign_result(manifest, first.work_ref, CampaignWorkState.COMPLETED, recovery_ref=RUN_REF)
    reserved = reserve_campaign_work(manifest)
    with pytest.raises(CampaignManifestError, match="recovery-ref-invalid"):
        record_campaign_result(reserved, first.work_ref, CampaignWorkState.COMPLETED, recovery_ref="hostile")
    with pytest.raises(CampaignManifestError, match="result-state-invalid"):
        record_campaign_result(reserved, first.work_ref, CampaignWorkState.PLANNED, recovery_ref=RUN_REF)
    with pytest.raises(CampaignManifestError, match="threshold-evidence-invalid"):
        record_campaign_result(reserved, first.work_ref, CampaignWorkState.THRESHOLD_BLOCKED,
                               recovery_ref=RUN_REF, evidence="hostile-evidence")
    completed = record_campaign_result(
        reserved, first.work_ref, CampaignWorkState.COMPLETED, recovery_ref=RUN_REF,
    )
    summary = campaign_redacted_summary(completed)
    assert set(summary) == {"campaignRef", "stateCounts", "baseCount", "splitCount", "leafCount",
                            "totalCount", "outstandingCount", "terminalCount"}
    rendered = repr(summary)
    for private in (PROFILE, "2026-01-01", "received", first.work_ref, RUN_REF, "sat_too_many_results"):
        assert private not in rendered


@pytest.mark.parametrize("evidence", ([], _EvidenceImpostor(), _EvidenceAlias("sat_too_many_results")))
def test_result_evidence_requires_exact_immutable_builtin_type(evidence: object) -> None:
    reserved = reserve_campaign_work(build_campaign_manifest(PROFILE))
    first = reserved.items[0]
    with pytest.raises(CampaignManifestError, match="result-evidence-invalid"):
        record_campaign_result(
            reserved, first.work_ref, CampaignWorkState.THRESHOLD_BLOCKED,
            recovery_ref=RUN_REF, evidence=evidence,  # type: ignore[arg-type]
        )


def test_hostile_snapshot_evidence_comparison_is_sanitized() -> None:
    reserved = reserve_campaign_work(build_campaign_manifest(PROFILE))
    first = reserved.items[0]
    blocked = record_campaign_result(
        reserved, first.work_ref, CampaignWorkState.THRESHOLD_BLOCKED,
        recovery_ref=RUN_REF, evidence="sat_too_many_results",
    )
    object.__setattr__(_work(blocked, first.work_ref), "evidence", _EvidenceImpostor())
    with pytest.raises(CampaignManifestError, match="work-evidence-invalid"):
        campaign_redacted_summary(blocked)


def test_recovery_refs_are_unique_across_transitions_and_reconstructed_snapshots() -> None:
    reserved = reserve_campaign_work(build_campaign_manifest(PROFILE))
    first, second = (item for item in reserved.items if item.state is CampaignWorkState.OUTSTANDING)
    once = record_campaign_result(
        reserved, first.work_ref, CampaignWorkState.COMPLETED, recovery_ref=RUN_REF,
    )
    with pytest.raises(CampaignManifestError, match="recovery-ref-duplicate"):
        record_campaign_result(
            once, second.work_ref, CampaignWorkState.NO_DATA, recovery_ref=RUN_REF,
        )
    complete = record_campaign_result(
        once, second.work_ref, CampaignWorkState.NO_DATA, recovery_ref=SECOND_RUN_REF,
    )
    hostile_items = tuple(
        replace(item, recovery_ref=RUN_REF) if item.work_ref == second.work_ref else item
        for item in complete.items
    )
    with pytest.raises(CampaignManifestError, match="recovery-ref-duplicate"):
        replace(complete, items=hostile_items)


def test_splits_preserve_and_enforce_global_canonical_item_order() -> None:
    manifest = reserve_campaign_work(build_campaign_manifest(PROFILE))
    outstanding = tuple(item for item in manifest.items if item.state is CampaignWorkState.OUTSTANDING)
    for item, recovery_ref in zip(outstanding, (RUN_REF, SECOND_RUN_REF), strict=True):
        manifest = record_campaign_result(
            manifest, item.work_ref, CampaignWorkState.THRESHOLD_BLOCKED,
            recovery_ref=recovery_ref, evidence="sat_too_many_results",
        )
        manifest = split_campaign_work(manifest, item.work_ref)
    rank = {"received": 0, "issued": 1}
    priorities = [
        (item.start, rank[item.direction.value], item.depth, item.end, item.work_ref)
        for item in manifest.items
    ]
    assert priorities == sorted(priorities)
    assert max(index for index, item in enumerate(manifest.items) if item.parent_ref) < next(
        index for index, item in enumerate(manifest.items) if item.start == date(2026, 1, 15)
    )
    bases_then_children = tuple(item for item in manifest.items if item.depth == 0) + tuple(
        item for item in manifest.items if item.depth == 1
    )
    with pytest.raises(CampaignManifestError, match="campaign-item-order-invalid"):
        replace(manifest, items=bases_then_children)


def test_constructor_rejects_campaign_ref_equality_impostor() -> None:
    manifest = build_campaign_manifest(PROFILE)
    with pytest.raises(CampaignManifestError, match="campaign-ref-invalid"):
        SatCampaignManifest(
            _CampaignRefImpostor(), manifest.profile_id, manifest.items,  # type: ignore[arg-type]
        )


def test_reconstruction_rejects_campaign_ref_string_subclass() -> None:
    manifest = build_campaign_manifest(PROFILE)
    with pytest.raises(CampaignManifestError, match="campaign-ref-invalid"):
        replace(manifest, campaign_ref=_CampaignRefAlias(manifest.campaign_ref))


def test_mutated_campaign_ref_equality_failure_is_sanitized() -> None:
    manifest = build_campaign_manifest(PROFILE)
    object.__setattr__(manifest, "campaign_ref", _CampaignRefImpostor())
    with pytest.raises(CampaignManifestError, match="campaign-ref-invalid"):
        campaign_redacted_summary(manifest)
