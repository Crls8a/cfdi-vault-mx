from __future__ import annotations

import json
from dataclasses import fields, replace
from datetime import datetime, timedelta, timezone
from inspect import signature
from types import SimpleNamespace

import pytest

import cfdi_vault.sat_campaign_grant as grants
import cfdi_vault.sat_campaign_recovery_projection as subject
import cfdi_vault.sat_metadata_recovery as lifecycle
import cfdi_vault.sat_metadata_recovery_runner as runner
import cfdi_vault.sat_metadata_recovery_state as state
from cfdi_vault.domain import DownloadDirection
from cfdi_vault.sat_campaign_manifest import (
    CampaignWorkState,
    apply_campaign_submission_failure,
    bind_campaign_recovery,
    build_campaign_manifest,
    reserve_campaign_work,
)
from cfdi_vault.sat_campaign_manifest_store import (
    CampaignManifestStoreError,
    campaign_manifest_state_path,
    initialize_campaign_manifest,
)
from cfdi_vault.sat_campaign_query import build_metadata_query_for_work
from cfdi_vault.setup_core import CredentialMode, LocalProfile, LocalProfileStatus

NOW, PROFILE, COMMIT = datetime(2026, 7, 16, tzinfo=timezone.utc), "profile-synthetic", "a" * 40


@pytest.mark.parametrize("status", ("scheduled", "packages"))
def test_nonterminal_verified_state_is_unchanged_and_idempotent(tmp_path, monkeypatch, status) -> None:
    assert set(signature(subject.project_persisted_campaign_recovery).parameters) == {"storage_root", "repo_root", "campaign_ref", "grant_ref", "profile", "work_ref", "now"}
    ctx = _context(tmp_path, monkeypatch, status)
    before = ctx.path.read_bytes()
    assert subject.project_persisted_campaign_recovery(**ctx.args) == ctx.manifest
    assert subject.project_persisted_campaign_recovery(**ctx.args) == ctx.manifest
    assert ctx.path.read_bytes() == before


@pytest.mark.parametrize(
    ("status", "expected"),
    (("no_data", CampaignWorkState.NO_DATA), ("budget", CampaignWorkState.FAILED),
     ("failed", CampaignWorkState.FAILED), ("uncertain", CampaignWorkState.FAILED)),
)
def test_terminal_state_projects_once_and_replays_exactly(tmp_path, monkeypatch, status, expected) -> None:
    ctx = _context(tmp_path, monkeypatch, status)
    projected = subject.project_persisted_campaign_recovery(**ctx.args)
    assert _item(projected, ctx.work_ref).state is expected
    assert subject.project_persisted_campaign_recovery(**ctx.args) == projected


@pytest.mark.parametrize(("depth", "expected"), ((0, CampaignWorkState.SPLIT),
                                                   (1, CampaignWorkState.THRESHOLD_BLOCKED)))
def test_exact_persisted_5003_is_the_only_split_authority(tmp_path, monkeypatch, depth, expected) -> None:
    ctx = _context(tmp_path, monkeypatch, "5003", depth=depth)
    projected = subject.project_persisted_campaign_recovery(**ctx.args)
    parent = _item(projected, ctx.work_ref)
    assert parent.state is expected and parent.evidence == "sat_too_many_results"
    if depth == 0:
        assert len(tuple(item for item in projected.items if item.parent_ref == ctx.work_ref)) == 2
    assert subject.project_persisted_campaign_recovery(**ctx.args) == projected


@pytest.mark.parametrize("category", (None, "sat_too_many_results", state.MetadataVerifyErrorKind.VERIFY_RETRYABLE))
def test_missing_forged_or_inconsistent_category_cannot_split(tmp_path, monkeypatch, category) -> None:
    ctx = _context(tmp_path, monkeypatch, "5003")
    monkeypatch.setattr(subject, "load_metadata_recovery_state",
                        lambda *a, **k: _tamper(ctx.record, last_verify_error_kind=category))
    before = ctx.path.read_bytes()
    with pytest.raises(subject.CampaignRecoveryProjectionError, match="campaign-recovery-projection-state-invalid"):
        subject.project_persisted_campaign_recovery(**ctx.args)
    assert ctx.path.read_bytes() == before


@pytest.mark.parametrize("conflict", (
    "campaign", "profile", "work", "grant", "claim", "recovery", "criteria", "direction", "kind", "date", "query",
))
def test_every_lineage_binding_conflict_is_redacted_and_read_only(tmp_path, monkeypatch, conflict) -> None:
    ctx = _context(tmp_path, monkeypatch, "no_data")
    argument_conflicts = {"campaign": ("campaign_ref", "cmp-" + "f" * 12), "profile": ("profile", replace(ctx.profile, profile_id="profile-other")), "work": ("work_ref", ctx.manifest.items[1].work_ref), "grant": ("grant_ref", "grt-" + "f" * 24)}
    if conflict in argument_conflicts:
        key, value = argument_conflicts[conflict]
        ctx.args[key] = value
    elif conflict == "claim":
        document = json.loads(ctx.grant_path.read_bytes())
        document["submissionClaims"][0]["recoveryRef"] = "run-" + "f" * 12
        ctx.grant_path.write_text(json.dumps(document), encoding="utf-8")
    elif conflict == "query":
        monkeypatch.setattr(subject, "build_metadata_query_for_work",
                            lambda *a: replace(ctx.query, direction=DownloadDirection.ISSUED))
    else:
        updates = {"recovery": replace(ctx.record.recovery, recovery_ref="run-" + "f" * 12)} if conflict == "recovery" else {
            "criteria_hash": "f" * 64} if conflict == "criteria" else {"direction": "issued"} if conflict == "direction" else {
            "kind": "cfdi"} if conflict == "kind" else {"fecha_final": "2026-01-13"}
        monkeypatch.setattr(subject, "load_metadata_recovery_state", lambda *a, **k: _tamper(ctx.record, **updates))
    before = ctx.path.read_bytes()
    with pytest.raises(subject.CampaignRecoveryProjectionError) as captured:
        subject.project_persisted_campaign_recovery(**ctx.args)
    assert captured.value.reason.startswith("campaign-recovery-projection-") and captured.value.retry_safe
    assert all(value not in repr(captured.value) for value in (str(ctx.storage), PROFILE, ctx.recovery_ref))
    assert ctx.path.read_bytes() == before


def test_malformed_private_state_and_download_owned_states_fail_closed(tmp_path, monkeypatch) -> None:
    ctx = _context(tmp_path, monkeypatch, "packages")
    for malformed in (SimpleNamespace(), _tamper(ctx.record, recovery=replace(
            ctx.record.recovery, status=lifecycle.RecoveryStatus.COMPLETED))):
        monkeypatch.setattr(subject, "load_metadata_recovery_state", lambda *a, value=malformed, **k: value)
        with pytest.raises(subject.CampaignRecoveryProjectionError):
            subject.project_persisted_campaign_recovery(**ctx.args)


def test_atomic_store_error_flags_are_preserved_without_private_error_text(tmp_path, monkeypatch) -> None:
    ctx = _context(tmp_path, monkeypatch, "no_data")
    monkeypatch.setattr(subject, "record_campaign_manifest_result", lambda *a, **k: (_ for _ in ()).throw(
        CampaignManifestStoreError("PRIVATE", committed=True, uncertain=True)))
    with pytest.raises(subject.CampaignRecoveryProjectionError) as captured:
        subject.project_persisted_campaign_recovery(**ctx.args)
    assert (captured.value.reason, captured.value.committed, captured.value.uncertain,
            captured.value.retry_safe) == ("campaign-recovery-projection-write-failed", True, True, False)
    assert "PRIVATE" not in repr(captured.value)


def _context(tmp_path, monkeypatch, outcome: str, *, depth: int = 0):
    repo, storage = tmp_path / "repo", tmp_path / "storage"
    repo.mkdir()
    monkeypatch.setattr(grants, "_repository_context", lambda _root: (repo.resolve(), COMMIT))
    profile = LocalProfile(PROFILE, "AAA010101AAA", storage, CredentialMode.REFERENCED,
                           storage / "synthetic.cer", storage / "synthetic.key",
                           "test-provider://synthetic", LocalProfileStatus.READY, "0" * 64)
    manifest = reserve_campaign_work(build_campaign_manifest(PROFILE))
    work = manifest.items[0]
    if depth:
        query = build_metadata_query_for_work(manifest, profile, work.work_ref)
        parent_ref = state.campaign_metadata_recovery_ref(PROFILE, query.criteria_hash())
        manifest = bind_campaign_recovery(manifest, work.work_ref, recovery_ref=parent_ref)
        manifest = apply_campaign_submission_failure(manifest, work.work_ref, parent_ref, "sat_too_many_results")
        manifest = reserve_campaign_work(manifest)
        work = next(item for item in manifest.items if item.depth == 1 and item.state is CampaignWorkState.OUTSTANDING)
    query = build_metadata_query_for_work(manifest, profile, work.work_ref)
    recovery_ref = state.campaign_metadata_recovery_ref(PROFILE, query.criteria_hash())
    manifest = bind_campaign_recovery(manifest, work.work_ref, recovery_ref=recovery_ref)
    initialize_campaign_manifest(storage, manifest, repo_root=repo)
    grant = grants.create_campaign_grant(storage, manifest, PROFILE, COMMIT, repo, "metadata proof",
                                         timedelta(hours=1), now=NOW)
    invocation = "inv-" + "1" * 24
    grants.claim_campaign_grant_invocation(storage, grant.grant_ref, invocation, PROFILE, repo, now=NOW)
    grants.claim_campaign_grant_submission(storage, grant.grant_ref, invocation, manifest, work.work_ref,
                                           recovery_ref, PROFILE, repo, now=NOW)
    assert (period := query.period) is not None
    recovery = lifecycle.start_metadata_recovery(recovery_ref, created_at=NOW)
    record = state.new_metadata_recovery_state(
        recovery=recovery, id_solicitud="synthetic-request", profile_id=PROFILE,
        direction=query.direction.value, kind=query.request_type.value,
        fecha_inicial=period.start.date().isoformat(), fecha_final=period.end.date().isoformat(),
        criteria_hash=query.criteria_hash(), authorization_ref=grant.grant_ref,
        observation_provenance=state.new_metadata_observation_provenance(
            tested_commit=COMMIT, observed_at=NOW, entry_point="sat-campaign"))
    state.save_metadata_recovery_state(storage, record, repo_root=repo)
    record = _persist_outcome(storage, repo, record, outcome)
    args = dict(storage_root=storage, repo_root=repo, campaign_ref=manifest.campaign_ref,
                grant_ref=grant.grant_ref, profile=profile, work_ref=work.work_ref,
                now=NOW + timedelta(hours=2))
    return SimpleNamespace(repo=repo, storage=storage, profile=profile, manifest=manifest,
                           work_ref=work.work_ref, query=query, recovery_ref=recovery_ref,
                           record=record, args=args, path=campaign_manifest_state_path(
                               storage, manifest.campaign_ref, repo_root=repo),
                           grant_path=next(storage.rglob(grants._filename(grant.grant_ref))))


def _persist_outcome(storage, repo, record, outcome):
    if outcome == "scheduled":
        return record
    if outcome == "budget":
        record = replace(record, recovery=lifecycle.apply_recovery_deadline(
            record.recovery, now=record.recovery.deadline_at))
    else:
        assert (due := record.recovery.next_check_at) is not None
        claimed = runner._claim_verification(record, COMMIT, "sat-campaign", due, due)  # noqa: SLF001
        state.save_metadata_recovery_state(storage, claimed, repo_root=repo)
        base = runner._verification_base(claimed)  # noqa: SLF001
        kind = None
        if outcome in {"packages", "no_data"}:
            packages = (state.package_ref("synthetic-package"),) if outcome == "packages" else ()
            recovery = lifecycle.record_finished_verification(base.recovery, checked_at=due,
                                                               package_refs=packages, record_count=None)
            bindings = (state.PackageIdBinding(packages[0], "synthetic-package"),) if packages else ()
            base = _tamper(base, package_bindings=bindings)
        else:
            recovery = lifecycle.record_verification_failure(base.recovery, checked_at=due)
            kind = {"5003": state.MetadataVerifyErrorKind.SAT_TOO_MANY_RESULTS,
                    "failed": state.MetadataVerifyErrorKind.VERIFY_FAILED,
                    "uncertain": state.MetadataVerifyErrorKind.VERIFY_UNCERTAIN}[outcome]
        record = runner._resolve_verification_claim(  # noqa: SLF001
            base, recovery, kind, COMMIT, "sat-campaign", due,
            0 if outcome in {"packages", "no_data"} else None)
    state.save_metadata_recovery_state(storage, record, repo_root=repo)
    return record


def _tamper(record, **updates):
    clone = object.__new__(type(record))
    for field in fields(record):
        object.__setattr__(clone, field.name, updates.get(field.name, getattr(record, field.name)))
    return clone


def _item(manifest, work_ref):
    return next(item for item in manifest.items if item.work_ref == work_ref)
