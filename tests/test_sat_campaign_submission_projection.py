from __future__ import annotations

import ast
import inspect
import json
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

import cfdi_vault.sat_campaign_grant as grants
import cfdi_vault.sat_campaign_submission_projection as subject
from cfdi_vault.sat_campaign_manifest import (
    CampaignWorkState,
    bind_campaign_recovery,
    build_campaign_manifest,
    reserve_campaign_work,
)
from cfdi_vault.sat_campaign_manifest_store import campaign_manifest_state_path, initialize_campaign_manifest
from cfdi_vault.sat_campaign_query import build_metadata_query_for_work
from cfdi_vault.sat_contract import SatOutcomeAction, SatRequestResult
from cfdi_vault.sat_metadata_recovery_state import (
    MetadataRecoveryStateError,
    campaign_metadata_recovery_ref,
    metadata_recovery_state_path,
)
from cfdi_vault.sat_metadata_submission import (
    MetadataSubmissionProjection,
    SubmissionFailureCategory,
    SubmissionStatus,
    metadata_submission_claim_path,
    submit_metadata_recovery_once,
)
from cfdi_vault.setup_core import CredentialMode, LocalProfile, LocalProfileStatus

NOW, PROFILE, COMMIT = datetime(2026, 7, 16, tzinfo=timezone.utc), "profile-synthetic", "a" * 40


def test_expired_real_failure_projects_one_atomic_restart_safe_split(tmp_path, monkeypatch) -> None:
    ctx = _context(tmp_path, monkeypatch)
    def attempt():
        try:
            return subject.project_persisted_campaign_submission(**ctx.arguments)
        except subject.CampaignSubmissionProjectionError as error:
            return error
    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = tuple(pool.map(lambda _: attempt(), range(2)))
    assert all(isinstance(item, (subject.CampaignSubmissionProjectionError,
                                 type(ctx.manifest))) for item in outcomes)
    projected = subject.project_persisted_campaign_submission(**ctx.arguments)
    parent = _item(projected, ctx.work_ref)
    children = tuple(item for item in projected.items if item.parent_ref == ctx.work_ref)
    assert (parent.state is CampaignWorkState.SPLIT and PROFILE not in repr(projected)
            and ctx.recovery_ref not in repr(projected))
    assert len(children) == 2 and all(item.depth == 1 for item in children)
    assert subject.project_persisted_campaign_submission(**ctx.arguments) == projected

@pytest.mark.parametrize(("status", "category", "recovery"), (
    (SubmissionStatus.CLAIMED, None, "unused"),
    (SubmissionStatus.SUBMIT_UNCERTAIN, SubmissionFailureCategory.SUBMIT_UNCERTAIN, "unused"),
    (SubmissionStatus.ACCEPTED, None, "exact"),
    (SubmissionStatus.ACCEPTED, None, "missing"),
))
def test_nonfailed_outcomes_never_mutate_manifest_or_recovery_bytes(
    tmp_path, monkeypatch, status, category, recovery,
) -> None:
    ctx = _context(tmp_path, monkeypatch)
    monkeypatch.setattr(subject, "load_metadata_submission_projection", lambda *args, **kwargs:
                        MetadataSubmissionProjection(status, category))
    if recovery == "exact":
        monkeypatch.setattr(subject, "load_metadata_recovery_state", lambda *args, **kwargs: ctx.record)
    elif recovery == "missing":
        monkeypatch.setattr(subject, "load_metadata_recovery_state", lambda *args, **kwargs:
                            (_ for _ in ()).throw(MetadataRecoveryStateError("recovery-state-not-found")))
    recovery_path = metadata_recovery_state_path(ctx.storage, repo_root=ctx.repo)
    recovery_path.write_bytes(b"unchanged-private-state")
    before = ctx.manifest_path.read_bytes()
    assert subject.project_persisted_campaign_submission(**ctx.arguments) == ctx.manifest
    assert ctx.manifest_path.read_bytes() == before
    assert recovery_path.read_bytes() == b"unchanged-private-state"

@pytest.mark.parametrize("mismatch", (
    "future", "head", "profile", "work", "grant", "recovery", "collision", "query",
))
def test_every_lineage_mismatch_fails_redacted_before_manifest_write(
    tmp_path, monkeypatch, mismatch,
) -> None:
    ctx = _context(tmp_path, monkeypatch)
    if mismatch == "future":
        ctx.arguments["now"] = NOW - timedelta(seconds=1)
    elif mismatch == "head":
        monkeypatch.setattr(grants, "_repository_context", lambda _root: (ctx.repo.resolve(), "b" * 40))
    elif mismatch == "profile":
        ctx.arguments["profile"] = replace(ctx.profile, profile_id="profile-other")
    elif mismatch == "work":
        ctx.arguments["work_ref"] = ctx.manifest.items[1].work_ref
    elif mismatch == "grant":
        ctx.arguments["grant_ref"] = "grt-" + "f" * 24
    elif mismatch in {"recovery", "collision"}:
        document = json.loads(ctx.grant_path.read_bytes())
        claim = document["submissionClaims"][0]
        claim["recoveryRef"] = "run-" + "f" * 12
        if mismatch == "collision":
            other = dict(claim)
            other["workRef"] = ctx.manifest.items[1].work_ref
            other["recoveryRef"] = ctx.recovery_ref
            document["submissionClaims"].append(other)
        ctx.grant_path.write_text(json.dumps(document), encoding="utf-8")
    else:
        document = json.loads(ctx.submission_path.read_bytes())
        document["claims"][0]["query"]["requesterRfc"] = "XAXX010101000"
        ctx.submission_path.write_text(json.dumps(document), encoding="utf-8")
    before = ctx.manifest_path.read_bytes()
    with pytest.raises(subject.CampaignSubmissionProjectionError) as captured:
        subject.project_persisted_campaign_submission(**ctx.arguments)
    assert captured.value.reason.startswith("campaign-projection-")
    assert str(ctx.storage) not in str(captured.value)
    assert ctx.manifest_path.read_bytes() == before

def test_projection_has_no_effect_event_dependency_and_redacts_repr() -> None:
    imports = {node.module or "" for node in ast.walk(ast.parse(inspect.getsource(subject)))
               if isinstance(node, ast.ImportFrom)}
    assert not any("submission_effect" in name for name in imports)
    assert "private" not in repr(subject.CampaignSubmissionProjectionError(
        "campaign-projection-lineage-invalid"))


class _Requester:
    def submit_request(self, _query):
        return SatRequestResult("", "5003", "synthetic", SatOutcomeAction.PERMANENT_FAILURE)


def _context(tmp_path, monkeypatch):
    repo, storage = tmp_path / "repo", tmp_path / "storage"
    repo.mkdir()
    monkeypatch.setattr(grants, "_repository_context", lambda _root: (repo.resolve(), COMMIT))
    profile = LocalProfile(PROFILE, "AAA010101AAA", storage, CredentialMode.REFERENCED,
                           storage / "synthetic.cer", storage / "synthetic.key",
                           "test-provider://synthetic", LocalProfileStatus.READY, "0" * 64)
    manifest = reserve_campaign_work(build_campaign_manifest(PROFILE))
    work = manifest.items[0]
    query = build_metadata_query_for_work(manifest, profile, work.work_ref)
    recovery_ref = campaign_metadata_recovery_ref(PROFILE, query.criteria_hash())
    manifest = bind_campaign_recovery(manifest, work.work_ref, recovery_ref=recovery_ref)
    initialize_campaign_manifest(storage, manifest, repo_root=repo)
    grant = grants.create_campaign_grant(
        storage, manifest, PROFILE, COMMIT, repo, "metadata proof", timedelta(days=1), now=NOW)
    invocation_ref = "inv-" + "1" * 24
    grants.claim_campaign_grant_invocation(
        storage, grant.grant_ref, invocation_ref, PROFILE, repo, now=NOW)
    grants.claim_campaign_grant_submission(
        storage, grant.grant_ref, invocation_ref, manifest, work.work_ref,
        recovery_ref, PROFILE, repo, now=NOW)
    submit_metadata_recovery_once(
        requester=_Requester(), query=query, now=NOW, storage_root=storage,
        profile_id=PROFILE, criteria_hash=query.criteria_hash(), authorization_ref=grant.grant_ref,
        tested_commit=COMMIT, entry_point="sat-campaign", expected_recovery_ref=recovery_ref,
        repo_root=repo)
    period = query.period
    record = SimpleNamespace(
        recovery=SimpleNamespace(recovery_ref=recovery_ref), profile_id=PROFILE,
        criteria_hash=query.criteria_hash(), direction=query.direction.value,
        kind=query.request_type.value, fecha_inicial=period.start.date().isoformat(),
        fecha_final=period.end.date().isoformat(), authorization_ref=grant.grant_ref)
    arguments = dict(storage_root=storage, repo_root=repo, campaign_ref=manifest.campaign_ref,
                     grant_ref=grant.grant_ref, profile=profile, work_ref=work.work_ref,
                     now=NOW + timedelta(days=2))
    return SimpleNamespace(
        repo=repo, storage=storage, profile=profile, manifest=manifest, record=record,
        work_ref=work.work_ref, recovery_ref=recovery_ref, arguments=arguments,
        manifest_path=campaign_manifest_state_path(storage, manifest.campaign_ref, repo_root=repo),
        grant_path=next(storage.rglob(grants._filename(grant.grant_ref))),  # noqa: SLF001
        submission_path=metadata_submission_claim_path(storage, repo_root=repo))


def _item(manifest, work_ref):
    return next(item for item in manifest.items if item.work_ref == work_ref)
