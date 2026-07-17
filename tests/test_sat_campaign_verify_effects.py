from __future__ import annotations

import ast
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

import cfdi_vault.sat_campaign_manifest as policy
import cfdi_vault.sat_campaign_verify_effects as subject
from cfdi_vault.sat_campaign_recovery_projection import CampaignRecoveryProjectionError
from cfdi_vault.sat_metadata_recovery_runner import MetadataRecoveryAdvanceOutcome
from cfdi_vault.sat_metadata_recovery_state import MetadataRecoveryStateError
from cfdi_vault.setup_core import CredentialMode, LocalProfile, LocalProfileStatus

NOW = datetime(2026, 7, 16, 12, tzinfo=timezone.utc)
PROFILE, COMMIT = "synthetic-profile", "a" * 40


def _profile(root: Path) -> LocalProfile:
    return LocalProfile(
        PROFILE, "AAA010101AAA", root, CredentialMode.REFERENCED, root / "synthetic.cer",
        root / "synthetic.key", "test-provider://synthetic", LocalProfileStatus.READY, "0" * 64)


def _manifest(count: int = 2, *, bound: bool = True):  # type: ignore[no-untyped-def]
    manifest = policy.reserve_campaign_work(policy.build_campaign_manifest(PROFILE))
    outstanding = tuple(item for item in manifest.items if item.state is policy.CampaignWorkState.OUTSTANDING)
    if count < 2:
        inactive = {item.work_ref for item in outstanding[count:]}
        manifest = replace(manifest, items=tuple(
            replace(item, state=policy.CampaignWorkState.PLANNED) if item.work_ref in inactive else item
            for item in manifest.items
        ))
    if bound:
        for index, item in enumerate(outstanding[:count]):
            manifest = policy.bind_campaign_recovery(
                manifest, item.work_ref, recovery_ref=f"run-{index + 1:012x}")
    return manifest


def _out(status: str, attempts: int, contacted: bool, *, error: str | None = None,
         downloads: int = 0, terminal: bool | None = None) -> MetadataRecoveryAdvanceOutcome:
    return MetadataRecoveryAdvanceOutcome({"status": status}, contacted, attempts, downloads,
        error_kind=error, verify_contacts_not_before_due=int(contacted),
        terminal_status_received=(status in {"packages_ready", "no_data"} and attempts == 1
                                  if terminal is None else terminal))


def _run(monkeypatch, tmp_path, manifest, outcomes=(), projections=None,
         factory=lambda: object(), *, patch_projection=True, state_error=None):
    plans = {key: list(value) for key, value in (projections or {}).items()}
    calls = SimpleNamespace(project=[], verify=[], factory=[])
    monkeypatch.setattr(subject, "load_campaign_manifest", lambda *a, **k: manifest)
    monkeypatch.setattr(subject, "load_campaign_grant", lambda *a, **k: SimpleNamespace(
        campaign_ref=manifest.campaign_ref, profile_id=PROFILE, tested_commit=COMMIT,
    ))
    monkeypatch.setattr(subject, "load_metadata_recovery_state", lambda *a, **k: (
        (_ for _ in ()).throw(MetadataRecoveryStateError(state_error))
        if state_error else object()))
    def project(**kwargs):
        calls.project.append(kwargs["work_ref"])
        values = plans.get(kwargs["work_ref"], [])
        return values.pop(0) if values else manifest
    queued = list(outcomes)
    def verify(**kwargs):
        calls.verify.append(kwargs["recovery_ref"])
        return queued.pop(0)
    if patch_projection:
        monkeypatch.setattr(subject, "project_persisted_campaign_recovery", project)
    monkeypatch.setattr(subject, "verify_metadata_recovery_once", verify)
    result = subject.execute_metadata_verify_effects_once(
        storage_root=tmp_path, repo_root=tmp_path / "repo",
        campaign_ref=manifest.campaign_ref, grant_ref="grt-" + "1" * 24,
        profile=_profile(tmp_path),
        verifier_factory=lambda: calls.factory.append(1) or factory(), now=NOW,
    )
    return result, calls


def _actions(result):  # type: ignore[no-untyped-def]
    return tuple(event.action.value for event in result.events)


@pytest.mark.parametrize("count", (0, 1, 2))
def test_only_current_two_outstanding_are_processed(monkeypatch, tmp_path, count) -> None:
    manifest = _manifest(count)
    outcomes = tuple(_out("verify_scheduled", 0, False) for _ in range(count))
    result, calls = _run(monkeypatch, tmp_path, manifest, outcomes)
    assert (result.verify_attempts, _actions(result)) == (0, ("waiting",) * count)
    assert len(calls.project) == count * 2 and len(calls.verify) == count
    assert calls.factory == []


@pytest.mark.parametrize("missing", (False, True))
def test_unbound_or_exact_missing_recovery_is_submission_pending(monkeypatch, tmp_path, missing) -> None:
    manifest = _manifest(1, bound=missing)
    result, calls = _run(
        monkeypatch, tmp_path, manifest,
        state_error="recovery-state-not-found" if missing else None,
    )
    assert _actions(result) == ("submission_pending",)
    assert result.verify_attempts == 0 and calls.project == calls.verify == calls.factory == []


@pytest.mark.parametrize(
    ("state", "category", "action"),
    ((policy.CampaignWorkState.NO_DATA, None, "no_data"),
     (policy.CampaignWorkState.FAILED, None, "failed"),
     (policy.CampaignWorkState.THRESHOLD_BLOCKED, "sat_too_many_results", "threshold_blocked")),
)
def test_preprojection_terminal_replay_skips_verify(monkeypatch, tmp_path, state, category, action) -> None:
    manifest = _manifest(1)
    work = next(item for item in manifest.items if item.state is policy.CampaignWorkState.OUTSTANDING)
    projected = policy.record_campaign_result(
        manifest, work.work_ref, state, recovery_ref=work.recovery_ref, evidence=category,
    )
    result, calls = _run(monkeypatch, tmp_path, manifest, projections={work.work_ref: [projected]})
    assert (result.verify_attempts, _actions(result), calls.verify) == (0, (action,), [])


def test_preprojection_5003_depth_zero_split_replays(monkeypatch, tmp_path) -> None:
    manifest = _manifest(1)
    work = next(item for item in manifest.items if item.state is policy.CampaignWorkState.OUTSTANDING)
    projected = policy.apply_campaign_submission_failure(
        manifest, work.work_ref, work.recovery_ref, "sat_too_many_results",
    )
    result, _ = _run(monkeypatch, tmp_path, manifest, projections={work.work_ref: [projected]})
    assert _actions(result) == ("split",)


@pytest.mark.parametrize(
    ("outcome", "post_state", "action", "attempts"),
    ((_out("verify_scheduled", 0, False), None, "waiting", 0),
     (_out("verify_scheduled", 1, True), None, "verify_pending", 1),
     (_out("packages_ready", 0, False), None, "packages_ready", 0),
     (_out("packages_ready", 1, True), None, "packages_ready", 1), (_out("no_data", 1, True), policy.CampaignWorkState.NO_DATA, "no_data", 1),
     (_out("pending_after_budget", 0, False), policy.CampaignWorkState.FAILED, "failed", 0), (_out("verify_failed", 0, False, error="verify_uncertain"), policy.CampaignWorkState.FAILED, "failed", 0),
     (_out("verify_failed", 1, True, error="sat_too_many_results"), policy.CampaignWorkState.THRESHOLD_BLOCKED, "threshold_blocked", 1),
     (_out("verify_failed", 1, True, error="verify_failed"), policy.CampaignWorkState.FAILED, "failed", 1)),
)
def test_verify_final_state_is_exact(monkeypatch, tmp_path, outcome, post_state, action, attempts) -> None:
    manifest = _manifest(1)
    work = next(item for item in manifest.items if item.state is policy.CampaignWorkState.OUTSTANDING)
    projected = manifest if post_state is None else policy.record_campaign_result(
        manifest, work.work_ref, post_state, recovery_ref=work.recovery_ref,
        evidence="sat_too_many_results" if post_state is policy.CampaignWorkState.THRESHOLD_BLOCKED else None)
    result, calls = _run(
        monkeypatch, tmp_path, manifest, (outcome,), {work.work_ref: [manifest, projected]},
    )
    assert (result.verify_attempts, _actions(result)) == (attempts, (action,))
    if attempts == 0:
        assert calls.factory == []


def test_adapter_local_failure_stops_before_second(monkeypatch, tmp_path) -> None:
    manifest = _manifest(2)
    result, calls = _run(
        monkeypatch, tmp_path, manifest,
        (_out("verify_failed", 1, False, error="verify_failed"), _out("verify_scheduled", 1, True)),
    )
    assert (result.verify_attempts, _actions(result)) == (1, ("adapter_failed",))
    assert len(calls.verify) == 1


def test_confirmed_retryable_contact_can_use_second_slot_once(monkeypatch, tmp_path) -> None:
    manifest = _manifest(2)
    result, calls = _run(monkeypatch, tmp_path, manifest, (
        _out("verify_scheduled", 1, True, error="verify_retryable"),
        _out("verify_scheduled", 1, True),
    ))
    assert (result.verify_attempts, _actions(result)) == (
        2, ("verify_pending", "verify_pending"),
    )
    assert len(calls.verify) == 2 and len(set(calls.verify)) == 2


@pytest.mark.parametrize(
    "outcome",
    (_out("verify_scheduled", 2, True), _out("verify_scheduled", 1, True, downloads=1),
     _out("impossible", 1, True), _out("verify_scheduled", 0, True),
     _out("verify_scheduled", 1, False), _out("packages_ready", 1, False),
     _out("packages_ready", 1, True, terminal=False),
     _out("no_data", 1, True, terminal=False),
     replace(_out("verify_scheduled", 1, True), error_kind="unsupported"),
     replace(_out("verify_scheduled", 1, True), requires_live=True), replace(_out("verify_scheduled", 1, True), download_attempts=False),
     replace(_out("verify_scheduled", 1, True), verify_contacts_not_before_due=0), replace(_out("verify_scheduled", 1, True), verify_count=True), replace(_out("verify_scheduled", 1, True), sat_contacted=1),
     replace(_out("verify_scheduled", 0, False), verify_contacts_before_due=-1), replace(_out("verify_scheduled", 0, False), verify_contacts_before_due=True), replace(_out("verify_scheduled", 0, False), terminal_status_received=0)),
)
def test_malformed_or_download_outcome_fails_closed(monkeypatch, tmp_path, outcome) -> None:
    with pytest.raises(subject.CampaignVerifyEffectsError) as captured:
        _run(monkeypatch, tmp_path, _manifest(1), (outcome,))
    assert captured.value.retry_safe is False


def test_state_corruption_and_projection_flags_are_sanitized(monkeypatch, tmp_path) -> None:
    with pytest.raises(subject.CampaignVerifyEffectsError) as captured:
        _run(monkeypatch, tmp_path, _manifest(1), state_error="PRIVATE-MARKER")
    assert (captured.value.reason, captured.value.retry_safe) == (
        "campaign-verify-recovery-state-invalid", False)
    assert "PRIVATE-MARKER" not in repr(captured.value)


def test_projection_conflict_preserves_only_safe_flags(monkeypatch, tmp_path) -> None:
    manifest = _manifest(1)
    monkeypatch.setattr(subject, "project_persisted_campaign_recovery", lambda **k: (_ for _ in ()).throw(
        CampaignRecoveryProjectionError("PRIVATE", committed=True, uncertain=True)))
    with pytest.raises(subject.CampaignVerifyEffectsError) as captured:
        _run(monkeypatch, tmp_path, manifest, patch_projection=False)
    assert (captured.value.reason, captured.value.retry_safe, captured.value.uncertain) == (
        "campaign-verify-projection-failed", False, True)
    assert "PRIVATE" not in repr(captured.value)


def test_output_and_import_graph_are_redacted() -> None:
    tree = ast.parse(Path(subject.__file__).read_text(encoding="utf-8"))
    imports = " ".join(
        node.module or "" for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)
    )
    assert all(word not in imports for word in (
        "smoke", "probe", "diagnose", "live_gate", "backfill", "scheduler", "adapters.cli",
    ))
    assert "rfc" not in {field for field in subject.CampaignVerifyEffectEvent.__dataclass_fields__}
