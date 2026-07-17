import ast
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

import cfdi_vault.sat_campaign_run as subject
from cfdi_vault.sat_campaign_grant import CampaignGrant, campaign_manifest_digest
from cfdi_vault.sat_campaign_manifest import build_campaign_manifest
from cfdi_vault.sat_campaign_runner import CampaignCapacityResult
from cfdi_vault.sat_campaign_submission_effects import (
    CampaignSubmissionEffectAction as Action,
)
from cfdi_vault.sat_campaign_submission_effects import (
    CampaignSubmissionEffectEvent as Event,
)
from cfdi_vault.sat_campaign_submission_effects import (
    CampaignSubmissionEffectsResult as Effects,
)
from cfdi_vault.setup_core import CredentialMode, LocalProfile, LocalProfileStatus

NOW = datetime(2026, 7, 16, 12, tzinfo=timezone.utc)
PROFILE, GRANT = "profile-synthetic", "grt-" + "1" * 24
CAMPAIGN = build_campaign_manifest(PROFILE).campaign_ref


def _profile(tmp_path: Path) -> LocalProfile:
    return LocalProfile(
        PROFILE, "XAXX010101000", tmp_path / "private", CredentialMode.COPIED,
        tmp_path / "certificate.cer", tmp_path / "key.key",
        "windows-credential-manager://cfdi-vault/synthetic-phrase",
        LocalProfileStatus.READY, "a" * 64,
    )


def _grant(manifest) -> CampaignGrant:
    return CampaignGrant(
        GRANT, manifest.campaign_ref, campaign_manifest_digest(manifest), "a" * 40,
        PROFILE, NOW - timedelta(minutes=1), NOW + timedelta(days=1), "proof",
    )


def _wire(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, events=(), attempts=0):
    profile, manifest, calls = _profile(tmp_path), build_campaign_manifest(PROFILE), []
    grant = _grant(manifest)
    provider = SimpleNamespace(provider_scheme="windows-credential-manager")
    monkeypatch.setattr(subject, "load_profile", lambda value: calls.append(("profile", value)) or profile)
    manifests = iter((manifest, manifest))
    monkeypatch.setattr(subject, "load_campaign_manifest", lambda storage, ref, **kw:
                        calls.append(("manifest", storage, ref, kw)) or next(manifests))
    monkeypatch.setattr(subject.grants, "load_campaign_grant", lambda storage, ref, repo, now=None:
                        calls.append(("grant", storage, ref, repo, now)) or grant)
    monkeypatch.setattr(subject.preflight, "verify_campaign_preflight", lambda **kw:
                        calls.append(("preflight", kw)) or "evidence")
    capacity = CampaignCapacityResult("inv-" + "2" * 24, (), ())
    monkeypatch.setattr(subject, "reserve_metadata_campaign_capacity_once", lambda **kw:
                        calls.append(("reserve", kw)) or capacity)
    queries = {"work-a": object(), "work-b": object(), "work-c": object()}
    monkeypatch.setattr(subject, "build_outstanding_metadata_queries", lambda current, bound:
                        calls.append(("queries", current, bound)) or queries)
    def adapter():
        calls.append(("adapter-called",))
    monkeypatch.setattr(subject, "build_campaign_metadata_request_factory", lambda **kw:
                        calls.append(("adapter-built", kw)) or adapter)
    monkeypatch.setattr(subject.submission, "execute_metadata_submission_effects_once", lambda **kw:
                        calls.append(("effects", kw)) or Effects(attempts, tuple(events)))
    result = subject.run_metadata_campaign_once(
        profile_id=PROFILE, campaign_ref=CAMPAIGN, grant_ref=GRANT,
        repo_root=tmp_path / "repo", environ={}, provider_factory=lambda bound: provider,
        checks_factory=lambda bound: {}, now=NOW,
    )
    return result, calls, profile, capacity, queries, adapter


def test_one_shot_preserves_order_storage_lineage_and_invocation(monkeypatch, tmp_path) -> None:
    result, calls, profile, capacity, queries, adapter = _wire(monkeypatch, tmp_path)
    assert [call[0] for call in calls] == [
        "profile", "manifest", "grant", "preflight", "reserve", "manifest", "queries",
        "adapter-built", "effects",
    ]
    assert calls[1][1] == calls[2][1] == calls[4][1]["storage_root"] == profile.storage_root
    assert calls[7][1]["storage_root"] == calls[8][1]["storage_root"] == profile.storage_root
    assert calls[8][1]["invocation_ref"] == capacity.invocation_ref
    assert calls[8][1]["queries_by_work"] is queries and calls[8][1]["adapter_factory"] is adapter
    assert result == subject.CampaignRunResult("completed", 0, 3, 0, 0, 0, 0, 0, 0)


def test_preflight_failure_never_reserves_and_is_retry_safe(monkeypatch, tmp_path) -> None:
    profile, manifest, grant = _profile(tmp_path), build_campaign_manifest(PROFILE), None
    grant = _grant(manifest)
    monkeypatch.setattr(subject, "load_profile", lambda _: profile)
    monkeypatch.setattr(subject, "load_campaign_manifest", lambda *a, **k: manifest)
    monkeypatch.setattr(subject.grants, "load_campaign_grant", lambda *a, **k: grant)
    monkeypatch.setattr(subject.preflight, "verify_campaign_preflight", lambda **kw: (_ for _ in ()).throw(OSError("secret")))
    called = []
    monkeypatch.setattr(subject, "reserve_metadata_campaign_capacity_once", lambda **kw: called.append(kw))
    with pytest.raises(subject.CampaignRunError) as caught:
        subject.run_metadata_campaign_once(
            profile_id=PROFILE, campaign_ref=manifest.campaign_ref, grant_ref=GRANT,
            repo_root=tmp_path / "repo", environ={}, provider_factory=lambda _: object(),
            checks_factory=lambda _: {}, now=NOW,
        )
    assert (caught.value.error, caught.value.reason, caught.value.retry_safe) == \
        ("sat_campaign_run_failed", "campaign-run-preflight-failed", True)
    assert not called and "secret" not in repr(caught.value)


def test_last_event_per_work_drives_redacted_attention_aggregates(monkeypatch, tmp_path) -> None:
    events = (
        Event("work-a", Action.SUBMISSION_DEFERRED),
        Event("work-a", Action.SUBMISSION_ACCEPTED),
        Event("work-b", Action.CLAIMED_REPLAY),
        Event("work-c", Action.SUBMISSION_FAILED),
    )
    result, *_ = _wire(monkeypatch, tmp_path, events, 2)
    assert result == subject.CampaignRunResult("attention_required", 0, 3, 2, 1, 1, 0, 0, 1)
    assert set(result.__dataclass_fields__) == {
        "status", "reserved_count", "outstanding_count", "submission_attempts",
        "accepted_count", "failed_count", "uncertain_count", "deferred_count", "replay_count",
    }
    assert all(value not in repr(result) for value in (PROFILE, CAMPAIGN, GRANT, "work-a"))
    with pytest.raises((AttributeError, TypeError)):
        result.status = "completed"


@pytest.mark.parametrize("action", (
    Action.ORPHAN_UNCERTAIN, Action.SUBMISSION_UNCERTAIN,
    Action.ADAPTER_FAILED, Action.SUBMISSION_ERROR,
))
def test_uncertain_persisted_effect_requires_reconciliation(monkeypatch, tmp_path, action) -> None:
    with pytest.raises(subject.CampaignRunError) as caught:
        _wire(monkeypatch, tmp_path, (Event("work-a", action),), 1)
    assert (caught.value.reason, caught.value.retry_safe) == \
        ("campaign-run-reconciliation-required", False)


@pytest.mark.parametrize(("attempts", "events"), (
    (1, ()),
    (0, (Event("unknown-work", Action.SUBMISSION_ACCEPTED),)),
    (0, (Event("work-a", Action.SUBMISSION_ACCEPTED),)),
    (2, (Event("work-a", Action.SUBMISSION_ACCEPTED),)),
))
def test_invalid_raw_effect_consistency_requires_reconciliation(
    monkeypatch, tmp_path, attempts, events,
) -> None:
    with pytest.raises(subject.CampaignRunError) as caught:
        _wire(monkeypatch, tmp_path, events, attempts)
    assert (caught.value.reason, caught.value.retry_safe) == \
        ("campaign-run-reconciliation-required", False)


def test_exception_after_reservation_is_not_retry_safe(monkeypatch, tmp_path) -> None:
    profile, manifest, grant = _profile(tmp_path), build_campaign_manifest(PROFILE), None
    grant = _grant(manifest)
    monkeypatch.setattr(subject, "load_profile", lambda _: profile)
    monkeypatch.setattr(subject, "load_campaign_manifest", lambda *a, **k: manifest)
    monkeypatch.setattr(subject.grants, "load_campaign_grant", lambda *a, **k: grant)
    monkeypatch.setattr(subject.preflight, "verify_campaign_preflight", lambda **kw: object())
    monkeypatch.setattr(subject, "reserve_metadata_campaign_capacity_once", lambda **kw:
                        (_ for _ in ()).throw(OSError("private path")))
    with pytest.raises(subject.CampaignRunError) as caught:
        subject.run_metadata_campaign_once(
            profile_id=PROFILE, campaign_ref=manifest.campaign_ref, grant_ref=GRANT,
            repo_root=tmp_path / "repo", environ={}, provider_factory=lambda _: object(),
            checks_factory=lambda _: {}, now=NOW,
        )
    assert (caught.value.reason, caught.value.retry_safe) == \
        ("campaign-run-reconciliation-required", False)
    assert "private path" not in repr(caught.value)


def test_import_graph_has_no_experimental_or_cli_dependencies() -> None:
    tree = ast.parse(Path(subject.__file__).read_text(encoding="utf-8"))
    imported = {node.module or "" for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)}
    assert not any(any(word in name for word in ("smoke", "probe", "diagnose", "live_gate", "adapters.cli"))
                   for name in imported)
