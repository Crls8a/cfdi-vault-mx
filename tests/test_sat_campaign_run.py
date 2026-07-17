import ast
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

import cfdi_vault.sat_campaign_run as subject
from cfdi_vault.sat_campaign_download_effects import CampaignMetadataZipDownloadResult
from cfdi_vault.sat_campaign_grant import CampaignGrant, campaign_manifest_digest
from cfdi_vault.sat_campaign_manifest import (
    CampaignWorkState,
    build_campaign_manifest,
    reserve_campaign_work,
)
from cfdi_vault.sat_campaign_runner import (
    CampaignCapacityAction,
    CampaignCapacityResult,
    CampaignCapacityWork,
)
from cfdi_vault.sat_campaign_submission_effects import (
    CampaignSubmissionEffectAction as Action,
)
from cfdi_vault.sat_campaign_submission_effects import (
    CampaignSubmissionEffectEvent as Event,
)
from cfdi_vault.sat_campaign_submission_effects import (
    CampaignSubmissionEffectsResult as Effects,
)
from cfdi_vault.sat_campaign_verify_effects import (
    CampaignVerifyEffectAction as VerifyAction,
)
from cfdi_vault.sat_campaign_verify_effects import (
    CampaignVerifyEffectEvent as VerifyEvent,
)
from cfdi_vault.sat_campaign_verify_effects import (
    CampaignVerifyEffectsResult as VerifyEffects,
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


def _wire(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    events=(),
    attempts=0,
    *,
    manifest=None,
    projected=None,
    verify_result=None,
    call_log=None,
    capacity=None,
    zip_result=None,
):
    profile = _profile(tmp_path)
    manifest = build_campaign_manifest(PROFILE) if manifest is None else manifest
    projected = manifest if projected is None else projected
    calls = [] if call_log is None else call_log
    grant = _grant(manifest)
    provider = SimpleNamespace(provider_scheme="windows-credential-manager")
    monkeypatch.setattr(subject, "load_profile", lambda value: calls.append(("profile", value)) or profile)
    manifests = iter((manifest, projected))
    monkeypatch.setattr(subject, "load_campaign_manifest", lambda storage, ref, **kw:
                        calls.append(("manifest", storage, ref, kw)) or next(manifests))
    monkeypatch.setattr(subject.grants, "load_campaign_grant", lambda storage, ref, repo, now=None:
                        calls.append(("grant", storage, ref, repo, now)) or grant)
    monkeypatch.setattr(subject.preflight, "verify_campaign_preflight", lambda **kw:
                        calls.append(("preflight", kw)) or "evidence")
    capacity = capacity or CampaignCapacityResult("inv-" + "2" * 24, (), ())
    monkeypatch.setattr(subject, "reserve_metadata_campaign_capacity_once", lambda **kw:
                        calls.append(("reserve", kw)) or capacity)
    outstanding = tuple(
        item.work_ref for item in projected.items
        if item.state is CampaignWorkState.OUTSTANDING
    )
    query_refs = outstanding or ("work-a", "work-b", "work-c")
    queries = {work_ref: object() for work_ref in query_refs}
    monkeypatch.setattr(subject, "build_outstanding_metadata_queries", lambda current, bound:
                        calls.append(("queries", current, bound)) or queries)
    def adapter():
        calls.append(("adapter-called",))
    monkeypatch.setattr(subject, "build_campaign_metadata_request_factory", lambda **kw:
                        calls.append(("adapter-built", kw)) or adapter)
    verified = VerifyEffects(0, ()) if verify_result is None else verify_result
    monkeypatch.setattr(subject.verification, "execute_metadata_verify_effects_once", lambda **kw:
                        calls.append(("verify-effects", kw)) or verified)
    if zip_result is None:
        zip_result = CampaignMetadataZipDownloadResult(
            False, False, 0, None, "no-pending-package", "no-pending-package",
        )
    monkeypatch.setattr(subject.download, "execute_campaign_metadata_zip_download_once", lambda **kw:
                        calls.append(("zip-download", kw)) or zip_result)
    monkeypatch.setattr(subject.submission, "execute_metadata_submission_effects_once", lambda **kw:
                        calls.append(("effects", kw)) or Effects(attempts, tuple(events)))
    result = subject.run_metadata_campaign_once(
        profile_id=PROFILE, campaign_ref=CAMPAIGN, grant_ref=GRANT,
        repo_root=tmp_path / "repo", environ={}, provider_factory=lambda bound: provider,
        checks_factory=lambda bound: {}, now=NOW,
    )
    return result, calls, profile, capacity, queries, adapter


def test_packages_ready_downloads_before_reservation_and_stops(monkeypatch, tmp_path) -> None:
    manifest = reserve_campaign_work(build_campaign_manifest(PROFILE))
    work_ref = next(item.work_ref for item in manifest.items
                    if item.state is CampaignWorkState.OUTSTANDING)
    zip_result = CampaignMetadataZipDownloadResult(
        True, True, 1, None, "downloaded", None,
    )
    result, calls, *_ = _wire(
        monkeypatch, tmp_path, manifest=manifest,
        verify_result=VerifyEffects(0, (VerifyEvent(work_ref, VerifyAction.PACKAGES_READY),
                                        VerifyEvent(next(item.work_ref for item in manifest.items
                                                         if item.state is CampaignWorkState.OUTSTANDING
                                                         and item.work_ref != work_ref),
                                                    VerifyAction.WAITING))),
        zip_result=zip_result,
    )
    names = [call[0] for call in calls]
    assert names.index("verify-effects") < names.index("zip-download")
    assert "reserve" not in names and "effects" not in names
    assert calls[names.index("zip-download")][1]["work_ref"] == work_ref
    assert calls[names.index("zip-download")][1]["downloader_factory"] is calls[names.index("verify-effects")][1]["verifier_factory"]
    assert (result.zip_downloaded, result.zip_valid, result.package_count,
            result.zip_status, result.submission_attempts) == (True, True, 1, "downloaded", 0)
    assert result.status == "completed"


def test_ready_package_is_prioritized_over_an_earlier_waiting_work(monkeypatch, tmp_path) -> None:
    manifest = reserve_campaign_work(build_campaign_manifest(PROFILE))
    refs = tuple(item.work_ref for item in manifest.items
                 if item.state is CampaignWorkState.OUTSTANDING)
    result, calls, *_ = _wire(
        monkeypatch, tmp_path, manifest=manifest,
        verify_result=VerifyEffects(0, (
            VerifyEvent(refs[0], VerifyAction.WAITING),
            VerifyEvent(refs[1], VerifyAction.PACKAGES_READY),
        )),
        zip_result=CampaignMetadataZipDownloadResult(True, True, 1, None, "downloaded", None),
    )
    names = [call[0] for call in calls]
    assert "reserve" not in names and calls[names.index("zip-download")][1]["work_ref"] == refs[1]
    assert result.zip_valid is True


@pytest.mark.parametrize("zip_status", ("in-progress", "already-downloaded"))
def test_zip_pending_or_idempotent_stops_before_new_requests(monkeypatch, tmp_path, zip_status) -> None:
    manifest = reserve_campaign_work(build_campaign_manifest(PROFILE))
    work_ref = next(item.work_ref for item in manifest.items
                    if item.state is CampaignWorkState.OUTSTANDING)
    result, calls, *_ = _wire(
        monkeypatch, tmp_path, manifest=manifest,
        verify_result=VerifyEffects(0, (VerifyEvent(work_ref, VerifyAction.PACKAGES_READY),
                                        VerifyEvent(next(item.work_ref for item in manifest.items
                                                         if item.state is CampaignWorkState.OUTSTANDING
                                                         and item.work_ref != work_ref),
                                                    VerifyAction.WAITING))),
        zip_result=CampaignMetadataZipDownloadResult(
            zip_status == "already-downloaded", zip_status == "already-downloaded", 1,
            "2026-07-16T12:00:00Z" if zip_status == "in-progress" else None,
            zip_status, None,
        ),
    )
    names = [call[0] for call in calls]
    assert "zip-download" in names and "reserve" not in names and "effects" not in names
    assert result.zip_status == zip_status
    assert result.submission_attempts == 0


def test_waiting_work_with_pending_zip_stops_before_new_requests(monkeypatch, tmp_path) -> None:
    manifest = reserve_campaign_work(build_campaign_manifest(PROFILE))
    refs = tuple(item.work_ref for item in manifest.items
                 if item.state is CampaignWorkState.OUTSTANDING)
    result, calls, *_ = _wire(
        monkeypatch, tmp_path, manifest=manifest,
        verify_result=VerifyEffects(0, tuple(
            VerifyEvent(ref, VerifyAction.WAITING) for ref in refs
        )),
        zip_result=CampaignMetadataZipDownloadResult(
            False, False, 1, "2026-07-16T12:00:00Z", "in-progress", None,
        ),
    )
    names = [call[0] for call in calls]
    assert "zip-download" in names and "reserve" not in names and "effects" not in names
    assert result.zip_status == "in-progress"


def test_no_ready_package_preserves_reserve_and_submission(monkeypatch, tmp_path) -> None:
    result, calls, *_ = _wire(
        monkeypatch, tmp_path,
        verify_result=VerifyEffects(0, ()),
        zip_result=CampaignMetadataZipDownloadResult(False, False, 0, None, "no-pending-package", "no-pending-package"),
    )
    names = [call[0] for call in calls]
    assert "zip-download" not in names and "reserve" in names and "effects" in names
    assert (result.zip_downloaded, result.zip_valid, result.package_count, result.zip_status) == (False, False, 0, None)


def test_one_shot_preserves_order_storage_lineage_and_invocation(monkeypatch, tmp_path) -> None:
    result, calls, profile, capacity, queries, adapter = _wire(monkeypatch, tmp_path)
    assert [call[0] for call in calls] == [
        "profile", "manifest", "grant", "preflight", "adapter-built", "verify-effects",
        "reserve", "manifest", "queries", "effects",
    ]
    assert calls[1][1] == calls[2][1] == calls[6][1]["storage_root"] == profile.storage_root
    assert calls[6][1]["max_reservations"] == 1
    assert calls[4][1]["storage_root"] == profile.storage_root
    assert calls[5][1] == {
        "storage_root": profile.storage_root,
        "repo_root": tmp_path / "repo",
        "campaign_ref": CAMPAIGN,
        "grant_ref": GRANT,
        "profile": profile,
        "verifier_factory": adapter,
        "now": NOW,
    }
    assert calls[9][1]["invocation_ref"] == capacity.invocation_ref
    assert calls[9][1]["queries_by_work"] is queries
    assert calls[9][1]["adapter_factory"] is adapter
    assert result == subject.CampaignRunResult("completed", 0, 3, 0, 0, 0, 0, 0, 0)


def test_preflight_failure_never_reserves_and_is_retry_safe(monkeypatch, tmp_path) -> None:
    profile, manifest, grant = _profile(tmp_path), build_campaign_manifest(PROFILE), None
    grant = _grant(manifest)
    monkeypatch.setattr(subject, "load_profile", lambda _: profile)
    monkeypatch.setattr(subject, "load_campaign_manifest", lambda *a, **k: manifest)
    monkeypatch.setattr(subject.grants, "load_campaign_grant", lambda *a, **k: grant)
    monkeypatch.setattr(subject.preflight, "verify_campaign_preflight", lambda **kw: (_ for _ in ()).throw(OSError("secret")))
    called = []
    monkeypatch.setattr(subject.verification, "execute_metadata_verify_effects_once", lambda **kw:
                        called.append(("verify", kw)))
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


@pytest.mark.parametrize(("action", "reserved"), (
    (VerifyAction.SUBMISSION_PENDING, 0),
    (VerifyAction.WAITING, 0),
    (VerifyAction.VERIFY_PENDING, 0),
    (VerifyAction.PACKAGES_READY, 0),
    (VerifyAction.NO_DATA, 1),
    (VerifyAction.SPLIT, 1),
))
def test_nonblocking_verify_is_projected_before_reservation(
    monkeypatch, tmp_path, action, reserved,
) -> None:
    manifest = reserve_campaign_work(build_campaign_manifest(PROFILE))
    work_refs = tuple(
        item.work_ref for item in manifest.items
        if item.state is CampaignWorkState.OUTSTANDING
    )
    reservation = CampaignCapacityResult(
        "inv-" + "2" * 24, (),
        (() if not reserved else (CampaignCapacityWork(
            CampaignCapacityAction.RESERVED_WITHOUT_CONTACT,
            next(item.work_ref for item in manifest.items
                 if item.state is CampaignWorkState.PLANNED),
        ),)),
    )
    result, calls, *_ = _wire(
        monkeypatch, tmp_path, manifest=manifest,
        verify_result=VerifyEffects(0, (
            VerifyEvent(work_refs[0], action),
            VerifyEvent(work_refs[1], VerifyAction.WAITING),
        )),
        capacity=reservation,
    )
    names = [call[0] for call in calls]
    if action is VerifyAction.PACKAGES_READY:
        assert "zip-download" in names and "reserve" not in names
    else:
        assert names.index("verify-effects") < names.index("reserve")
    assert result.reserved_count == reserved


@pytest.mark.parametrize("action", (
    VerifyAction.ADAPTER_FAILED,
    VerifyAction.FAILED,
    VerifyAction.THRESHOLD_BLOCKED,
))
def test_blocking_verify_stops_before_reservation(monkeypatch, tmp_path, action) -> None:
    manifest = reserve_campaign_work(build_campaign_manifest(PROFILE))
    work_ref = next(
        item.work_ref for item in manifest.items
        if item.state is CampaignWorkState.OUTSTANDING
    )
    calls = []
    with pytest.raises(subject.CampaignRunError) as caught:
        _wire(
            monkeypatch, tmp_path, manifest=manifest,
            verify_result=VerifyEffects(1, (VerifyEvent(work_ref, action),)),
            call_log=calls,
        )
    assert (caught.value.reason, caught.value.retry_safe) == \
        ("campaign-run-reconciliation-required", False)
    assert "reserve" not in [call[0] for call in calls]


def test_two_unique_verify_attempts_are_accepted(monkeypatch, tmp_path) -> None:
    manifest = reserve_campaign_work(build_campaign_manifest(PROFILE))
    work_refs = tuple(
        item.work_ref for item in manifest.items
        if item.state is CampaignWorkState.OUTSTANDING
    )
    result, calls, *_ = _wire(
        monkeypatch, tmp_path, manifest=manifest,
        verify_result=VerifyEffects(2, tuple(
            VerifyEvent(work_ref, VerifyAction.VERIFY_PENDING)
            for work_ref in work_refs
        )),
    )
    assert result.status == "completed"
    assert [call[0] for call in calls].count("verify-effects") == 1


def test_one_outstanding_requires_its_exact_verify_event(monkeypatch, tmp_path) -> None:
    manifest = reserve_campaign_work(build_campaign_manifest(PROFILE))
    outstanding = tuple(
        item for item in manifest.items
        if item.state is CampaignWorkState.OUTSTANDING
    )
    manifest = replace(manifest, items=tuple(
        replace(item, state=CampaignWorkState.PLANNED)
        if item.work_ref == outstanding[1].work_ref else item
        for item in manifest.items
    ))
    result, calls, *_ = _wire(
        monkeypatch, tmp_path, manifest=manifest,
        verify_result=VerifyEffects(0, (
            VerifyEvent(outstanding[0].work_ref, VerifyAction.WAITING),
        )),
    )
    assert result.status == "completed"
    assert [call[0] for call in calls].count("verify-effects") == 1


def _invalid_verify_results(work_refs: tuple[str, str]):
    class WorkRef(str):
        pass

    work_ref, second_ref = work_refs
    event = VerifyEvent(work_ref, VerifyAction.WAITING)
    return (
        SimpleNamespace(verify_attempts=0, events=()),
        VerifyEffects(True, ()), VerifyEffects(-1, ()), VerifyEffects(3, ()),
        VerifyEffects(0, []),
        VerifyEffects(0, (SimpleNamespace(work_ref=work_ref, action=VerifyAction.WAITING),)),
        VerifyEffects(0, (VerifyEvent(WorkRef(work_ref), VerifyAction.WAITING),)),
        VerifyEffects(0, (VerifyEvent("", VerifyAction.WAITING),)),
        VerifyEffects(0, (VerifyEvent("work-foreign000000", VerifyAction.WAITING),)),
        VerifyEffects(0, (VerifyEvent(work_ref, "waiting"),)),
        VerifyEffects(0, ()),
        VerifyEffects(0, (event,)),
        VerifyEffects(0, (
            VerifyEvent(second_ref, VerifyAction.WAITING), event,
        )),
        VerifyEffects(0, (event, event)),
        VerifyEffects(0, (event, VerifyEvent(work_ref, VerifyAction.NO_DATA))),
        VerifyEffects(0, (event, VerifyEvent(work_ref, VerifyAction.WAITING), event)),
    )


def test_malformed_verify_results_fail_closed_before_reservation(monkeypatch, tmp_path) -> None:
    manifest = reserve_campaign_work(build_campaign_manifest(PROFILE))
    work_refs = tuple(
        item.work_ref for item in manifest.items
        if item.state is CampaignWorkState.OUTSTANDING
    )
    for invalid in _invalid_verify_results(work_refs):
        calls = []
        with monkeypatch.context() as scoped:
            with pytest.raises(subject.CampaignRunError) as caught:
                _wire(
                    scoped, tmp_path, manifest=manifest, verify_result=invalid,
                    call_log=calls,
                )
        assert (caught.value.reason, caught.value.retry_safe) == \
            ("campaign-run-reconciliation-required", False)
        assert "reserve" not in [call[0] for call in calls]


def test_blocking_verify_cannot_skip_the_first_outstanding_slot(monkeypatch, tmp_path) -> None:
    manifest = reserve_campaign_work(build_campaign_manifest(PROFILE))
    work_refs = tuple(
        item.work_ref for item in manifest.items
        if item.state is CampaignWorkState.OUTSTANDING
    )
    calls = []
    with pytest.raises(subject.CampaignRunError) as caught:
        _wire(
            monkeypatch, tmp_path, manifest=manifest,
            verify_result=VerifyEffects(1, (
                VerifyEvent(work_refs[1], VerifyAction.ADAPTER_FAILED),
            )),
            call_log=calls,
        )
    assert (caught.value.reason, caught.value.retry_safe) == \
        ("campaign-run-reconciliation-required", False)
    assert not any(call[0] in {"reserve", "effects"} for call in calls)


def test_verify_exception_is_redacted_and_stops_before_reservation(monkeypatch, tmp_path) -> None:
    profile, manifest = _profile(tmp_path), build_campaign_manifest(PROFILE)
    grant, calls = _grant(manifest), []
    monkeypatch.setattr(subject, "load_profile", lambda _: profile)
    monkeypatch.setattr(subject, "load_campaign_manifest", lambda *a, **k: manifest)
    monkeypatch.setattr(subject.grants, "load_campaign_grant", lambda *a, **k: grant)
    monkeypatch.setattr(subject.preflight, "verify_campaign_preflight", lambda **kw: object())
    monkeypatch.setattr(subject, "build_campaign_metadata_request_factory", lambda **kw: object())
    monkeypatch.setattr(subject.verification, "execute_metadata_verify_effects_once", lambda **kw:
                        (_ for _ in ()).throw(OSError("PRIVATE-MARKER")))
    monkeypatch.setattr(subject, "reserve_metadata_campaign_capacity_once", lambda **kw:
                        calls.append(kw))
    with pytest.raises(subject.CampaignRunError) as caught:
        subject.run_metadata_campaign_once(
            profile_id=PROFILE, campaign_ref=manifest.campaign_ref, grant_ref=GRANT,
            repo_root=tmp_path / "repo", environ={}, provider_factory=lambda _: object(),
            checks_factory=lambda _: {}, now=NOW,
        )
    assert (caught.value.reason, caught.value.retry_safe) == \
        ("campaign-run-reconciliation-required", False)
    assert calls == [] and "PRIVATE-MARKER" not in repr(caught.value)


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
        "zip_downloaded", "zip_valid", "package_count", "next_check_at", "zip_status",
    }
    assert all(value not in repr(result) for value in (PROFILE, CAMPAIGN, GRANT, "work-a"))
    with pytest.raises((AttributeError, TypeError)):
        result.status = "completed"


def test_zero_attempt_failed_replay_is_valid_attention_required(monkeypatch, tmp_path) -> None:
    result, *_ = _wire(monkeypatch, tmp_path, (Event("work-a", Action.SUBMISSION_FAILED_REPLAY),), 0)
    assert result == subject.CampaignRunResult("attention_required", 0, 3, 0, 0, 1, 0, 0, 0)


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
    (0, (Event("work-a", Action.SUBMISSION_FAILED),)),
    (1, (Event("work-a", Action.SUBMISSION_FAILED_REPLAY),)),
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
