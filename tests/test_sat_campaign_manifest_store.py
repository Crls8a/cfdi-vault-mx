from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, Mock

import pytest

import cfdi_vault.sat_campaign_manifest_store as subject
from cfdi_vault.sat_campaign_manifest import (
    CampaignManifestError,
    CampaignWorkState,
    bind_campaign_recovery,
    build_campaign_manifest,
    record_campaign_result,
    reserve_campaign_work,
    split_campaign_work,
)
from cfdi_vault.secure_state_file import SecureStateFileError

PROFILE, RUN_REF = "profile-synthetic", "run-000000000000"


def _roots(tmp_path: Path) -> tuple[Path, Path]:
    repository, storage = tmp_path / "checkout", tmp_path / "storage"
    repository.mkdir()
    return repository, storage


def _bound_manifest():  # type: ignore[no-untyped-def]
    reserved = reserve_campaign_work(build_campaign_manifest(PROFILE))
    return bind_campaign_recovery(reserved, reserved.items[0].work_ref, recovery_ref=RUN_REF)


def _completed_manifest():  # type: ignore[no-untyped-def]
    bound = _bound_manifest()
    return record_campaign_result(
        bound, bound.items[0].work_ref, CampaignWorkState.COMPLETED, recovery_ref=RUN_REF,
    )


def test_bound_outstanding_round_trip_is_canonical_and_idempotent(tmp_path: Path) -> None:
    repository, storage = _roots(tmp_path)
    manifest = _bound_manifest()
    with pytest.raises(subject.CampaignManifestStoreError, match="campaign-state-not-found"):
        subject.load_campaign_manifest(storage, manifest.campaign_ref, repo_root=repository)
    assert subject.initialize_campaign_manifest(
        storage, manifest, repo_root=repository,
    ) == manifest
    path = subject.campaign_manifest_state_path(
        storage, manifest.campaign_ref, repo_root=repository,
    )
    contents = path.read_bytes()
    assert contents == json.dumps(json.loads(contents), sort_keys=True, separators=(",", ":")).encode() + b"\n"
    assert subject.load_campaign_manifest(
        storage, manifest.campaign_ref, repo_root=repository,
    ) == manifest
    assert subject.initialize_campaign_manifest(
        storage, manifest, repo_root=repository,
    ) == manifest
    with pytest.raises(subject.CampaignManifestStoreError, match="campaign-state-conflict"):
        subject.initialize_campaign_manifest(
            storage, build_campaign_manifest(PROFILE), repo_root=repository,
        )


@pytest.mark.parametrize(
    ("mutation", "reason"),
    (("version", "campaign-state-unsupported"), ("bool-version", "campaign-state-invalid"),
     ("extra", "campaign-state-invalid"), ("missing", "campaign-state-invalid"),
     ("bool-depth", "campaign-state-invalid"), ("date", "campaign-state-invalid")),
)
def test_decode_rejects_noncanonical_or_invalid_schema(
    tmp_path: Path, mutation: str, reason: str,
) -> None:
    repository, storage = _roots(tmp_path)
    manifest = build_campaign_manifest(PROFILE)
    subject.initialize_campaign_manifest(storage, manifest, repo_root=repository)
    path = subject.campaign_manifest_state_path(storage, manifest.campaign_ref, repo_root=repository)
    document = json.loads(path.read_bytes())
    if mutation == "version":
        document["schemaVersion"] = 2
    elif mutation == "bool-version":
        document["schemaVersion"] = True
    elif mutation == "extra":
        document["unexpected"] = None
    elif mutation == "missing":
        del document["profileId"]
    elif mutation == "bool-depth":
        document["items"][0]["depth"] = False
    else:
        document["items"][0]["start"] = "20260101"
    path.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(subject.CampaignManifestStoreError, match=reason):
        subject.load_campaign_manifest(storage, manifest.campaign_ref, repo_root=repository)


@pytest.mark.parametrize(
    ("payload", "reason"),
    ((b"\xef\xbb\xbf{}", "campaign-state-invalid"),
     (b"\xff", "campaign-state-invalid"),
     (b'{"schemaVersion":1,"schemaVersion":1}', "campaign-state-duplicate-key"),
     (b" " * (1024 * 1024 + 1), "campaign-state-too-large")),
    ids=("bom", "invalid-utf8", "duplicate-key", "oversize"),
)
def test_decode_rejects_encoding_duplicates_and_oversize(
    tmp_path: Path, payload: bytes, reason: str,
) -> None:
    repository, storage = _roots(tmp_path)
    manifest = build_campaign_manifest(PROFILE)
    subject.initialize_campaign_manifest(storage, manifest, repo_root=repository)
    path = subject.campaign_manifest_state_path(storage, manifest.campaign_ref, repo_root=repository)
    path.write_bytes(payload)
    with pytest.raises(subject.CampaignManifestStoreError, match=reason):
        subject.load_campaign_manifest(storage, manifest.campaign_ref, repo_root=repository)


def test_load_enforces_campaign_limit_inside_secure_read(monkeypatch) -> None:
    manifest = build_campaign_manifest(PROFILE)
    transaction, manager = Mock(), MagicMock()
    transaction.read.return_value = subject._encode(manifest)  # noqa: SLF001
    manager.__enter__.return_value = transaction
    monkeypatch.setattr(subject, "secure_state_transaction", Mock(return_value=manager))
    assert subject.load_campaign_manifest("C:/private", manifest.campaign_ref) == manifest
    transaction.read.assert_called_once_with(max_bytes=1024 * 1024)


def test_decode_rejects_hostile_nested_json_without_leaking_recursion_error(tmp_path: Path) -> None:
    repository, storage = _roots(tmp_path)
    manifest = build_campaign_manifest(PROFILE)
    subject.initialize_campaign_manifest(storage, manifest, repo_root=repository)
    path = subject.campaign_manifest_state_path(storage, manifest.campaign_ref, repo_root=repository)
    payload = b'{"schemaVersion":' + (b"[" * 2_000) + b"0" + (b"]" * 2_000) + b"}"
    assert len(payload) <= 1024 * 1024
    path.write_bytes(payload)
    with pytest.raises(subject.CampaignManifestStoreError, match="campaign-state-invalid"):
        subject.load_campaign_manifest(storage, manifest.campaign_ref, repo_root=repository)


def test_domain_store_transitions_are_atomic_and_keep_allowed_noops(tmp_path: Path, monkeypatch) -> None:
    repository, storage = _roots(tmp_path)
    manifest = build_campaign_manifest(PROFILE)
    subject.initialize_campaign_manifest(storage, manifest, repo_root=repository)
    write = Mock(wraps=subject._replace)  # noqa: SLF001
    monkeypatch.setattr(subject, "_replace", write)
    reserved = subject.reserve_campaign_manifest(storage, manifest.campaign_ref, repo_root=repository)
    assert reserved == reserve_campaign_work(manifest) and write.call_count == 1
    assert subject.reserve_campaign_manifest(
        storage, manifest.campaign_ref, repo_root=repository,
    ) == reserved
    assert write.call_count == 1
    work_ref = reserved.items[0].work_ref
    bound = subject.bind_campaign_manifest_recovery(
        storage, manifest.campaign_ref, work_ref, RUN_REF, repo_root=repository,
    )
    assert bound == bind_campaign_recovery(reserved, work_ref, recovery_ref=RUN_REF)
    assert subject.bind_campaign_manifest_recovery(
        storage, manifest.campaign_ref, work_ref, RUN_REF, repo_root=repository,
    ) == bound
    assert write.call_count == 2
    completed = subject.record_campaign_manifest_result(
        storage, manifest.campaign_ref, work_ref, CampaignWorkState.COMPLETED, RUN_REF,
        repo_root=repository,
    )
    assert completed == record_campaign_result(
        bound, work_ref, CampaignWorkState.COMPLETED, recovery_ref=RUN_REF,
    )


def test_split_store_transition_requires_threshold_evidence(tmp_path: Path) -> None:
    repository, storage = _roots(tmp_path)
    bound = _bound_manifest()
    work_ref = bound.items[0].work_ref
    blocked = record_campaign_result(
        bound, work_ref, CampaignWorkState.THRESHOLD_BLOCKED,
        recovery_ref=RUN_REF, evidence="sat_too_many_results",
    )
    subject.initialize_campaign_manifest(storage, blocked, repo_root=repository)
    assert subject.split_campaign_manifest_work(
        storage, blocked.campaign_ref, work_ref, repo_root=repository,
    ) == split_campaign_work(blocked, work_ref)


def test_completed_work_cannot_regress_through_public_store_api(tmp_path: Path) -> None:
    repository, storage = _roots(tmp_path)
    completed = _completed_manifest()
    target = completed.items[0]
    subject.initialize_campaign_manifest(storage, completed, repo_root=repository)
    reserved = subject.reserve_campaign_manifest(storage, completed.campaign_ref, repo_root=repository)
    assert next(item for item in reserved.items if item.work_ref == target.work_ref) == target
    with pytest.raises(subject.CampaignManifestStoreError, match="campaign-state-conflict"):
        subject.initialize_campaign_manifest(
            storage, build_campaign_manifest(PROFILE), repo_root=repository,
        )
    operations = (
        lambda: subject.bind_campaign_manifest_recovery(
            storage, completed.campaign_ref, target.work_ref, RUN_REF, repo_root=repository,
        ),
        lambda: subject.record_campaign_manifest_result(
            storage, completed.campaign_ref, target.work_ref, CampaignWorkState.NO_DATA, RUN_REF,
            repo_root=repository,
        ),
        lambda: subject.split_campaign_manifest_work(
            storage, completed.campaign_ref, target.work_ref, repo_root=repository,
        ),
    )
    for operation in operations:
        with pytest.raises(CampaignManifestError):
            operation()
        assert next(
            item for item in subject.load_campaign_manifest(
                storage, completed.campaign_ref, repo_root=repository,
            ).items if item.work_ref == target.work_ref
        ) == target
    assert not hasattr(subject, "transition_campaign_manifest")


def test_secure_error_translation_preserves_uncertain_commit_state() -> None:
    translated = subject._translate(SecureStateFileError(  # noqa: SLF001
        "state-file-commit-uncertain", committed=True, uncertain=True))
    assert (translated.reason, translated.committed, translated.uncertain, translated.retry_safe) == ("campaign-state-commit-uncertain", True, True, False)
    too_large = subject._translate(SecureStateFileError(  # noqa: SLF001
        "state-file-too-large", committed=True, uncertain=True))
    assert (too_large.reason, too_large.committed, too_large.uncertain, too_large.retry_safe) == ("campaign-state-too-large", True, True, False)
