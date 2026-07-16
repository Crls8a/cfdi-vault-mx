from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import Mock

import pytest

import cfdi_vault.sat_campaign_manifest_store as subject
from cfdi_vault.sat_campaign_manifest import (
    CampaignManifestError,
    bind_campaign_recovery,
    build_campaign_manifest,
    reserve_campaign_work,
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


def test_transition_is_atomic_noop_and_preserves_domain_errors(tmp_path: Path, monkeypatch) -> None:
    repository, storage = _roots(tmp_path)
    manifest = build_campaign_manifest(PROFILE)
    subject.initialize_campaign_manifest(storage, manifest, repo_root=repository)
    write = Mock(wraps=subject._replace)  # noqa: SLF001
    monkeypatch.setattr(subject, "_replace", write)
    assert subject.transition_campaign_manifest(
        storage, manifest.campaign_ref, lambda value: value, repo_root=repository,
    ) == manifest
    write.assert_not_called()
    reserved = subject.transition_campaign_manifest(
        storage, manifest.campaign_ref, reserve_campaign_work, repo_root=repository,
    )
    assert reserved == reserve_campaign_work(manifest) and write.call_count == 1
    expected = CampaignManifestError("synthetic-domain-error")
    with pytest.raises(CampaignManifestError) as raised:
        subject.transition_campaign_manifest(
            storage, manifest.campaign_ref, lambda _: (_ for _ in ()).throw(expected),
            repo_root=repository,
        )
    assert raised.value is expected
    with pytest.raises(subject.CampaignManifestStoreError, match="campaign-state-invalid"):
        subject.transition_campaign_manifest(
            storage, manifest.campaign_ref, lambda _: object(), repo_root=repository,  # type: ignore[arg-type,return-value]
        )
    with pytest.raises(subject.CampaignManifestStoreError, match="campaign-state-identity-change"):
        subject.transition_campaign_manifest(
            storage, manifest.campaign_ref, lambda _: build_campaign_manifest("profile-other"),
            repo_root=repository,
        )


def test_secure_error_translation_preserves_uncertain_commit_state() -> None:
    translated = subject._translate(SecureStateFileError(  # noqa: SLF001
        "state-file-commit-uncertain", committed=True, uncertain=True))
    assert (translated.reason, translated.committed, translated.uncertain, translated.retry_safe) == ("campaign-state-commit-uncertain", True, True, False)
