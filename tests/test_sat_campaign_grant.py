from __future__ import annotations

import json
import re
import subprocess
from contextlib import contextmanager
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import Iterator

import pytest

import cfdi_vault.sat_campaign_grant as subject
import cfdi_vault.sat_campaign_manifest as campaign
import cfdi_vault.secure_state_file as secure_state

NOW = datetime(2026, 7, 16, 12, tzinfo=timezone.utc)
PROFILE, COMMIT = "profile-synthetic", "a" * 40
REPO_ROOT = Path(__file__).resolve().parents[1]


def _grant() -> subject.CampaignGrant:
    return subject._new_campaign_grant(  # noqa: SLF001
        campaign.build_campaign_manifest(PROFILE), PROFILE, COMMIT.upper(), COMMIT, "metadata proof",
        timedelta(days=14), now=NOW)


def _claimed_grant(
    *, invocation_count: int = 1, submission_count: int = 1,
) -> subject.CampaignGrant:
    grant = _grant()
    invocations = tuple(
        subject.CampaignInvocationClaim(
            f"inv-{index:024x}", NOW, PROFILE, COMMIT,
        )
        for index in range(invocation_count)
    )
    submissions = tuple(
        subject.CampaignSubmissionClaim(
            grant.grant_ref, invocations[index % invocation_count].invocation_ref,
            f"work-{index:012x}", f"run-{index:012x}", PROFILE, COMMIT, NOW,
        )
        for index in range(submission_count)
    )
    return replace(grant, invocation_claims=invocations, submission_claims=submissions)


def test_value_codec_and_redacted_summary_are_exact() -> None:
    grant = _grant()
    payload = subject._encode_campaign_grant(grant)  # noqa: SLF001

    assert _grant() == grant
    assert subject._decode_campaign_grant(payload, grant.grant_ref, COMMIT) == grant  # noqa: SLF001
    assert subject.campaign_grant_redacted_summary(grant) == {
        "grant_ref": grant.grant_ref, "phase": "metadata-proof",
        "expires_at": "2026-07-30T12:00:00Z", "max_outstanding": 2,
        "max_submissions": 84, "max_invocations": 4032,
        "invocation_count": 0, "submission_count": 0,
    }
    document = json.loads(payload)
    assert (document["dateFrom"], document["dateTo"], document["directions"]) == (
        "2026-01-01", "2026-07-15", ["received", "issued"],
    )
    assert document["invocationClaims"] == document["submissionClaims"] == []


def test_non_empty_claims_roundtrip_are_typed_redacted_and_counted() -> None:
    grant = _claimed_grant()
    payload = subject._encode_campaign_grant(grant)  # noqa: SLF001

    decoded = subject._decode_campaign_grant(payload, grant.grant_ref, COMMIT)  # noqa: SLF001

    assert decoded == grant
    assert isinstance(decoded.invocation_claims[0], subject.CampaignInvocationClaim)
    assert isinstance(decoded.submission_claims[0], subject.CampaignSubmissionClaim)
    assert PROFILE not in repr(decoded.invocation_claims[0])
    assert PROFILE not in repr(decoded.submission_claims[0])
    assert "run-000000000000" not in repr(decoded.submission_claims[0])
    assert subject.campaign_grant_redacted_summary(decoded)["invocation_count"] == 1
    assert subject.campaign_grant_redacted_summary(decoded)["submission_count"] == 1


def test_new_invocation_reference_is_opaque() -> None:
    first, second = subject.new_campaign_invocation_ref(), subject.new_campaign_invocation_ref()
    assert first != second
    assert re.fullmatch(r"inv-[0-9a-f]{24}", first)
    assert re.fullmatch(r"inv-[0-9a-f]{24}", second)


def test_rejects_duplicate_or_incoherent_typed_claims() -> None:
    grant = _claimed_grant(invocation_count=2)
    invocation = grant.invocation_claims[0]
    submission = grant.submission_claims[0]
    other_work = campaign.build_campaign_manifest(PROFILE).items[1].work_ref
    invalid = (
        replace(grant, invocation_claims=list(grant.invocation_claims)),  # type: ignore[arg-type]
        replace(grant, submission_claims=list(grant.submission_claims)),  # type: ignore[arg-type]
        replace(grant, invocation_claims=(invocation, invocation)),
        replace(grant, submission_claims=(submission, submission)),
        replace(grant, submission_claims=(replace(submission, recovery_ref="run-222222222222"),
                                          replace(submission, invocation_ref=grant.invocation_claims[1].invocation_ref,
                                                  recovery_ref="run-333333333333"))),
        replace(grant, submission_claims=(submission, replace(submission, work_ref=other_work))),
        replace(grant, submission_claims=(replace(submission, invocation_ref="inv-" + "f" * 24),)),
        replace(grant, invocation_claims=(replace(invocation, invocation_ref="invalid"),)),
        replace(grant, invocation_claims=(replace(invocation, claimed_at="invalid"),)),  # type: ignore[arg-type]
        replace(grant, submission_claims=(replace(submission, recovery_ref="invalid"),)),
        replace(grant, invocation_claims=(replace(invocation, profile_id="other"),)),
        replace(grant, invocation_claims=(replace(invocation, tested_commit="b" * 40),)),
        replace(grant, submission_claims=(replace(submission, grant_ref="grt-" + "f" * 24),)),
        replace(grant, submission_claims=(replace(submission, profile_id="other"),)),
        replace(grant, submission_claims=(replace(submission, tested_commit="b" * 40),)),
    )
    for corrupted in invalid:
        with pytest.raises(subject.CampaignGrantError, match="^campaign-grant-state-invalid$"):
            subject.campaign_grant_redacted_summary(corrupted)


@pytest.mark.parametrize(
    ("claim_key", "mutation"),
    [
        ("invocationClaims", {"invocationRef": "inv-" + "1" * 24, "claimedAt": "bad",
                              "profileId": PROFILE, "testedCommit": COMMIT}),
        ("invocationClaims", {"invocationRef": "inv-" + "1" * 24, "claimedAt": NOW.isoformat(),
                              "profileId": PROFILE, "testedCommit": COMMIT, "extra": True}),
        ("invocationClaims", {"invocationRef": 1, "claimedAt": "2026-07-16T12:00:00Z",
                              "profileId": PROFILE, "testedCommit": COMMIT}),
        ("submissionClaims", {"grantRef": "grt-" + "1" * 24,
                              "invocationRef": "inv-" + "1" * 24,
                              "workRef": "work-" + "1" * 12, "recoveryRef": "run-" + "1" * 12,
                              "profileId": PROFILE, "testedCommit": COMMIT}),
    ],
)
def test_decode_rejects_malformed_claim_keys_types_and_timestamps(
    claim_key: str, mutation: dict[str, object],
) -> None:
    grant = _grant()
    document = json.loads(subject._encode_campaign_grant(grant))  # noqa: SLF001
    document[claim_key] = [mutation]
    with pytest.raises(subject.CampaignGrantError, match="^campaign-grant-state-invalid$"):
        subject._decode_campaign_grant(  # noqa: SLF001
            json.dumps(document).encode(), grant.grant_ref, COMMIT,
        )


def test_valid_claim_state_larger_than_64k_roundtrips_below_1mib(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    _head(monkeypatch)
    grant = _claimed_grant(invocation_count=4032, submission_count=84)
    payload = subject._encode_campaign_grant(grant)  # noqa: SLF001
    assert 64 * 1024 < len(payload) <= 1024 * 1024
    assert subject._decode_campaign_grant(payload, grant.grant_ref, COMMIT) == grant  # noqa: SLF001
    subject.create_campaign_grant(
        tmp_path / "private", campaign.build_campaign_manifest(PROFILE), PROFILE,
        COMMIT, REPO_ROOT, "metadata proof", timedelta(days=14), now=NOW,
    )
    with secure_state.secure_state_transaction(
        tmp_path / "private", subject._filename(grant.grant_ref), repo_root=REPO_ROOT,  # noqa: SLF001
    ) as transaction:
        transaction.replace(payload)
    assert subject.load_campaign_grant(
        tmp_path / "private", grant.grant_ref, REPO_ROOT, now=NOW,
    ) == grant


def test_manifest_digest_ignores_mutable_state_recovery_and_splits() -> None:
    base = campaign.build_campaign_manifest(PROFILE)
    reserved = campaign.reserve_campaign_work(base)
    work_ref = reserved.items[0].work_ref
    bound = campaign.bind_campaign_recovery(reserved, work_ref, recovery_ref="run-111111111111")
    blocked = campaign.record_campaign_result(
        bound, work_ref, campaign.CampaignWorkState.THRESHOLD_BLOCKED,
        recovery_ref="run-111111111111", evidence="sat_too_many_results",
    )
    split = campaign.split_campaign_work(blocked, work_ref)
    assert subject._manifest_digest(base) == subject._manifest_digest(split)  # noqa: SLF001


@pytest.mark.parametrize("expires_in", [timedelta(0), timedelta(microseconds=-1),
                                        timedelta(days=14, microseconds=1)])
def test_rejects_invalid_validity(expires_in: timedelta) -> None:
    with pytest.raises(subject.CampaignGrantError, match="^campaign-grant-validity-invalid$"):
        subject._new_campaign_grant(  # noqa: SLF001
            campaign.build_campaign_manifest(PROFILE), PROFILE, COMMIT, COMMIT, "proof", expires_in, now=NOW)


@pytest.mark.parametrize(
    ("created_at", "expires_at"),
    [(NOW.replace(tzinfo=None), (NOW + timedelta(days=1)).replace(tzinfo=None)),
     (NOW, (NOW + timedelta(days=1)).replace(tzinfo=None)), ("invalid", NOW)],
)
def test_summary_rejects_invalid_datetime_values(created_at: object, expires_at: object) -> None:
    grant = replace(_grant(), created_at=created_at, expires_at=expires_at)  # type: ignore[arg-type]
    with pytest.raises(subject.CampaignGrantError, match="^campaign-grant-state-invalid$"):
        subject.campaign_grant_redacted_summary(grant)


@pytest.mark.parametrize(
    ("field", "value"),
    [("profile", ""), ("profile", "../profile"), ("profile", "other-profile"),
     ("reason", ""), ("reason", "../proof"), ("reason", "proof\nnext")],
)
def test_rejects_blank_hostile_or_mismatched_identity(field: str, value: str) -> None:
    profile, reason = (value, "proof") if field == "profile" else (PROFILE, value)
    with pytest.raises(subject.CampaignGrantError, match="^campaign-grant-"):
        subject._new_campaign_grant(  # noqa: SLF001
            campaign.build_campaign_manifest(PROFILE), profile, COMMIT, COMMIT, reason,
            timedelta(days=1), now=NOW,
        )


@pytest.mark.parametrize("tested", ["bad", "g" * 40, "0" * 40])
def test_rejects_invalid_or_wrong_commit(tested: str) -> None:
    with pytest.raises(subject.CampaignGrantError, match="^campaign-grant-commit-"):
        subject._new_campaign_grant(  # noqa: SLF001
            campaign.build_campaign_manifest(PROFILE), PROFILE, tested, COMMIT, "proof",
            timedelta(days=1), now=NOW,
        )


def test_rejects_fixed_policy_mismatch() -> None:
    manifest = campaign.build_campaign_manifest(PROFILE)
    object.__setattr__(manifest, "max_outstanding", 3)
    with pytest.raises(subject.CampaignGrantError, match="^campaign-grant-manifest-invalid$"):
        subject._new_campaign_grant(  # noqa: SLF001
            manifest, PROFILE, COMMIT, COMMIT, "proof", timedelta(days=1), now=NOW,
        )


@pytest.mark.parametrize(
    ("key", "value"),
    [("schemaVersion", 2), ("phase", "continue"), ("campaignRef", "cmp-000000000000"),
     ("manifestDigest", "0" * 64), ("testedCommit", "0" * 40),
     ("dateFrom", "2026-01-02"), ("directions", ["issued", "received"]),
     ("maxOutstanding", 3), ("maxSubmissions", 85), ("maxInvocations", 1),
     ("redactionRequired", False)],
)
def test_decode_rejects_corrupted_authority(key: str, value: object) -> None:
    grant = _grant()
    document = json.loads(subject._encode_campaign_grant(grant))  # noqa: SLF001
    document[key] = value
    payload = json.dumps(document).encode()
    with pytest.raises(subject.CampaignGrantError, match="^campaign-grant-state-invalid$"):
        subject._decode_campaign_grant(payload, grant.grant_ref, COMMIT)  # noqa: SLF001


def _head(monkeypatch: pytest.MonkeyPatch, commit: str = COMMIT) -> None:
    monkeypatch.setattr(subject, "_repository_context", lambda repo_root: (REPO_ROOT.resolve(), commit))


def test_create_and_load_roundtrip_in_external_storage(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    _head(monkeypatch)
    manifest = campaign.build_campaign_manifest(PROFILE)

    grant = subject.create_campaign_grant(
        tmp_path / "private", manifest, PROFILE, COMMIT, REPO_ROOT,
        "metadata proof", timedelta(days=14), now=NOW,
    )

    assert subject.load_campaign_grant(
        tmp_path / "private", grant.grant_ref, REPO_ROOT, now=NOW,
    ) == grant
    names = [path.name for path in (tmp_path / "private").rglob("*")]
    assert PROFILE not in " ".join(names)
    assert manifest.campaign_ref not in " ".join(names)


def test_create_for_current_commit_rechecks_head_before_persistence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    heads = iter(((REPO_ROOT.resolve(), COMMIT), (REPO_ROOT.resolve(), "b" * 40)))
    monkeypatch.setattr(subject, "_repository_context", lambda _root: next(heads))
    with pytest.raises(subject.CampaignGrantError, match="^campaign-grant-commit-mismatch$"):
        subject.create_campaign_grant_for_current_commit(
            storage_root=tmp_path / "private",
            manifest=campaign.build_campaign_manifest(PROFILE), profile_id=PROFILE,
            repo_root=REPO_ROOT, reason="metadata proof", expires_in=timedelta(days=14),
        )
    assert not (tmp_path / "private").exists()


def test_each_create_uses_a_distinct_opaque_reference(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    _head(monkeypatch)
    manifest = campaign.build_campaign_manifest(PROFILE)
    first = subject.create_campaign_grant(
        tmp_path / "private", manifest, PROFILE, COMMIT, REPO_ROOT,
        "metadata proof", timedelta(days=1), now=NOW,
    )
    second = subject.create_campaign_grant(
        tmp_path / "private", manifest, PROFILE, COMMIT, REPO_ROOT,
        "metadata proof", timedelta(days=1), now=NOW + timedelta(microseconds=1),
    )
    assert first.grant_ref != second.grant_ref


def test_create_rejects_an_existing_grant_reference(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    _head(monkeypatch)
    arguments = (
        tmp_path / "private", campaign.build_campaign_manifest(PROFILE), PROFILE,
        COMMIT, REPO_ROOT, "metadata proof", timedelta(days=1),
    )
    subject.create_campaign_grant(*arguments, now=NOW)
    with pytest.raises(subject.CampaignGrantError, match="^campaign-grant-ref-collision$"):
        subject.create_campaign_grant(*arguments, now=NOW)


@pytest.mark.parametrize("tested", ["bad", "A" * 40, "b" * 40])
def test_create_rejects_noncanonical_or_mismatched_head_before_write(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, tested: str,
) -> None:
    _head(monkeypatch)

    def unexpected(*args: object, **kwargs: object) -> None:
        raise AssertionError("storage must not be opened")

    monkeypatch.setattr(subject, "secure_state_transaction", unexpected, raising=False)
    with pytest.raises(subject.CampaignGrantError, match="^campaign-grant-commit-"):
        subject.create_campaign_grant(
            tmp_path / "private", campaign.build_campaign_manifest(PROFILE), PROFILE,
            tested, REPO_ROOT, "metadata proof", timedelta(days=1), now=NOW,
        )


@pytest.mark.parametrize("repo_root", [REPO_ROOT, REPO_ROOT / "src"])
def test_create_rejects_storage_inside_checkout_even_from_subdirectory(
    monkeypatch: pytest.MonkeyPatch, repo_root: Path,
) -> None:
    _head(monkeypatch)

    @contextmanager
    def contained(*args: object, **kwargs: object) -> Iterator[None]:
        assert kwargs["repo_root"] == REPO_ROOT.resolve()
        raise secure_state.SecureStateFileError("storage-root-inside-repository")
        yield

    monkeypatch.setattr(subject, "secure_state_transaction", contained)
    with pytest.raises(subject.CampaignGrantError, match="^campaign-grant-path-invalid$"):
        subject.create_campaign_grant(
            REPO_ROOT / "private-state", campaign.build_campaign_manifest(PROFILE), PROFILE,
            COMMIT, repo_root, "metadata proof", timedelta(days=1), now=NOW,
        )


def test_load_rejects_changed_repository_head(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    _head(monkeypatch)
    grant = subject.create_campaign_grant(
        tmp_path / "private", campaign.build_campaign_manifest(PROFILE), PROFILE,
        COMMIT, REPO_ROOT, "metadata proof", timedelta(days=1), now=NOW,
    )
    _head(monkeypatch, "b" * 40)
    with pytest.raises(subject.CampaignGrantError, match="^campaign-grant-state-invalid$"):
        subject.load_campaign_grant(tmp_path / "private", grant.grant_ref, REPO_ROOT)


def test_load_rejects_expired_grant(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    _head(monkeypatch)
    grant = subject.create_campaign_grant(
        tmp_path / "private", campaign.build_campaign_manifest(PROFILE), PROFILE,
        COMMIT, REPO_ROOT, "metadata proof", timedelta(days=1), now=NOW,
    )
    with pytest.raises(subject.CampaignGrantError, match="^campaign-grant-expired$"):
        subject.load_campaign_grant(
            tmp_path / "private", grant.grant_ref, REPO_ROOT, now=NOW + timedelta(days=1),
        )


def test_local_reconciliation_evidence_allows_expiry_but_rejects_future_or_changed_head(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    _head(monkeypatch)
    grant = subject.create_campaign_grant(
        tmp_path / "private", campaign.build_campaign_manifest(PROFILE), PROFILE,
        COMMIT, REPO_ROOT, "metadata proof", timedelta(days=1), now=NOW)
    path = next((tmp_path / "private").rglob(subject._filename(grant.grant_ref)))  # noqa: SLF001
    before = path.read_bytes()
    evidence = subject.load_campaign_local_reconciliation_evidence(
        tmp_path / "private", grant.grant_ref, REPO_ROOT, now=NOW + timedelta(days=2))
    assert evidence.grant == grant and path.read_bytes() == before
    assert evidence.authorizes_sat_contact is False
    assert "metadata proof" not in repr(evidence)
    with pytest.raises(TypeError, match="construction-denied"):
        subject.CampaignLocalReconciliationEvidence()
    with pytest.raises(AttributeError, match="immutable"):
        evidence.grant = grant  # type: ignore[misc]
    with pytest.raises(subject.CampaignGrantError, match="campaign-grant-not-yet-valid"):
        subject.load_campaign_local_reconciliation_evidence(
            tmp_path / "private", grant.grant_ref, REPO_ROOT, now=NOW - timedelta(seconds=1))
    _head(monkeypatch, "b" * 40)
    with pytest.raises(subject.CampaignGrantError, match="campaign-grant-state-invalid"):
        subject.load_campaign_local_reconciliation_evidence(
            tmp_path / "private", grant.grant_ref, REPO_ROOT, now=NOW)


@pytest.mark.parametrize(
    ("payload", "reason"),
    [(b"{", "campaign-grant-state-invalid"),
     (b"x" * (1024 * 1024 + 1), "campaign-grant-state-too-large")],
    ids=("corrupt", "oversize"),
)
def test_load_rejects_corrupt_or_oversize_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, payload: bytes, reason: str,
) -> None:
    _head(monkeypatch)
    grant = subject.create_campaign_grant(
        tmp_path / "private", campaign.build_campaign_manifest(PROFILE), PROFILE,
        COMMIT, REPO_ROOT, "metadata proof", timedelta(days=1), now=NOW,
    )
    with secure_state.secure_state_transaction(
        tmp_path / "private", subject._filename(grant.grant_ref), repo_root=REPO_ROOT,  # noqa: SLF001
    ) as transaction:
        transaction.replace(payload)
    with pytest.raises(subject.CampaignGrantError, match=f"^{reason}$"):
        subject.load_campaign_grant(tmp_path / "private", grant.grant_ref, REPO_ROOT)


def test_load_rejects_missing_and_malicious_references(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    _head(monkeypatch)
    with pytest.raises(subject.CampaignGrantError, match="^campaign-grant-state-not-found$"):
        subject.load_campaign_grant(tmp_path / "private", "grt-" + "1" * 24, REPO_ROOT)
    for grant_ref in ("../state", "grt-" + "1" * 23, "C:/private/grant"):
        with pytest.raises(subject.CampaignGrantError, match="^campaign-grant-ref-invalid$"):
            subject.load_campaign_grant(tmp_path / "private", grant_ref, REPO_ROOT)


@pytest.mark.parametrize(
    ("operation", "failure", "reason"),
    [("read", PermissionError("private"), "campaign-grant-state-unreadable"),
     ("write", OSError("private"), "campaign-grant-state-write-failed")],
)
def test_secure_state_filesystem_failures_are_sanitized(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    operation: str, failure: OSError, reason: str,
) -> None:
    _head(monkeypatch)
    target = "_read" if operation == "read" else "_atomic_write"
    monkeypatch.setattr(secure_state, target, lambda *args, **kwargs: (_ for _ in ()).throw(failure))
    def call() -> None:
        if operation == "read":
            subject.load_campaign_grant(
                tmp_path / "private", "grt-" + "1" * 24, REPO_ROOT,
            )
            return
        subject.create_campaign_grant(
            tmp_path / "private", campaign.build_campaign_manifest(PROFILE), PROFILE,
            COMMIT, REPO_ROOT, "metadata proof", timedelta(days=1), now=NOW,
        )
    with pytest.raises(subject.CampaignGrantError, match=f"^{reason}$") as captured:
        call()
    assert captured.value.retry_safe is True


def test_secure_state_uncertainty_flags_are_preserved(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    _head(monkeypatch)

    @contextmanager
    def uncertain(*args: object, **kwargs: object) -> Iterator[None]:
        raise secure_state.SecureStateFileError(
            "state-file-commit-uncertain", committed=True, uncertain=True,
        )
        yield

    monkeypatch.setattr(subject, "secure_state_transaction", uncertain, raising=False)
    with pytest.raises(subject.CampaignGrantError, match="^campaign-grant-state-commit-uncertain$") as captured:
        subject.create_campaign_grant(
            tmp_path / "private", campaign.build_campaign_manifest(PROFILE), PROFILE,
            COMMIT, REPO_ROOT, "metadata proof", timedelta(days=1), now=NOW,
        )
    assert (captured.value.committed, captured.value.uncertain, captured.value.retry_safe) == (
        True, True, False,
    )


@pytest.mark.parametrize(
    "failure",
    [PermissionError("sensitive path"),
     UnicodeDecodeError("utf-8", b"\xff", 0, 1, "invalid"),
     SimpleNamespace(returncode=1, stdout="secret", stderr="secret")],
)
def test_repository_git_failure_is_sanitized(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: object,
) -> None:
    if isinstance(failure, BaseException):
        monkeypatch.setattr(subprocess, "run", lambda *args, **kwargs: (_ for _ in ()).throw(failure))
    else:
        monkeypatch.setattr(subprocess, "run", lambda *args, **kwargs: failure)
    with pytest.raises(subject.CampaignGrantError, match="^campaign-grant-repository-unavailable$"):
        subject.create_campaign_grant(
            tmp_path / "private", campaign.build_campaign_manifest(PROFILE), PROFILE,
            COMMIT, REPO_ROOT, "metadata proof", timedelta(days=1), now=NOW,
        )


def test_repository_context_clears_git_overrides_and_canonicalizes_subdir(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("GIT_DIR", "redirected")
    monkeypatch.setenv("git_work_tree", "redirected")

    def run(command: list[str], **kwargs: object) -> SimpleNamespace:
        assert command == ["git", "rev-parse", "--show-toplevel", "HEAD"]
        assert kwargs["cwd"] == (REPO_ROOT / "src").resolve()
        assert not any(key.upper().startswith("GIT_") for key in kwargs["env"])
        return SimpleNamespace(returncode=0, stdout=f"{REPO_ROOT}\n{COMMIT}\n", stderr="")

    monkeypatch.setattr(subprocess, "run", run)
    assert subject._repository_context(REPO_ROOT / "src") == (REPO_ROOT.resolve(), COMMIT)  # noqa: SLF001
