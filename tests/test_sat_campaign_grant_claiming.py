from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from threading import Barrier, Event
from typing import Iterator

import pytest

import cfdi_vault.sat_campaign_grant as subject
import cfdi_vault.sat_campaign_manifest as campaign
import cfdi_vault.secure_state_file as secure_state

NOW = datetime(2026, 7, 16, 12, tzinfo=timezone.utc)
PROFILE, COMMIT = "profile-synthetic", "a" * 40
REPO_ROOT = Path(__file__).resolve().parents[1]


def _create(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> subject.CampaignGrant:
    monkeypatch.setattr(subject, "_repository_context", lambda _: (REPO_ROOT, COMMIT))
    return subject.create_campaign_grant(
        tmp_path / "private", campaign.build_campaign_manifest(PROFILE), PROFILE,
        COMMIT, REPO_ROOT, "metadata proof", timedelta(days=14), now=NOW,
    )


def _persist(tmp_path: Path, grant: subject.CampaignGrant) -> None:
    with secure_state.secure_state_transaction(
        tmp_path / "private", subject._filename(grant.grant_ref), repo_root=REPO_ROOT,  # noqa: SLF001
    ) as transaction:
        transaction.replace(subject._encode_campaign_grant(grant))  # noqa: SLF001


def _bound_manifest() -> tuple[campaign.SatCampaignManifest, str, str]:
    reserved = campaign.reserve_campaign_work(campaign.build_campaign_manifest(PROFILE))
    item = next(value for value in reserved.items if value.state is campaign.CampaignWorkState.OUTSTANDING)
    recovery_ref = "run-111111111111"
    return campaign.bind_campaign_recovery(
        reserved, item.work_ref, recovery_ref=recovery_ref,
    ), item.work_ref, recovery_ref


def test_invocation_claim_create_and_exact_retry_are_atomic(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    grant = _create(tmp_path, monkeypatch)
    arguments = (tmp_path / "private", grant.grant_ref, "inv-" + "1" * 24,
                 PROFILE, REPO_ROOT)
    first = subject.claim_campaign_grant_invocation(*arguments, now=NOW)
    second = subject.claim_campaign_grant_invocation(*arguments, now=NOW + timedelta(seconds=1))
    assert first.created is True and second.created is False
    assert first.claim == second.claim
    assert subject.load_campaign_grant(
        tmp_path / "private", grant.grant_ref, REPO_ROOT, now=NOW,
    ).invocation_claims == (first.claim,)


@pytest.mark.parametrize(
    ("now", "profile", "reason"),
    [(NOW - timedelta(microseconds=1), PROFILE, "campaign-grant-not-yet-valid"),
     (NOW + timedelta(days=14), PROFILE, "campaign-grant-expired"),
     (NOW.replace(tzinfo=None), PROFILE, "campaign-grant-time-invalid"),
     (NOW, "other-profile", "campaign-grant-profile-mismatch")],
)
def test_invocation_rejects_time_and_profile(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    now: datetime, profile: str, reason: str,
) -> None:
    grant = _create(tmp_path, monkeypatch)
    with pytest.raises(subject.CampaignGrantError, match=f"^{reason}$"):
        subject.claim_campaign_grant_invocation(
            tmp_path / "private", grant.grant_ref, "inv-" + "1" * 24,
            profile, REPO_ROOT, now=now,
        )


def test_invocation_ref_collision_and_limit_are_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    grant = _create(tmp_path, monkeypatch)
    collision = replace(grant, invocation_claims=(subject.CampaignInvocationClaim(
        "inv-" + "1" * 24, NOW, PROFILE, COMMIT,
    ),))
    _persist(tmp_path, collision)
    with pytest.raises(subject.CampaignGrantError, match="^campaign-grant-invocation-conflict$"):
        subject.claim_campaign_grant_invocation(
            tmp_path / "private", grant.grant_ref, "inv-" + "1" * 24,
            "other-profile", REPO_ROOT, now=NOW,
        )
    full = replace(grant, invocation_claims=tuple(
        subject.CampaignInvocationClaim(f"inv-{index:024x}", NOW, PROFILE, COMMIT)
        for index in range(4032)
    ))
    _persist(tmp_path, full)
    with pytest.raises(subject.CampaignGrantError, match="^campaign-grant-invocation-limit$"):
        subject.claim_campaign_grant_invocation(
            tmp_path / "private", grant.grant_ref, "inv-" + "f" * 24,
            PROFILE, REPO_ROOT, now=NOW,
        )


def test_concurrent_same_invocation_claim_creates_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    grant = _create(tmp_path, monkeypatch)
    start, busy_seen = Barrier(2), Event()
    original_read = secure_state._read  # noqa: SLF001
    def hold_first_read(*args: object, **kwargs: object) -> bytes | None:
        assert busy_seen.wait(2)
        return original_read(*args, **kwargs)  # type: ignore[arg-type]
    monkeypatch.setattr(secure_state, "_read", hold_first_read)

    def claim() -> subject.CampaignGrantClaimOutcome:
        start.wait()
        for _ in range(100):
            try:
                return subject.claim_campaign_grant_invocation(
                    tmp_path / "private", grant.grant_ref, "inv-" + "1" * 24,
                    PROFILE, REPO_ROOT, now=NOW,
                )
            except subject.CampaignGrantError as error:
                if error.reason != "campaign-grant-state-busy":
                    raise
                busy_seen.set()
                time.sleep(0.005)
        raise AssertionError("claim lock did not become available")

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = tuple(pool.map(lambda _: claim(), range(2)))
    assert sorted(item.created for item in outcomes) == [False, True]
    assert busy_seen.is_set()


def test_submission_create_exact_retry_and_conflicts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    grant = _create(tmp_path, monkeypatch)
    manifest, work_ref, recovery_ref = _bound_manifest()
    first_invocation, second_invocation = "inv-" + "1" * 24, "inv-" + "2" * 24
    for invocation_ref in (first_invocation, second_invocation):
        subject.claim_campaign_grant_invocation(
            tmp_path / "private", grant.grant_ref, invocation_ref, PROFILE, REPO_ROOT, now=NOW,
        )
    arguments = (tmp_path / "private", grant.grant_ref, first_invocation,
                 manifest, work_ref, recovery_ref, PROFILE, REPO_ROOT)
    first = subject.claim_campaign_grant_submission(*arguments, now=NOW)
    assert first.created is True
    assert subject.claim_campaign_grant_submission(
        *arguments, now=NOW + timedelta(seconds=1),
    ).created is False
    other_work = next(item.work_ref for item in manifest.items if item.work_ref != work_ref
                      and item.state is campaign.CampaignWorkState.OUTSTANDING)
    for changed in ((second_invocation, work_ref, recovery_ref),
                    (first_invocation, work_ref, "run-222222222222"),
                    (first_invocation, other_work, recovery_ref)):
        with pytest.raises(subject.CampaignGrantError, match="^campaign-grant-submission-conflict$"):
            subject.claim_campaign_grant_submission(
                tmp_path / "private", grant.grant_ref, changed[0], manifest,
                changed[1], changed[2], PROFILE, REPO_ROOT, now=NOW,
            )


@pytest.mark.parametrize(
    ("variant", "reason"),
    [("missing-invocation", "campaign-grant-invocation-not-found"),
     ("wrong-manifest", "campaign-grant-manifest-mismatch"),
     ("planned", "campaign-grant-work-not-outstanding"),
     ("unbound", "campaign-grant-recovery-unbound"),
     ("mismatch", "campaign-grant-recovery-mismatch")],
)
def test_submission_rejects_invalid_lineage_and_manifest_work_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, variant: str, reason: str,
) -> None:
    grant = _create(tmp_path, monkeypatch)
    invocation_ref = "inv-" + "1" * 24
    subject.claim_campaign_grant_invocation(
        tmp_path / "private", grant.grant_ref, invocation_ref, PROFILE, REPO_ROOT, now=NOW,
    )
    manifest, work_ref, recovery_ref = _bound_manifest()
    if variant == "missing-invocation":
        invocation_ref = "inv-" + "2" * 24
    elif variant == "wrong-manifest":
        manifest = campaign.build_campaign_manifest("other-profile")
    elif variant == "planned":
        manifest = campaign.build_campaign_manifest(PROFILE)
    elif variant == "unbound":
        manifest = campaign.reserve_campaign_work(campaign.build_campaign_manifest(PROFILE))
    elif variant == "mismatch":
        recovery_ref = "run-222222222222"
    with pytest.raises(subject.CampaignGrantError, match=f"^{reason}$"):
        subject.claim_campaign_grant_submission(
            tmp_path / "private", grant.grant_ref, invocation_ref, manifest,
            work_ref, recovery_ref, PROFILE, REPO_ROOT, now=NOW,
        )


@pytest.mark.parametrize(
    ("per_invocation", "total", "reason"),
    [(2, 2, "campaign-grant-invocation-submission-limit"),
     (0, 84, "campaign-grant-submission-limit")],
)
def test_submission_limits_are_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    per_invocation: int, total: int, reason: str,
) -> None:
    grant = _create(tmp_path, monkeypatch)
    invocation_ref = "inv-" + "f" * 24
    invocations = (subject.CampaignInvocationClaim(invocation_ref, NOW, PROFILE, COMMIT),)
    submissions = tuple(subject.CampaignSubmissionClaim(
        grant.grant_ref, invocation_ref if index < per_invocation else "inv-" + f"{index:024x}",
        f"work-{index:012x}", f"run-{index:012x}", PROFILE, COMMIT, NOW,
    ) for index in range(total))
    extra_invocations = tuple(subject.CampaignInvocationClaim(
        claim.invocation_ref, NOW, PROFILE, COMMIT,
    ) for claim in submissions if claim.invocation_ref != invocation_ref)
    _persist(tmp_path, replace(grant, invocation_claims=(*invocations, *extra_invocations),
                               submission_claims=submissions))
    manifest, work_ref, recovery_ref = _bound_manifest()
    with pytest.raises(subject.CampaignGrantError, match=f"^{reason}$"):
        subject.claim_campaign_grant_submission(
            tmp_path / "private", grant.grant_ref, invocation_ref, manifest,
            work_ref, recovery_ref, PROFILE, REPO_ROOT, now=NOW,
        )


def test_claim_write_uncertainty_flags_are_preserved(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    grant = _create(tmp_path, monkeypatch)

    @contextmanager
    def uncertain(*args: object, **kwargs: object) -> Iterator[None]:
        raise secure_state.SecureStateFileError(
            "state-file-commit-uncertain", committed=True, uncertain=True,
        )
        yield

    monkeypatch.setattr(subject, "secure_state_transaction", uncertain)
    with pytest.raises(subject.CampaignGrantError) as captured:
        subject.claim_campaign_grant_invocation(
            tmp_path / "private", grant.grant_ref, "inv-" + "1" * 24,
            PROFILE, REPO_ROOT, now=NOW,
        )
    assert (captured.value.committed, captured.value.uncertain,
            captured.value.retry_safe) == (True, True, False)
