from __future__ import annotations

import json
from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest

import cfdi_vault.sat_campaign_grant as subject
import cfdi_vault.sat_campaign_manifest as campaign

NOW = datetime(2026, 7, 16, 12, tzinfo=timezone.utc)
PROFILE, COMMIT = "profile-synthetic", "a" * 40


def _grant() -> subject.CampaignGrant:
    return subject._new_campaign_grant(  # noqa: SLF001
        campaign.build_campaign_manifest(PROFILE), PROFILE, COMMIT.upper(), COMMIT, "metadata proof",
        timedelta(days=14), now=NOW)


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
     ("redactionRequired", False), ("invocationClaims", [{}]), ("submissionClaims", [{}])],
)
def test_decode_rejects_corrupted_authority(key: str, value: object) -> None:
    grant = _grant()
    document = json.loads(subject._encode_campaign_grant(grant))  # noqa: SLF001
    document[key] = value
    payload = json.dumps(document).encode()
    with pytest.raises(subject.CampaignGrantError, match="^campaign-grant-state-invalid$"):
        subject._decode_campaign_grant(payload, grant.grant_ref, COMMIT)  # noqa: SLF001
