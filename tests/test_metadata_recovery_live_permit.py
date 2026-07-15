from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from cfdi_vault.live_permit import (
    METADATA_RECOVERY_LIVE_SCOPE,
    LivePermitError,
    LivePermitRequest,
    create_live_execution_permit,
    load_live_execution_permit,
    validate_and_consume_live_permit,
    validate_consumed_metadata_recovery_permit,
    validate_consumed_metadata_recovery_permit_id,
)

NOW = datetime(2026, 7, 15, 15, 0, tzinfo=timezone.utc)


def _request(**overrides: object) -> LivePermitRequest:
    values: dict[str, object] = {
        "scope": METADATA_RECOVERY_LIVE_SCOPE,
        "profile_id": "dummy-profile",
        "kind": "metadata",
        "direction": "received",
        "date_from": "2026-06-30",
        "date_to": "2026-06-30",
        "reason": "Carlos authorized one metadata recovery test",
    }
    values.update(overrides)
    return LivePermitRequest(**values)  # type: ignore[arg-type]


def _create(tmp_path: Path, *, scope: str = METADATA_RECOVERY_LIVE_SCOPE):
    env = {"LOCALAPPDATA": str(tmp_path / "appdata")}
    repo_root = tmp_path / "repo"
    repo_root.mkdir(exist_ok=True)
    permit = create_live_execution_permit(
        _request(scope=scope), env=env, now=NOW, repo_root=repo_root
    )
    return permit, env, repo_root


def _consume(permit_id: str, env: dict[str, str], repo_root: Path):
    return validate_and_consume_live_permit(
        permit_id,
        scope=METADATA_RECOVERY_LIVE_SCOPE,
        profile_id="dummy-profile",
        kind="metadata",
        direction="received",
        date_from="2026-06-30",
        date_to="2026-06-30",
        env=env,
        now=NOW + timedelta(minutes=1),
        repo_root=repo_root,
    )


def _continue(
    permit_id: str,
    env: dict[str, str],
    repo_root: Path,
    *,
    now: datetime,
    **overrides: str,
):
    values = {
        "profile_id": "dummy-profile",
        "direction": "received",
        "date_from": "2026-06-30",
        "date_to": "2026-06-30",
    }
    values.update(overrides)
    return validate_consumed_metadata_recovery_permit(
        permit_id, env=env, now=now, repo_root=repo_root, **values
    )


def _mutate_document(path: Path, key: str, value: object) -> None:
    document = json.loads(path.read_text(encoding="utf-8"))
    document[key] = value
    path.write_text(json.dumps(document), encoding="utf-8")


def test_metadata_recovery_permit_is_exact_credentialed_and_reusable_through_day_seven(
    tmp_path: Path,
) -> None:
    permit, env, repo_root = _create(tmp_path)

    assert permit.max_range_days == 7
    assert permit.max_attempts == 1
    assert permit.allow_real_sat is True
    assert permit.allow_real_credentials is True
    assert load_live_execution_permit(permit.permit_id, env=env).permit_id == permit.permit_id

    consumed = _consume(permit.permit_id, env, repo_root)
    assert consumed.consumed_at is not None
    assert consumed.path is not None
    original = consumed.path.read_bytes()

    at_consumption = _continue(
        permit.permit_id, env, repo_root, now=consumed.consumed_at
    )
    at_boundary = _continue(
        permit.permit_id,
        env,
        repo_root,
        now=consumed.consumed_at + timedelta(days=7),
    )

    assert at_consumption.permit_id == permit.permit_id
    assert at_boundary.permit_id == permit.permit_id
    assert consumed.path.read_bytes() == original


def test_metadata_recovery_continuation_rejects_after_day_seven(tmp_path: Path) -> None:
    permit, env, repo_root = _create(tmp_path)
    consumed = _consume(permit.permit_id, env, repo_root)
    assert consumed.consumed_at is not None

    with pytest.raises(LivePermitError, match="permit-continuation-expired"):
        _continue(
            permit.permit_id,
            env,
            repo_root,
            now=consumed.consumed_at + timedelta(days=7, microseconds=1),
        )


def test_metadata_recovery_continuation_requires_prior_consumption(tmp_path: Path) -> None:
    permit, env, repo_root = _create(tmp_path)

    with pytest.raises(LivePermitError, match="permit-not-consumed"):
        _continue(permit.permit_id, env, repo_root, now=NOW + timedelta(minutes=1))


@pytest.mark.parametrize(
    ("consumed_at", "reason"),
    [
        ((NOW - timedelta(seconds=1)).isoformat(), "permit-consumption-invalid"),
        ((NOW + timedelta(minutes=15, seconds=1)).isoformat(), "permit-consumption-invalid"),
        (None, "permit-not-consumed"),
    ],
)
def test_metadata_recovery_continuation_rejects_invalid_original_consumption(
    tmp_path: Path, consumed_at: str | None, reason: str
) -> None:
    permit, env, repo_root = _create(tmp_path)
    assert permit.path is not None
    _mutate_document(permit.path, "consumed", True)
    _mutate_document(permit.path, "consumedAt", consumed_at)

    with pytest.raises(LivePermitError, match=reason):
        _continue(permit.permit_id, env, repo_root, now=NOW + timedelta(minutes=2))


def test_metadata_recovery_continuation_rejects_time_before_consumption(tmp_path: Path) -> None:
    permit, env, repo_root = _create(tmp_path)
    consumed = _consume(permit.permit_id, env, repo_root)
    assert consumed.consumed_at is not None

    with pytest.raises(LivePermitError, match="permit-continuation-before-consumption"):
        _continue(
            permit.permit_id,
            env,
            repo_root,
            now=consumed.consumed_at - timedelta(microseconds=1),
        )


@pytest.mark.parametrize(
    ("override", "reason"),
    [
        ({"profile_id": "other-profile"}, "permit-profileId-mismatch"),
        ({"direction": "issued"}, "permit-direction-mismatch"),
        ({"date_from": "2026-06-29"}, "permit-dateFrom-mismatch"),
        ({"date_to": "2026-07-01"}, "permit-dateTo-mismatch"),
    ],
)
def test_metadata_recovery_continuation_requires_exact_identity(
    tmp_path: Path, override: dict[str, str], reason: str
) -> None:
    permit, env, repo_root = _create(tmp_path)
    consumed = _consume(permit.permit_id, env, repo_root)
    assert consumed.consumed_at is not None

    with pytest.raises(LivePermitError, match=reason):
        _continue(
            permit.permit_id,
            env,
            repo_root,
            now=consumed.consumed_at,
            **override,
        )


def test_metadata_recovery_continuation_rejects_other_scope(tmp_path: Path) -> None:
    permit, env, repo_root = _create(tmp_path, scope="transport_probe")
    validate_and_consume_live_permit(
        permit.permit_id,
        scope="transport_probe",
        profile_id="dummy-profile",
        kind="metadata",
        direction="received",
        date_from="2026-06-30",
        date_to="2026-06-30",
        env=env,
        now=NOW + timedelta(minutes=1),
        repo_root=repo_root,
    )

    with pytest.raises(LivePermitError, match="permit-scope-mismatch"):
        _continue(permit.permit_id, env, repo_root, now=NOW + timedelta(minutes=1))


def test_metadata_recovery_continuation_rejects_commit_drift(tmp_path: Path) -> None:
    permit, env, repo_root = _create(tmp_path)
    consumed = _consume(permit.permit_id, env, repo_root)
    drifted_root = tmp_path / "other-repo"
    drifted_root.mkdir()
    assert consumed.consumed_at is not None

    with pytest.raises(LivePermitError, match="permit-repo-identity-mismatch"):
        _continue(permit.permit_id, env, drifted_root, now=consumed.consumed_at)


@pytest.mark.parametrize(
    ("key", "value", "reason"),
    [
        ("maxRangeDays", 1, "permit-range-policy-invalid"),
        ("maxAttempts", 2, "permit-attempt-policy-invalid"),
        ("allowRealSat", False, "permit-real-sat-not-allowed"),
        ("allowRealCredentials", False, "permit-real-credentials-not-allowed"),
        ("redactionRequired", False, "permit-redaction-required"),
        ("authEnvelopeVariant", "security_only", "permit-auth-envelope-options-not-applicable"),
        ("wcfActionHeaderEnabled", True, "permit-auth-envelope-options-not-applicable"),
    ],
)
def test_metadata_recovery_continuation_revalidates_security_policy(
    tmp_path: Path, key: str, value: object, reason: str
) -> None:
    permit, env, repo_root = _create(tmp_path)
    consumed = _consume(permit.permit_id, env, repo_root)
    assert consumed.path is not None
    assert consumed.consumed_at is not None
    _mutate_document(consumed.path, key, value)

    with pytest.raises(LivePermitError, match=reason):
        _continue(permit.permit_id, env, repo_root, now=consumed.consumed_at)


def test_metadata_recovery_continuation_rejects_unsafe_explicit_path(tmp_path: Path) -> None:
    permit, env, repo_root = _create(tmp_path)
    consumed = _consume(permit.permit_id, env, repo_root)
    outside = tmp_path / "outside.json"
    assert consumed.path is not None
    outside.write_bytes(consumed.path.read_bytes())

    with pytest.raises(LivePermitError, match="permit-outside-appdata"):
        validate_consumed_metadata_recovery_permit(
            outside,
            profile_id="dummy-profile",
            direction="received",
            date_from="2026-06-30",
            date_to="2026-06-30",
            env=env,
            now=NOW + timedelta(minutes=1),
            repo_root=repo_root,
        )


@pytest.mark.parametrize("reference", ["permit.json", "../permit-id", r"C:\permit-id.json"])
def test_scheduler_continuation_accepts_only_canonical_permit_ids(reference: str) -> None:
    with pytest.raises(LivePermitError, match="permit-id-invalid"):
        validate_consumed_metadata_recovery_permit_id(
            reference, profile_id="dummy-profile", direction="received",
            date_from="2026-06-30", date_to="2026-06-30", now=NOW,
            repo_root=Path("repo"),
        )


def test_scheduler_continuation_resolves_consumed_permit_by_id(tmp_path: Path) -> None:
    permit, env, repo_root = _create(tmp_path)
    consumed = _consume(permit.permit_id, env, repo_root)

    validated = validate_consumed_metadata_recovery_permit_id(
        permit.permit_id, profile_id="dummy-profile", direction="received",
        date_from="2026-06-30", date_to="2026-06-30", now=consumed.consumed_at,
        repo_root=repo_root, env=env,
    )

    assert validated.permit_id == permit.permit_id


def test_metadata_recovery_permit_still_rejects_double_initial_consumption(
    tmp_path: Path,
) -> None:
    permit, env, repo_root = _create(tmp_path)
    _consume(permit.permit_id, env, repo_root)

    with pytest.raises(LivePermitError, match="permit-already-consumed"):
        _consume(permit.permit_id, env, repo_root)
