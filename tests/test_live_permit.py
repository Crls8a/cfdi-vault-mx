from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path

import pytest

from cfdi_vault.live_permit import (
    LivePermitError,
    LivePermitRequest,
    create_live_execution_permit,
    load_live_execution_permit,
    permit_root,
    validate_and_consume_live_permit,
)

NOW = datetime(2026, 7, 3, 18, 0, tzinfo=timezone.utc)


def _request(**overrides: object) -> LivePermitRequest:
    values: dict[str, object] = {
        "scope": "transport_probe",
        "profile_id": "dummy-profile",
        "kind": "metadata",
        "direction": "received",
        "date_from": "2026-07-03",
        "date_to": "2026-07-03",
        "reason": "Carlos authorized post-86 transport probe",
        "expires_minutes": 15,
        "issued_by": "carlos-local",
    }
    values.update(overrides)
    return LivePermitRequest(**values)  # type: ignore[arg-type]


def test_live_execution_permit_is_appdata_local_one_time_and_exact_scope(tmp_path: Path) -> None:
    env = {"LOCALAPPDATA": str(tmp_path / "appdata")}
    repo_root = tmp_path / "repo"
    repo_root.mkdir()

    permit = create_live_execution_permit(_request(), env=env, now=NOW, repo_root=repo_root)

    assert permit.path is not None
    assert permit.path.parent == permit_root(env=env)
    assert permit.permit_id in permit.path.name
    assert permit.allow_real_sat is True
    assert permit.allow_real_credentials is False
    assert permit.consumed is False

    document = json.loads(permit.path.read_text(encoding="utf-8"))
    assert document["permitId"] == permit.permit_id
    assert document["scope"] == "transport_probe"
    assert document["profileId"] == "dummy-profile"
    assert document["kind"] == "metadata"
    assert document["direction"] == "received"
    assert document["dateFrom"] == "2026-07-03"
    assert document["dateTo"] == "2026-07-03"
    assert document["maxRangeDays"] == 1
    assert document["maxAttempts"] == 1
    assert document["issuedBy"] == "carlos-local"
    assert document["redactionRequired"] is True

    consumed = validate_and_consume_live_permit(
        permit.permit_id,
        scope="transport_probe",
        profile_id="dummy-profile",
        kind="metadata",
        direction="received",
        date_from="2026-07-03",
        date_to="2026-07-03",
        env=env,
        now=NOW + timedelta(minutes=1),
        repo_root=repo_root,
    )

    assert consumed.consumed is True
    assert consumed.consumed_at is not None
    assert load_live_execution_permit(permit.permit_id, env=env).consumed is True
    with pytest.raises(LivePermitError, match="permit-already-consumed"):
        validate_and_consume_live_permit(
            permit.permit_id,
            scope="transport_probe",
            profile_id="dummy-profile",
            kind="metadata",
            direction="received",
            date_from="2026-07-03",
            date_to="2026-07-03",
            env=env,
            now=NOW + timedelta(minutes=2),
            repo_root=repo_root,
        )


def test_live_execution_permit_allows_auth_post_probe_scope_without_credentials(tmp_path: Path) -> None:
    env = {"LOCALAPPDATA": str(tmp_path / "appdata")}
    repo_root = tmp_path / "repo"
    repo_root.mkdir()

    permit = create_live_execution_permit(_request(scope="auth_post_probe"), env=env, now=NOW, repo_root=repo_root)

    assert permit.scope == "auth_post_probe"
    assert permit.allow_real_credentials is False
    consumed = validate_and_consume_live_permit(
        permit.permit_id,
        scope="auth_post_probe",
        profile_id="dummy-profile",
        kind="metadata",
        direction="received",
        date_from="2026-07-03",
        date_to="2026-07-03",
        env=env,
        now=NOW + timedelta(minutes=1),
        repo_root=repo_root,
    )
    assert consumed.consumed is True


def test_live_execution_permit_allows_auth_matrix_probe_scope_without_credentials(tmp_path: Path) -> None:
    env = {"LOCALAPPDATA": str(tmp_path / "appdata")}
    repo_root = tmp_path / "repo"
    repo_root.mkdir()

    permit = create_live_execution_permit(_request(scope="auth_matrix_probe"), env=env, now=NOW, repo_root=repo_root)

    assert permit.scope == "auth_matrix_probe"
    assert permit.allow_real_credentials is False
    consumed = validate_and_consume_live_permit(
        permit.permit_id,
        scope="auth_matrix_probe",
        profile_id="dummy-profile",
        kind="metadata",
        direction="received",
        date_from="2026-07-03",
        date_to="2026-07-03",
        env=env,
        now=NOW + timedelta(minutes=1),
        repo_root=repo_root,
    )
    assert consumed.consumed is True


@pytest.mark.parametrize(
    ("permit_request", "reason"),
    [
        (_request(kind="cfdi"), "metadata-only-required"),
        (_request(date_to="2026-07-04"), "range-too-wide"),
        (_request(expires_minutes=16), "invalid-expiration-window"),
        (_request(reason=" "), "reason-required"),
        (_request(issued_by="someone-else"), "invalid-issuer"),
    ],
)
def test_live_execution_permit_rejects_unsafe_create_inputs(
    tmp_path: Path,
    permit_request: LivePermitRequest,
    reason: str,
) -> None:
    env = {"LOCALAPPDATA": str(tmp_path / "appdata")}

    with pytest.raises(LivePermitError, match=reason):
        create_live_execution_permit(permit_request, env=env, now=NOW, repo_root=tmp_path / "repo")


def test_live_execution_permit_rejects_mismatch_and_expiration(tmp_path: Path) -> None:
    env = {"LOCALAPPDATA": str(tmp_path / "appdata")}
    repo_root = tmp_path / "repo"
    repo_root.mkdir()
    permit = create_live_execution_permit(_request(), env=env, now=NOW, repo_root=repo_root)

    with pytest.raises(LivePermitError, match="permit-profileId-mismatch"):
        validate_and_consume_live_permit(
            permit.permit_id,
            scope="transport_probe",
            profile_id="other-profile",
            kind="metadata",
            direction="received",
            date_from="2026-07-03",
            date_to="2026-07-03",
            env=env,
            now=NOW + timedelta(minutes=1),
            repo_root=repo_root,
        )

    with pytest.raises(LivePermitError, match="permit-expired"):
        validate_and_consume_live_permit(
            permit.permit_id,
            scope="transport_probe",
            profile_id="dummy-profile",
            kind="metadata",
            direction="received",
            date_from="2026-07-03",
            date_to="2026-07-03",
            env=env,
            now=NOW + timedelta(minutes=16),
            repo_root=repo_root,
        )


def test_live_execution_permit_storage_must_stay_outside_repo(tmp_path: Path) -> None:
    repo_root = tmp_path / "repo"
    repo_root.mkdir()
    repo_root.joinpath(".git").mkdir()
    env = {"LOCALAPPDATA": str(repo_root)}

    with pytest.raises(LivePermitError, match="permit-root-inside-repo"):
        create_live_execution_permit(_request(), env=env, now=NOW, repo_root=repo_root)
