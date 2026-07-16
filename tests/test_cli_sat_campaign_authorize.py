from __future__ import annotations

import ast
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest
from typer.testing import CliRunner

from cfdi_vault.adapters.cli.app import app
from cfdi_vault.sat_campaign_grant import CampaignGrant, CampaignGrantError
from cfdi_vault.sat_campaign_manifest import build_campaign_manifest
from cfdi_vault.sat_campaign_manifest_store import CampaignManifestStoreError
from cfdi_vault.setup_core import SetupError

PROFILE = "campaign-test"
CAMPAIGN_REF = build_campaign_manifest(PROFILE).campaign_ref
NOW = datetime(2026, 7, 16, 12, tzinfo=timezone.utc)
EXPECTED_KEYS = (
    "grant_ref", "phase", "expires_at", "max_outstanding", "max_submissions",
    "max_invocations", "invocation_count", "submission_count",
)


def _profile(tmp_path: Path, profile_id: str = PROFILE) -> SimpleNamespace:
    return SimpleNamespace(profile_id=profile_id, storage_root=tmp_path / "private")


def _grant(reason: str = "operator approval") -> CampaignGrant:
    from cfdi_vault import sat_campaign_grant as grants

    return grants._new_campaign_grant(  # noqa: SLF001
        build_campaign_manifest(PROFILE), PROFILE, "3" * 40, "3" * 40,
        reason, timedelta(days=14), now=NOW,
    )


def _args(*extra: str) -> list[str]:
    return [
        "sat", "campaign", "authorize", "--profile", PROFILE,
        "--campaign-ref", CAMPAIGN_REF, "--phase", "metadata-proof",
        "--expires-days", "14", "--reason", "operator approval", *extra,
    ]


def _assert_error(result, reason: str, retry_safe: bool = True) -> None:  # type: ignore[no-untyped-def]
    assert result.exit_code == 1
    assert result.stdout == ""
    assert result.stderr == (
        "error=campaign_authorize_failed\n"
        f"reason={reason}\nretry_safe={str(retry_safe).lower()}\n"
    )


def test_authorize_help_lists_exact_required_options() -> None:
    result = CliRunner().invoke(app, ["sat", "campaign", "authorize", "--help"])
    assert result.exit_code == 0
    for option in ("--profile", "--campaign-ref", "--phase", "--expires-days", "--reason"):
        assert option in result.stdout


def test_authorize_passes_exact_authority_and_prints_only_allowlisted_summary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    from cfdi_vault.adapters.cli import sat_campaign_authorize as subject

    profile, manifest, captured = _profile(tmp_path), build_campaign_manifest(PROFILE), {}
    monkeypatch.setattr(subject, "load_profile", lambda value: profile if value == PROFILE else None)
    monkeypatch.setattr(
        subject, "load_campaign_manifest",
        lambda root, ref: manifest if (root, ref) == (profile.storage_root, CAMPAIGN_REF) else None,
    )

    created_grant = _grant()

    def create(**kwargs):  # type: ignore[no-untyped-def]
        captured.update(kwargs)
        return created_grant

    monkeypatch.setattr(subject, "create_campaign_grant_for_current_commit", create)
    result = CliRunner().invoke(app, _args())

    assert result.exit_code == 0
    lines = result.stdout.strip().splitlines()
    assert tuple(line.split("=", 1)[0] for line in lines) == EXPECTED_KEYS
    assert dict(line.split("=", 1) for line in lines) == {
        "grant_ref": created_grant.grant_ref, "phase": "metadata-proof",
        "expires_at": "2026-07-30T12:00:00Z", "max_outstanding": "2",
        "max_submissions": "84", "max_invocations": "4032",
        "invocation_count": "0", "submission_count": "0",
    }
    assert captured == {
        "storage_root": profile.storage_root, "manifest": manifest,
        "profile_id": PROFILE, "repo_root": Path.cwd(),
        "reason": "operator approval", "expires_in": timedelta(days=14),
    }
    assert "operator approval" not in result.output


@pytest.mark.parametrize(
    ("phase", "reason"),
    [("cfdi-proof", "campaign-grant-phase-not-ready"),
     ("continue", "campaign-grant-phase-not-ready"),
     ("metadata", "campaign-grant-phase-invalid")],
)
def test_authorize_rejects_phase_before_loading_profile(
    phase: str, reason: str, monkeypatch: pytest.MonkeyPatch,
) -> None:
    from cfdi_vault.adapters.cli import sat_campaign_authorize as subject

    monkeypatch.setattr(subject, "load_profile", lambda *_: pytest.fail("profile was loaded"))
    args = _args()
    args[args.index("metadata-proof")] = phase
    _assert_error(CliRunner().invoke(app, args), reason)


@pytest.mark.parametrize("days", [0, 15, -1])
def test_authorize_rejects_validity_before_loading_profile(
    days: int, monkeypatch: pytest.MonkeyPatch,
) -> None:
    from cfdi_vault.adapters.cli import sat_campaign_authorize as subject

    monkeypatch.setattr(subject, "load_profile", lambda *_: pytest.fail("profile was loaded"))
    args = _args()
    args[args.index("14")] = str(days)
    _assert_error(CliRunner().invoke(app, args), "campaign-grant-validity-invalid")


@pytest.mark.parametrize(
    ("failure", "reason"),
    [(SetupError(["private detail"]), "campaign-profile-invalid"),
     (OSError("private path"), "campaign-profile-unavailable")],
)
def test_authorize_sanitizes_profile_failures(
    failure: Exception, reason: str, monkeypatch: pytest.MonkeyPatch,
) -> None:
    from cfdi_vault.adapters.cli import sat_campaign_authorize as subject

    monkeypatch.setattr(subject, "load_profile", lambda *_: (_ for _ in ()).throw(failure))
    result = CliRunner().invoke(app, _args())
    _assert_error(result, reason)
    assert "private" not in result.output


@pytest.mark.parametrize(
    ("failure", "reason", "retry_safe"),
    [(CampaignManifestStoreError("campaign-state-not-found"), "campaign-state-not-found", True),
     (CampaignManifestStoreError("campaign-state-invalid"), "campaign-state-invalid", True),
     (CampaignGrantError("campaign-grant-repository-unavailable"),
      "campaign-grant-repository-unavailable", True),
     (CampaignGrantError("campaign-grant-commit-mismatch"),
      "campaign-grant-commit-mismatch", True),
     (CampaignGrantError("campaign-grant-state-commit-uncertain", committed=True, uncertain=True),
      "campaign-grant-state-commit-uncertain", False),
     (RuntimeError("private detail"), "campaign-authorize-failed", False)],
)
def test_authorize_preserves_typed_failure_reason_and_retry_safety(
    tmp_path: Path, failure: Exception, reason: str, retry_safe: bool,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from cfdi_vault.adapters.cli import sat_campaign_authorize as subject

    monkeypatch.setattr(subject, "load_profile", lambda *_: _profile(tmp_path))
    target = "load_campaign_manifest" if isinstance(failure, CampaignManifestStoreError) else (
        "create_campaign_grant_for_current_commit"
    )
    if target != "load_campaign_manifest":
        monkeypatch.setattr(subject, "load_campaign_manifest", lambda *_: build_campaign_manifest(PROFILE))
    monkeypatch.setattr(subject, target, lambda *args, **kwargs: (_ for _ in ()).throw(failure))
    _assert_error(CliRunner().invoke(app, _args()), reason, retry_safe)


def test_authorize_rejects_profile_identity_mismatch(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from cfdi_vault.adapters.cli import sat_campaign_authorize as subject

    monkeypatch.setattr(subject, "load_profile", lambda *_: _profile(tmp_path, "different-profile"))
    _assert_error(CliRunner().invoke(app, _args()), "campaign-profile-mismatch")


def test_authorize_rejects_manifest_profile_mismatch(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from cfdi_vault.adapters.cli import sat_campaign_authorize as subject

    monkeypatch.setattr(subject, "load_profile", lambda *_: _profile(tmp_path))
    monkeypatch.setattr(
        subject, "load_campaign_manifest", lambda *_: build_campaign_manifest("different-profile"),
    )
    _assert_error(CliRunner().invoke(app, _args()), "campaign-grant-profile-mismatch")


def test_authorize_import_graph_excludes_experimental_and_shared_cli_modules() -> None:
    source = Path("src/cfdi_vault/adapters/cli/sat_campaign_authorize.py").read_text(encoding="utf-8")
    imported = {
        alias.name for node in ast.walk(ast.parse(source))
        if isinstance(node, (ast.Import, ast.ImportFrom)) for alias in node.names
    }
    forbidden = ("common", "smoke", "probe", "diagnose", "live_gate", "backfill", "recovery",
                 "live_permit", "scheduler")
    assert not any(fragment in name for fragment in forbidden for name in imported)
