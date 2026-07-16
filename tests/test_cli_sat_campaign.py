from __future__ import annotations

import ast
from pathlib import Path

import pytest
from typer.main import get_command
from typer.testing import CliRunner

from cfdi_vault.adapters.cli.app import app
from cfdi_vault.setup_core import CredentialMode, LocalProfile, LocalProfileStatus, SetupError

EXPECTED_KEYS = (
    "campaign_ref",
    "base_count",
    "split_count",
    "leaf_count",
    "total_count",
    "outstanding_count",
    "terminal_count",
    "planned_count",
    "completed_count",
    "no_data_count",
    "failed_count",
    "threshold_blocked_count",
)


def _profile(storage_root: Path, profile_id: str = "campaign-test") -> LocalProfile:
    return LocalProfile(
        profile_id=profile_id,
        rfc="AAA010101AAA",
        storage_root=storage_root,
        credential_mode=CredentialMode.REFERENCED,
        certificate_path=storage_root / "synthetic.cer",
        private_key_path=storage_root / "synthetic.key",
        phrase_ref="test-provider://synthetic",
        status=LocalProfileStatus.READY,
        certificate_fingerprint="0" * 64,
    )


def _output(result) -> dict[str, str]:  # type: ignore[no-untyped-def]
    lines = result.stdout.strip().splitlines()
    assert tuple(line.split("=", 1)[0] for line in lines) == EXPECTED_KEYS
    return dict(line.split("=", 1) for line in lines)


def test_campaign_help_exposes_only_productive_commands() -> None:
    root = get_command(app)
    campaign = root.commands["sat"].commands["campaign"]
    assert tuple(campaign.commands) == ("create", "authorize", "status")
    result = CliRunner().invoke(app, ["sat", "campaign", "--help"])
    assert result.exit_code == 0
    assert "create" in result.stdout
    assert "authorize" in result.stdout
    assert "status" in result.stdout


def test_campaign_create_is_idempotent_and_outputs_only_aggregates(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    from cfdi_vault.adapters.cli import sat_campaign

    profile = _profile(tmp_path / "private-storage")
    monkeypatch.setattr(sat_campaign, "load_profile", lambda _profile_id: profile)
    runner = CliRunner()
    args = ["sat", "campaign", "create", "--profile", profile.profile_id]

    first = runner.invoke(app, args)
    second = runner.invoke(app, args)

    assert first.exit_code == second.exit_code == 0
    assert first.stdout == second.stdout
    values = _output(first)
    assert values == {
        "campaign_ref": values["campaign_ref"],
        "base_count": "28",
        "split_count": "0",
        "leaf_count": "28",
        "total_count": "28",
        "outstanding_count": "0",
        "terminal_count": "0",
        "planned_count": "28",
        "completed_count": "0",
        "no_data_count": "0",
        "failed_count": "0",
        "threshold_blocked_count": "0",
    }
    assert values["campaign_ref"].startswith("cmp-")
    assert str(profile.storage_root) not in first.stdout
    assert profile.profile_id not in first.stdout


def test_campaign_create_preserves_legitimate_progress(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    from cfdi_vault.adapters.cli import sat_campaign
    from cfdi_vault.sat_campaign_manifest_store import reserve_campaign_manifest

    profile = _profile(tmp_path / "private-storage")
    monkeypatch.setattr(sat_campaign, "load_profile", lambda _profile_id: profile)
    runner = CliRunner()
    args = ["sat", "campaign", "create", "--profile", profile.profile_id]
    created = runner.invoke(app, args)
    campaign_ref = _output(created)["campaign_ref"]
    reserve_campaign_manifest(profile.storage_root, campaign_ref)

    repeated = runner.invoke(app, args)

    assert repeated.exit_code == 0
    assert _output(repeated)["outstanding_count"] == "2"
    assert _output(repeated)["planned_count"] == "26"


def test_campaign_create_works_without_a_git_checkout(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    from cfdi_vault import secure_state_file
    from cfdi_vault.adapters.cli import sat_campaign

    install_root = tmp_path / "installed" / "site-packages"
    work_dir = tmp_path / "operator"
    work_dir.mkdir()
    profile = _profile(tmp_path / "private-storage")
    monkeypatch.chdir(work_dir)
    monkeypatch.setattr(secure_state_file, "_REPO_ROOT", install_root)
    monkeypatch.setattr(sat_campaign, "find_repo_root", lambda *_args: None, raising=False)
    monkeypatch.setattr(sat_campaign, "load_profile", lambda _profile_id: profile)

    result = CliRunner().invoke(app, ["sat", "campaign", "create", "--profile", profile.profile_id])

    assert result.exit_code == 0
    assert _output(result)["base_count"] == "28"


@pytest.mark.parametrize("race_reload", [False, True])
def test_campaign_create_rejects_mismatched_existing_profile(
    tmp_path: Path, monkeypatch, race_reload: bool,
) -> None:  # type: ignore[no-untyped-def]
    from cfdi_vault.adapters.cli import sat_campaign
    from cfdi_vault.sat_campaign_manifest import build_campaign_manifest
    from cfdi_vault.sat_campaign_manifest_store import CampaignManifestStoreError

    profile = _profile(tmp_path / "private-storage")
    mismatched = build_campaign_manifest("different-profile")
    monkeypatch.setattr(sat_campaign, "load_profile", lambda _profile_id: profile)
    if race_reload:
        loads = iter((CampaignManifestStoreError("campaign-state-not-found"), mismatched))

        def load(*_args):  # type: ignore[no-untyped-def]
            value = next(loads)
            if isinstance(value, Exception):
                raise value
            return value

        monkeypatch.setattr(sat_campaign, "load_campaign_manifest", load)
        monkeypatch.setattr(
            sat_campaign, "initialize_campaign_manifest",
            lambda *_args: (_ for _ in ()).throw(CampaignManifestStoreError("campaign-state-conflict")),
        )
    else:
        monkeypatch.setattr(sat_campaign, "load_campaign_manifest", lambda *_args: mismatched)

    result = CliRunner().invoke(app, ["sat", "campaign", "create", "--profile", profile.profile_id])

    assert result.exit_code == 1
    assert result.stderr == "error=sat_campaign_failed\nreason=campaign-profile-mismatch\n"


def test_campaign_status_returns_the_persisted_aggregate_summary(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    from cfdi_vault.adapters.cli import sat_campaign

    profile = _profile(tmp_path / "private-storage")
    monkeypatch.setattr(sat_campaign, "load_profile", lambda _profile_id: profile)
    runner = CliRunner()
    created = runner.invoke(app, ["sat", "campaign", "create", "--profile", profile.profile_id])
    campaign_ref = _output(created)["campaign_ref"]

    status = runner.invoke(
        app, ["sat", "campaign", "status", "--profile", profile.profile_id, "--campaign-ref", campaign_ref]
    )

    assert status.exit_code == 0
    assert status.stdout == created.stdout


@pytest.mark.parametrize(
    ("failure", "reason"),
    [
        (SetupError(["private profile detail"]), "campaign-profile-invalid"),
        (OSError("private filesystem detail"), "campaign-profile-unavailable"),
        (RuntimeError("private runtime detail"), "campaign-operation-failed"),
    ],
)
def test_campaign_create_sanitizes_profile_and_unexpected_errors(failure, reason, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    from cfdi_vault.adapters.cli import sat_campaign

    def fail(_profile_id: str) -> None:
        raise failure

    monkeypatch.setattr(sat_campaign, "load_profile", fail)
    result = CliRunner().invoke(app, ["sat", "campaign", "create", "--profile", "campaign-test"])
    assert result.exit_code == 1
    assert result.stdout == ""
    assert result.stderr == f"error=sat_campaign_failed\nreason={reason}\n"
    assert "private" not in result.output


def test_campaign_rejects_profile_mismatch_and_checkout_storage(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    from cfdi_vault.adapters.cli import sat_campaign

    monkeypatch.setattr(sat_campaign, "load_profile", lambda _profile_id: _profile(tmp_path, "another-profile"))
    mismatch = CliRunner().invoke(app, ["sat", "campaign", "create", "--profile", "campaign-test"])
    assert mismatch.stderr == "error=sat_campaign_failed\nreason=campaign-profile-mismatch\n"

    repo_root = Path(__file__).resolve().parents[1]
    monkeypatch.setattr(sat_campaign, "load_profile", lambda _profile_id: _profile(repo_root / "storage-private"))
    unsafe = CliRunner().invoke(app, ["sat", "campaign", "create", "--profile", "campaign-test"])
    assert unsafe.stderr == "error=sat_campaign_failed\nreason=campaign-state-path-invalid\n"


def test_campaign_status_rejects_invalid_reference_without_leaking_details(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    from cfdi_vault.adapters.cli import sat_campaign

    monkeypatch.setattr(sat_campaign, "load_profile", lambda _profile_id: _profile(tmp_path))
    result = CliRunner().invoke(
        app, ["sat", "campaign", "status", "--profile", "campaign-test", "--campaign-ref", "not-a-ref"]
    )
    assert result.exit_code == 1
    assert result.stderr == "error=sat_campaign_failed\nreason=campaign-ref-invalid\n"
    assert "not-a-ref" not in result.output


def test_campaign_cli_import_graph_excludes_legacy_sat_surfaces() -> None:
    source = Path("src/cfdi_vault/adapters/cli/sat_campaign.py").read_text(encoding="utf-8")
    imported = {
        alias.name
        for node in ast.walk(ast.parse(source))
        if isinstance(node, (ast.Import, ast.ImportFrom))
        for alias in node.names
    }
    forbidden = ("common", "smoke", "probe", "diagnose", "live_gate", "backfill", "recovery")
    assert not any(fragment in name for fragment in forbidden for name in imported)
