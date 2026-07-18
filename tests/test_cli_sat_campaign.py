from __future__ import annotations

import ast
from pathlib import Path

import pytest
from typer.main import get_command
from typer.testing import CliRunner

from cfdi_vault.adapters.cli.app import app
from cfdi_vault.setup_core import CredentialMode, LocalProfile, LocalProfileStatus, SetupError

EXPECTED_KEYS = (
    "campaign_ref", "base_count", "split_count", "leaf_count", "total_count",
    "outstanding_count", "terminal_count", "planned_count", "completed_count",
    "no_data_count", "failed_count", "threshold_blocked_count",
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


def _args(command: str, *extra: str) -> list[str]:
    base = ["sat", "campaign", command, "--profile", "campaign-test"]
    if command in {"status", "run"}:
        base += ["--campaign-ref", "cmp-123456789abc"]
    if command == "run":
        base += ["--grant", "grant-123456789012345678901234"]
    return base + list(extra)


def _assert_required_database(result, command: str) -> None:  # type: ignore[no-untyped-def]
    assert result.exit_code == 1
    assert result.stdout == ""
    assert result.stderr == (
        f"error=sat_campaign{'_run' if command == 'run' else '_authorize' if command == 'authorize' else ''}_failed\n"
        f"reason=campaign-database-required\n"
        + ("retry_safe=true\n" if command in {"run", "authorize"} else "")
    )


def test_campaign_help_exposes_only_productive_commands() -> None:
    root = get_command(app)
    campaign = root.commands["sat"].commands["campaign"]
    assert tuple(campaign.commands) == ("create", "authorize", "run", "status")
    result = CliRunner().invoke(app, ["sat", "campaign", "--help"])
    assert result.exit_code == 0
    assert all(command in result.stdout for command in ("create", "authorize", "run", "status"))


@pytest.mark.parametrize("command", ("create", "status", "run"))
def test_campaign_commands_require_postgresql(monkeypatch: pytest.MonkeyPatch, command: str) -> None:
    monkeypatch.delenv("DATABASE_URL", raising=False)
    result = CliRunner().invoke(app, _args(command))
    _assert_required_database(result, command)


def test_campaign_create_uses_db_and_prints_only_aggregates(monkeypatch: pytest.MonkeyPatch) -> None:
    from cfdi_vault.adapters.cli import sat_campaign

    profile = _profile(Path("C:/private-storage"))
    captured: dict[str, object] = {}
    monkeypatch.setenv("DATABASE_URL", "postgresql://synthetic")
    monkeypatch.setattr(sat_campaign, "load_profile", lambda value: profile if value == profile.profile_id else None)

    def create(profile_id: str, *, tenant_rfc: str) -> dict[str, object]:
        captured.update(profile_id=profile_id, tenant_rfc=tenant_rfc)
        return {key: 0 for key in EXPECTED_KEYS} | {"campaign_ref": "cmp-123456789abc", "base_count": 28}

    monkeypatch.setattr(sat_campaign, "db_create_campaign", create)
    result = CliRunner().invoke(app, ["sat", "campaign", "create", "--profile", profile.profile_id])

    assert result.exit_code == 0
    assert dict(line.split("=", 1) for line in result.stdout.strip().splitlines())["base_count"] == "28"
    assert captured == {"profile_id": profile.profile_id, "tenant_rfc": profile.rfc}
    assert str(profile.storage_root) not in result.output


def test_campaign_status_uses_db_aggregate(monkeypatch: pytest.MonkeyPatch) -> None:
    from cfdi_vault.adapters.cli import sat_campaign

    monkeypatch.setenv("DATABASE_URL", "postgresql://synthetic")
    monkeypatch.setattr(
        sat_campaign, "db_campaign_status",
        lambda profile, campaign: {"campaign_ref": campaign, "total_count": 28, "verify_attempts": 0},
    )
    result = CliRunner().invoke(
        app, ["sat", "campaign", "status", "--profile", "campaign-test", "--campaign-ref", "cmp-123456789abc"],
    )
    assert result.exit_code == 0
    values = dict(line.split("=", 1) for line in result.stdout.strip().splitlines())
    assert values == {"campaign_ref": "cmp-123456789abc", "total_count": "28", "verify_attempts": "0"} | {
        key: "None" for key in (
            "base_count", "split_count", "leaf_count", "outstanding_count", "terminal_count", "planned_count",
            "completed_count", "no_data_count", "failed_count", "threshold_blocked_count", "next_check_at",
            "package_count", "zip_valid_count", "txt_count", "verify_history_count", "last_verify_result",
            "service_window_state",
        )
    }


@pytest.mark.parametrize(
    ("failure", "reason"),
    [(SetupError(["private profile detail"]), "campaign-profile-invalid"),
     (RuntimeError("private runtime detail"), "campaign-database-operation-failed")],
)
def test_campaign_create_sanitizes_failures(
    failure: Exception, reason: str, monkeypatch: pytest.MonkeyPatch,
) -> None:
    from cfdi_vault.adapters.cli import sat_campaign

    monkeypatch.setenv("DATABASE_URL", "postgresql://synthetic")
    if isinstance(failure, SetupError):
        monkeypatch.setattr(sat_campaign, "load_profile", lambda *_: (_ for _ in ()).throw(failure))
    else:
        monkeypatch.setattr(sat_campaign, "load_profile", lambda *_: _profile(Path("C:/private")))
        monkeypatch.setattr(sat_campaign, "db_create_campaign", lambda **_: (_ for _ in ()).throw(failure))
    result = CliRunner().invoke(app, ["sat", "campaign", "create", "--profile", "campaign-test"])
    assert result.exit_code == 1
    assert reason in result.stderr
    assert "private" not in result.output


def test_campaign_cli_import_graph_is_db_only() -> None:
    for name in ("sat_campaign.py", "sat_campaign_authorize.py", "sat_campaign_run.py"):
        tree = ast.parse(Path("src/cfdi_vault/adapters/cli", name).read_text(encoding="utf-8"))
        imported = {
            alias.name
            for node in ast.walk(tree)
            if isinstance(node, (ast.Import, ast.ImportFrom))
            for alias in node.names
        }
        forbidden = ("manifest_store", "sat_campaign_status", "smoke", "probe", "diagnose", "live_gate", "backfill")
        assert not any(fragment in value for fragment in forbidden for value in imported)
