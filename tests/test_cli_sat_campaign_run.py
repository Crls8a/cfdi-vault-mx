from __future__ import annotations

import ast
from pathlib import Path

import pytest
from typer.main import get_command
from typer.testing import CliRunner

from cfdi_vault.adapters.cli.app import app
from cfdi_vault.sat_campaign_db_cli import CampaignDatabaseError

PROFILE, CAMPAIGN, GRANT = "profile-synthetic", "cmp-123456789abc", "grant-123456789012345678901234"


def _command():
    root = get_command(app)
    return root.commands["sat"].commands["campaign"].commands["run"]


def _args() -> list[str]:
    return [
        "sat", "campaign", "run", "--profile", PROFILE,
        "--campaign-ref", CAMPAIGN, "--grant", GRANT,
    ]


def _assert_error(result, reason: str, retry_safe: bool = True) -> None:  # type: ignore[no-untyped-def]
    assert result.exit_code == 1 and result.stdout == ""
    assert result.stderr == (
        "error=sat_campaign_run_failed\n"
        f"reason={reason}\nretry_safe={str(retry_safe).lower()}\n"
    )


def test_run_has_exact_required_options() -> None:
    result = CliRunner().invoke(app, ["sat", "campaign", "run", "--help"])
    assert result.exit_code == 0
    assert all(option in result.stdout for option in ("--profile", "--campaign-ref", "--grant"))
    parameters = [parameter for parameter in _command().params if parameter.name != "help"]
    assert [(parameter.name, parameter.required) for parameter in parameters] == [
        ("profile", True), ("campaign_ref", True), ("grant", True),
    ]


def test_run_requires_postgresql(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("DATABASE_URL", raising=False)
    _assert_error(CliRunner().invoke(app, _args()), "campaign-database-required")


def test_run_uses_db_one_shot_and_redacted_output(monkeypatch: pytest.MonkeyPatch) -> None:
    from cfdi_vault.adapters.cli import sat_campaign_run as subject

    captured: dict[str, str] = {}
    monkeypatch.setenv("DATABASE_URL", "postgresql://synthetic")

    def run(profile: str, campaign: str, grant: str) -> dict[str, object]:
        captured.update(profile=profile, campaign=campaign, grant=grant)
        return {"status": "no_due_operations", "contacted_count": 0, "next_check_at": None}

    monkeypatch.setattr(subject, "run_from_environment", run)
    result = CliRunner().invoke(app, _args())
    assert result.exit_code == 0
    assert result.stdout == "status=no_due_operations\ncontacted_count=0\nnext_check_at=None\n"
    assert captured == {"profile": PROFILE, "campaign": CAMPAIGN, "grant": GRANT}
    assert all(value not in result.output for value in (PROFILE, CAMPAIGN, GRANT))


def test_run_preserves_typed_database_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    from cfdi_vault.adapters.cli import sat_campaign_run as subject

    monkeypatch.setenv("DATABASE_URL", "postgresql://synthetic")
    monkeypatch.setattr(
        subject, "run_from_environment",
        lambda *_args: (_ for _ in ()).throw(CampaignDatabaseError("campaign-adapter-required")),
    )
    _assert_error(CliRunner().invoke(app, _args()), "campaign-adapter-required")


def test_run_sanitizes_unexpected_database_error(monkeypatch: pytest.MonkeyPatch) -> None:
    from cfdi_vault.adapters.cli import sat_campaign_run as subject

    monkeypatch.setenv("DATABASE_URL", "postgresql://synthetic")
    monkeypatch.setattr(
        subject, "run_from_environment",
        lambda *_args: (_ for _ in ()).throw(RuntimeError("private database detail")),
    )
    result = CliRunner().invoke(app, _args())
    _assert_error(result, "campaign-database-run-failed")
    assert "private database detail" not in result.output


def test_run_import_graph_is_db_only() -> None:
    tree = ast.parse(Path("src/cfdi_vault/adapters/cli/sat_campaign_run.py").read_text(encoding="utf-8"))
    imported = {node.module or "" for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)}
    forbidden = ("manifest", "storage", "runtime", "smoke", "probe", "diagnose", "live_gate", "backfill", "scheduler")
    assert not any(any(word in name for word in forbidden) for name in imported)
