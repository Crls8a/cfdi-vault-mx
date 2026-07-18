from __future__ import annotations

import ast
from pathlib import Path

import pytest
from typer.testing import CliRunner

from cfdi_vault.adapters.cli.app import app
from cfdi_vault.sat_campaign_db_cli import CampaignDatabaseError

PROFILE = "campaign-test"
CAMPAIGN_REF = "cmp-123456789abc"
EXPECTED_KEYS = ("grant_ref", "phase", "expires_at", "max_open_operations")


def _args(*extra: str) -> list[str]:
    return [
        "sat", "campaign", "authorize", "--profile", PROFILE,
        "--campaign-ref", CAMPAIGN_REF, "--phase", "metadata-proof",
        "--expires-days", "14", "--reason", "operator approval", *extra,
    ]


def _assert_error(result, reason: str) -> None:  # type: ignore[no-untyped-def]
    assert result.exit_code == 1
    assert result.stdout == ""
    assert result.stderr == (
        "error=campaign_authorize_failed\n"
        f"reason={reason}\nretry_safe=true\n"
    )


def test_authorize_help_lists_exact_required_options() -> None:
    result = CliRunner().invoke(app, ["sat", "campaign", "authorize", "--help"])
    assert result.exit_code == 0
    assert all(option in result.stdout for option in ("--profile", "--campaign-ref", "--phase", "--expires-days", "--reason"))


def test_authorize_requires_postgresql(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("DATABASE_URL", raising=False)
    _assert_error(CliRunner().invoke(app, _args()), "campaign-database-required")


def test_authorize_uses_db_and_prints_allowlisted_summary(monkeypatch: pytest.MonkeyPatch) -> None:
    from cfdi_vault.adapters.cli import sat_campaign_authorize as subject

    captured: dict[str, object] = {}
    monkeypatch.setenv("DATABASE_URL", "postgresql://synthetic")

    def authorize(profile: str, campaign: str, phase: str, days: int, reason: str) -> dict[str, object]:
        captured.update(profile=profile, campaign=campaign, phase=phase, days=days, reason=reason)
        return {
            "grant_ref": "grant-123456789012345678901234", "phase": phase,
            "expires_at": "2026-07-30T12:00:00Z", "max_open_operations": 2,
        }

    monkeypatch.setattr(subject, "db_authorize_campaign", authorize)
    result = CliRunner().invoke(app, _args())
    assert result.exit_code == 0
    assert tuple(line.split("=", 1)[0] for line in result.stdout.strip().splitlines()) == EXPECTED_KEYS
    assert captured == {
        "profile": PROFILE, "campaign": CAMPAIGN_REF, "phase": "metadata-proof",
        "days": 14, "reason": "operator approval",
    }
    assert "operator approval" not in result.output


@pytest.mark.parametrize(
    ("phase", "reason"),
    [("metadata", "campaign-grant-phase-invalid"), ("", "campaign-grant-phase-invalid")],
)
def test_authorize_preserves_db_validation_errors(
    phase: str, reason: str, monkeypatch: pytest.MonkeyPatch,
) -> None:
    from cfdi_vault.adapters.cli import sat_campaign_authorize as subject

    monkeypatch.setenv("DATABASE_URL", "postgresql://synthetic")
    monkeypatch.setattr(
        subject, "db_authorize_campaign",
        lambda *_args: (_ for _ in ()).throw(CampaignDatabaseError(reason)),
    )
    args = _args()
    args[args.index("metadata-proof")] = phase
    _assert_error(CliRunner().invoke(app, args), reason)


def test_authorize_sanitizes_unexpected_database_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    from cfdi_vault.adapters.cli import sat_campaign_authorize as subject

    monkeypatch.setenv("DATABASE_URL", "postgresql://synthetic")
    monkeypatch.setattr(
        subject, "db_authorize_campaign",
        lambda *_args: (_ for _ in ()).throw(RuntimeError("private database detail")),
    )
    result = CliRunner().invoke(app, _args())
    _assert_error(result, "campaign-database-authorize-failed")
    assert "private database detail" not in result.output


def test_authorize_import_graph_excludes_json_and_experimental_surfaces() -> None:
    source = Path("src/cfdi_vault/adapters/cli/sat_campaign_authorize.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    imported = {
        alias.name for node in ast.walk(tree)
        if isinstance(node, (ast.Import, ast.ImportFrom)) for alias in node.names
    }
    forbidden = ("manifest_store", "sat_campaign_grant", "smoke", "probe", "diagnose", "live_gate", "recovery")
    assert not any(fragment in name for fragment in forbidden for name in imported)
