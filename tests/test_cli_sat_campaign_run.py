from __future__ import annotations

import ast
from pathlib import Path
from types import SimpleNamespace

import pytest
from typer.main import get_command
from typer.testing import CliRunner

from cfdi_vault.adapters.cli.app import app
from cfdi_vault.sat_campaign_run import CampaignRunError, CampaignRunResult

PROFILE, CAMPAIGN, GRANT = "profile-synthetic", "cmp-123456789abc", "grt-" + "1" * 24
EXPECTED_KEYS = (
    "status", "reserved_count", "outstanding_count", "submission_attempts",
    "accepted_count", "failed_count", "uncertain_count", "deferred_count", "replay_count",
    "zip_downloaded", "zip_valid", "package_count", "next_check_at", "zip_status",
)


def _command():
    root = get_command(app)
    return root.commands["sat"].commands["campaign"].commands["run"]


def _args() -> list[str]:
    return [
        "sat", "campaign", "run", "--profile", PROFILE,
        "--campaign-ref", CAMPAIGN, "--grant", GRANT,
    ]


def _wire(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, outcome=None):
    from cfdi_vault.adapters.cli import sat_campaign_run

    root = tmp_path / "repo"
    root.mkdir()
    provider_factory, checks_factory, calls = object(), object(), []
    runtime = SimpleNamespace(
        provider_factory=provider_factory, checks_factory=checks_factory,
    )
    monkeypatch.setattr(sat_campaign_run, "find_repo_root", lambda _start: root)
    monkeypatch.setattr(sat_campaign_run, "compose_sat_campaign_windows_runtime", lambda value:
                        calls.append(("runtime", value)) or runtime)

    def run(**kwargs):
        calls.append(("application", kwargs))
        if isinstance(outcome, Exception):
            raise outcome
        return outcome or CampaignRunResult("completed", 2, 2, 2, 1, 1, 0, 0, 0)

    monkeypatch.setattr(sat_campaign_run, "run_metadata_campaign_once", run)
    return calls, root.resolve(), provider_factory, checks_factory


def test_run_has_exact_required_options_and_one_shot_redacted_output(monkeypatch, tmp_path) -> None:
    calls, root, provider_factory, checks_factory = _wire(monkeypatch, tmp_path)
    result = CliRunner().invoke(app, _args())

    assert result.exit_code == 0
    lines = result.stdout.strip().splitlines()
    assert tuple(line.split("=", 1)[0] for line in lines) == EXPECTED_KEYS
    assert dict(line.split("=", 1) for line in lines) == {
        "status": "completed", "reserved_count": "2", "outstanding_count": "2",
        "submission_attempts": "2", "accepted_count": "1", "failed_count": "1",
        "uncertain_count": "0", "deferred_count": "0", "replay_count": "0",
        "zip_downloaded": "False", "zip_valid": "False", "package_count": "0",
        "next_check_at": "None", "zip_status": "None",
    }
    assert calls[0] == ("runtime", root)
    kwargs = calls[1][1]
    assert kwargs["profile_id"] == PROFILE and kwargs["campaign_ref"] == CAMPAIGN
    assert kwargs["grant_ref"] == GRANT and kwargs["repo_root"] == root
    assert kwargs["provider_factory"] is provider_factory
    assert kwargs["checks_factory"] is checks_factory
    assert all(value not in result.output for value in (PROFILE, CAMPAIGN, GRANT, str(root)))
    parameters = [parameter for parameter in _command().params if parameter.name != "help"]
    assert [(parameter.name, parameter.required) for parameter in parameters] == [
        ("profile", True), ("campaign_ref", True), ("grant", True),
    ]


def test_run_prints_sanitized_zip_aggregates(monkeypatch, tmp_path) -> None:
    _wire(monkeypatch, tmp_path, CampaignRunResult(
        "completed", 0, 1, 0, 0, 0, 0, 0, 0,
        True, True, 1, None, "downloaded",
    ))
    result = CliRunner().invoke(app, _args())
    values = dict(line.split("=", 1) for line in result.stdout.strip().splitlines())
    assert {key: values[key] for key in EXPECTED_KEYS[-5:]} == {
        "zip_downloaded": "True", "zip_valid": "True", "package_count": "1",
        "next_check_at": "None", "zip_status": "downloaded",
    }


@pytest.mark.parametrize(("failure", "reason", "retry"), (
    (CampaignRunError("campaign-run-reconciliation-required", retry_safe=False),
     "campaign-run-reconciliation-required", "false"),
    (CampaignRunError("campaign-run-preflight-failed", retry_safe=True),
     "campaign-run-preflight-failed", "true"),
    (RuntimeError("private detail"), "campaign-run-preflight-failed", "true"),
))
def test_run_failures_are_fixed_and_sanitized(monkeypatch, tmp_path, failure, reason, retry) -> None:
    _wire(monkeypatch, tmp_path, failure)
    result = CliRunner().invoke(app, _args())
    assert result.exit_code == 1 and result.stdout == ""
    assert result.stderr == (
        f"error=sat_campaign_run_failed\nreason={reason}\nretry_safe={retry}\n")
    assert "private detail" not in result.output


def test_missing_checkout_fails_before_runtime_composition(monkeypatch) -> None:
    from cfdi_vault.adapters.cli import sat_campaign_run

    monkeypatch.setattr(sat_campaign_run, "find_repo_root", lambda _start: None)
    reached = []
    monkeypatch.setattr(sat_campaign_run, "compose_sat_campaign_windows_runtime", reached.append)
    result = CliRunner().invoke(app, _args())
    assert result.exit_code == 1 and reached == []
    assert result.stderr == (
        "error=sat_campaign_run_failed\nreason=campaign-run-preflight-failed\nretry_safe=true\n")


def test_run_help_and_import_graph_are_productive_only() -> None:
    result = CliRunner().invoke(app, ["sat", "campaign", "run", "--help"])
    assert result.exit_code == 0
    for option in ("--profile", "--campaign-ref", "--grant"):
        assert option in result.stdout
    path = Path("src/cfdi_vault/adapters/cli/sat_campaign_run.py")
    tree = ast.parse(path.read_text(encoding="utf-8"))
    imported = {node.module or "" for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)}
    forbidden = ("common", "smoke", "probe", "diagnose", "live_gate", "permit",
                 "backfill", "scheduler")
    assert not any(any(word in name for word in forbidden) for name in imported)
