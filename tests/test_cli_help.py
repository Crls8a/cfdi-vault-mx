import pytest
from typer.testing import CliRunner

from cfdi_vault.cli import app


def test_help_command_lists_productive_recovery_flow() -> None:
    result = CliRunner().invoke(app, ["help"])

    assert result.exit_code == 0
    assert "Recommended recovery flow" in result.output
    for command in (
        "sat campaign create",
        "sat campaign authorize",
        "sat campaign run",
        "sat campaign status",
        "sync metadata",
        "sync xml",
        "download sync",
        "download status",
        "worker run",
    ):
        assert command in result.output
    assert "Command catalog" in result.output


def test_help_command_explains_one_topic() -> None:
    result = CliRunner().invoke(app, ["help", "sync xml"])

    assert result.exit_code == 0
    assert "sync xml" in result.output
    assert "fake/offline" in result.output
    assert "live SAT recovery belongs to sat campaign" in result.output
    assert "register local file paths" in result.output
    assert "Example:" in result.output


@pytest.mark.parametrize("command", ("metadata", "xml"))
def test_offline_sync_help_does_not_expose_live_option(command: str) -> None:
    result = CliRunner().invoke(app, ["sync", command, "--help"])

    assert result.exit_code == 0, result.output
    assert "--live" not in result.output
    assert "live SAT is available" in result.output
    assert "campaign" in result.output


def test_help_command_fails_for_unknown_topic() -> None:
    result = CliRunner().invoke(app, ["help", "unknown"])

    assert result.exit_code == 1
    assert "Unknown help topic" in result.output


def test_cli_subcommand_help_builds_for_productive_commands() -> None:
    for args in (
        ["--help"],
        ["setup", "--help"],
        ["setup", "--skip-credential-check", "--help"],
        ["doctor", "--help"],
        ["download", "plan", "--help"],
        ["download", "request", "--help"],
        ["download", "sync", "--help"],
        ["download", "status", "--help"],
        ["sat", "campaign", "create", "--help"],
        ["sat", "campaign", "authorize", "--help"],
        ["sat", "campaign", "run", "--help"],
        ["sat", "campaign", "status", "--help"],
        ["worker", "run", "--help"],
    ):
        result = CliRunner().invoke(app, args)

        assert result.exit_code == 0, result.output
        assert result.exception is None


def test_setup_help_exposes_only_credential_check_naming() -> None:
    result = CliRunner().invoke(app, ["setup", "--help"])
    catalog = CliRunner().invoke(app, ["help", "setup"])

    assert result.exit_code == 0, result.output
    assert "--skip-credential-check" in result.output
    assert "credential check" in result.output.lower()
    assert "--no-smoke" not in result.output
    assert catalog.exit_code == 0, catalog.output
    assert "local credential check" in catalog.output
    assert "smoke" not in catalog.output.lower()


def test_retired_sat_commands_are_absent_from_help_and_fail_closed() -> None:
    runner = CliRunner()
    catalog = runner.invoke(app, ["help"])
    assert catalog.exit_code == 0, catalog.output

    retired_commands = (
        ("download", "live-smoke"),
        ("sat", "auth-smoke"),
        ("sat", "metadata-request-smoke"),
        ("sat", "metadata-request-state"),
        ("sat", "metadata-recover-live"),
        ("sat", "metadata-recovery-status"),
        ("sat", "metadata-recovery-runner"),
        ("sat", "metadata-window-plan"),
        ("sat", "backfill", "plan"),
        ("sat", "backfill", "submit"),
        ("sat", "verify-due"),
        ("sat", "verify-due-runner"),
        ("sat", "scheduler", "render-windows-task"),
        ("sat", "package-download-smoke"),
        ("sat", "metadata-verify-smoke"),
        ("sat", "verify-live-gate"),
        ("sat", "download-live-gate"),
        ("sat", "inspect-auth-contract"),
        ("sat", "lint-auth-envelope"),
        ("sat", "oracle-auth-fingerprint"),
        ("sat", "diff-auth-oracle"),
        ("sat", "diagnose-live"),
        ("sat", "probe-transport"),
        ("sat", "probe-auth-post"),
        ("sat", "probe-verify-post"),
        ("sat", "probe-auth-matrix"),
        ("live", "permit", "create"),
    )

    for args in retired_commands:
        command = " ".join(args)
        assert command not in catalog.output
        result = runner.invoke(app, list(args))
        assert result.exit_code == 2, f"{command}: {result.output}"
        assert "no such command" in result.output.lower()
