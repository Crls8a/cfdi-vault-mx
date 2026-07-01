from typer.testing import CliRunner

from cfdi_vault.cli import app


def test_help_command_lists_recovery_flow() -> None:
    result = CliRunner().invoke(app, ["help"])

    assert result.exit_code == 0
    assert "Recommended recovery flow" in result.output
    assert "sync metadata" in result.output
    assert "sync xml" in result.output
    assert "Command catalog" in result.output


def test_help_command_explains_one_topic() -> None:
    result = CliRunner().invoke(app, ["help", "sync xml"])

    assert result.exit_code == 0
    assert "sync xml" in result.output
    assert "register local file paths" in result.output
    assert "Example:" in result.output


def test_help_command_fails_for_unknown_topic() -> None:
    result = CliRunner().invoke(app, ["help", "unknown"])

    assert result.exit_code == 1
    assert "Unknown help topic" in result.output
