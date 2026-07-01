from __future__ import annotations

from typer.testing import CliRunner

from cfdi_vault import cli
from cfdi_vault.cli import app
from cfdi_vault.secrets import CredentialAccessAction
from cfdi_vault.windows_secrets import InMemoryWindowsCredentialBackend, WindowsCredentialManagerSecretProvider


def test_secret_cli_register_verify_and_delete_do_not_print_value(monkeypatch) -> None:
    entered_value = "SYNTHETIC_CLI_CREDENTIAL_VALUE"
    reference_uri = "windows-credential-manager://cfdi-vault/tests/cli/private-key"
    provider = WindowsCredentialManagerSecretProvider(InMemoryWindowsCredentialBackend())
    monkeypatch.setattr(cli, "_provider_for_reference", lambda _reference: provider)
    runner = CliRunner()

    register = runner.invoke(
        app,
        ["secret", "register", reference_uri, "--kind", "private-key"],
        input=f"{entered_value}\n{entered_value}\n",
    )
    verify = runner.invoke(app, ["secret", "verify", reference_uri, "--kind", "private-key"])
    delete = runner.invoke(app, ["secret", "delete", reference_uri, "--kind", "private-key", "--yes"])

    assert register.exit_code == 0
    assert verify.exit_code == 0
    assert delete.exit_code == 0
    combined_output = register.output + verify.output + delete.output
    assert entered_value not in combined_output
    assert "Registered reference" in register.output
    assert "Reference verified" in verify.output
    assert "Deleted reference" in delete.output
    assert [event.action for event in provider.audit_events] == [
        CredentialAccessAction.CREATE,
        CredentialAccessAction.VERIFY,
        CredentialAccessAction.DELETE,
    ]


def test_secret_cli_verify_reports_missing_reference_without_value(monkeypatch) -> None:
    entered_value = "SYNTHETIC_MISSING_CLI_VALUE"
    reference_uri = "windows-credential-manager://cfdi-vault/tests/cli/missing"
    provider = WindowsCredentialManagerSecretProvider(InMemoryWindowsCredentialBackend())
    monkeypatch.setattr(cli, "_provider_for_reference", lambda _reference: provider)

    result = CliRunner().invoke(app, ["secret", "verify", reference_uri, "--kind", "generic"])

    assert result.exit_code == 1
    assert "Reference not found" in result.output
    assert entered_value not in result.output


def test_help_command_lists_secret_reference_topics() -> None:
    result = CliRunner().invoke(app, ["help", "secret register"])

    assert result.exit_code == 0
    assert "secret register" in result.output
    assert "without printing" in result.output
