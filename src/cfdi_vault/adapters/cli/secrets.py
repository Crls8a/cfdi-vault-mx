"""Secrets CLI commands."""

from __future__ import annotations

from .common import *


def _credential_reference(reference_uri: str, raw_kind: str) -> CredentialReference:
    normalized = raw_kind.strip().lower().replace("-", "_")
    try:
        kind = CredentialKind(normalized)
    except ValueError as exc:
        raise typer.BadParameter("kind must be certificate, private-key, phrase, or generic") from exc
    return CredentialReference(uri=reference_uri, kind=kind)

def custody_register(
    reference_uri: str = typer.Argument(..., help="Credential reference URI."),
    kind: str = typer.Option("generic", "--kind", help="certificate, private-key, phrase, or generic."),
    purpose: str = typer.Option("cli-register", "--purpose", help="Redacted audit purpose."),
) -> None:
    """Register a credential reference without printing the entered value."""

    reference = _credential_reference(reference_uri, kind)
    provider = _provider_for_reference(reference)
    entered_value = typer.prompt(
        "Credential value (hidden; not printed and not stored in config)",
        hide_input=True,
        confirmation_prompt=True,
    )
    try:
        provider.store(reference, str(entered_value), purpose=purpose)
    except CredentialProviderError as exc:
        typer.echo(f"Credential registration failed: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(f"Registered reference: {reference.uri}")
    typer.echo("Credential value was not printed and was not written to config.")

def custody_verify(
    reference_uri: str = typer.Argument(..., help="Credential reference URI."),
    kind: str = typer.Option("generic", "--kind", help="certificate, private-key, phrase, or generic."),
    purpose: str = typer.Option("cli-verify", "--purpose", help="Redacted audit purpose."),
) -> None:
    """Verify that a credential reference exists without printing the value."""

    reference = _credential_reference(reference_uri, kind)
    provider = _provider_for_reference(reference)
    try:
        exists = provider.exists(reference, purpose=purpose)
    except CredentialProviderError as exc:
        typer.echo(f"Credential verification failed: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    if not exists:
        typer.echo(f"Reference not found: {reference.uri}", err=True)
        raise typer.Exit(code=1)
    typer.echo(f"Reference verified: {reference.uri}")
    typer.echo("Credential value was not printed.")

def custody_delete(
    reference_uri: str = typer.Argument(..., help="Credential reference URI."),
    kind: str = typer.Option("generic", "--kind", help="certificate, private-key, phrase, or generic."),
    purpose: str = typer.Option("cli-delete", "--purpose", help="Redacted audit purpose."),
    yes: bool = typer.Option(False, "--yes", help="Skip confirmation prompt."),
) -> None:
    """Delete a credential reference without printing the previous value."""

    reference = _credential_reference(reference_uri, kind)
    if not yes and not typer.confirm(f"Delete credential reference {reference.uri}?"):
        typer.echo("Delete cancelled.")
        return
    provider = _provider_for_reference(reference)
    try:
        deleted = provider.delete(reference, purpose=purpose)
    except CredentialProviderError as exc:
        typer.echo(f"Credential deletion failed: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    if deleted:
        typer.echo(f"Deleted reference: {reference.uri}")
    else:
        typer.echo(f"Reference not found: {reference.uri}")
    typer.echo("Credential value was not printed.")


def register(custody_app: typer.Typer) -> None:
    """Register secrets commands."""

    custody_app.command("register")(custody_register)

    custody_app.command("verify")(custody_verify)

    custody_app.command("delete")(custody_delete)
