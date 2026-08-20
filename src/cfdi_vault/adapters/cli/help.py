"""Custom CLI help catalog."""

from __future__ import annotations

import typer

COMMAND_HELP: tuple[dict[str, str], ...] = (
    {
        "command": "sat campaign create",
        "purpose": "Create the fixed 2026 SAT recovery campaign in private external storage.",
        "when": "Run once for an exact local profile before authorizing SAT contact.",
        "example": "cfdi-vault sat campaign create --profile default",
    },
    {
        "command": "sat campaign authorize",
        "purpose": "Create a private manifest- and commit-bound grant for one campaign phase.",
        "when": "Run after campaign creation and before the authorized campaign execution.",
        "example": "cfdi-vault sat campaign authorize --profile default --campaign-ref <campaign-ref> --phase metadata-proof --expires-days 14 --reason <reason>",
    },
    {
        "command": "sat campaign run",
        "purpose": "Execute one bounded productive Metadata campaign submission run.",
        "when": "Run once after authorization and again only when persisted work is due.",
        "example": "cfdi-vault sat campaign run --profile default --campaign-ref <campaign-ref> --grant <grant-ref>",
    },
    {
        "command": "sat campaign status",
        "purpose": "Show only sanitized aggregate progress for one persisted SAT campaign.",
        "when": "Run after creation or campaign executions to inspect durable progress.",
        "example": "cfdi-vault sat campaign status --profile default --campaign-ref <campaign-ref>",
    },
    {
        "command": "analysis report",
        "purpose": "Read a tenant-scoped PostgreSQL V5 financial report as aggregate JSON.",
        "when": "Run after durable ledger data exists; output includes completeness and provenance only.",
        "example": "cfdi-vault analysis report --profile default --tenant-id default --from 2026-01-01 --to 2026-01-31",
    },
    {
        "command": "doctor",
        "purpose": "Check whether database, queue, cache, storage, and setup profile are reachable.",
        "when": "Run after install or when the CLI cannot connect to dependencies.",
        "example": "cfdi-vault doctor",
    },
    {
        "command": "setup",
        "purpose": "Create the local AppData RFC profile, import credential files, and run a local credential check.",
        "when": "Run once on the operator machine before recovery work.",
        "example": "cfdi-vault setup --source-folder <external-folder>",
    },
    {
        "command": "status",
        "purpose": "Show redacted local setup profile readiness.",
        "when": "Run after setup or when credential/profile readiness is unclear.",
        "example": "cfdi-vault status --profile-id default",
    },
    {
        "command": "onboard",
        "purpose": "Create the first safe local profile config from storage, RFC, schedule, and e.firma references.",
        "when": "Run once before recovery so users do not edit JSON by hand.",
        "example": "cfdi-vault onboard --config ./local.config.json",
    },
    {
        "command": "config validate",
        "purpose": "Validate the local multi-RFC profile config without reading credential material.",
        "when": "Run after creating or editing a config file.",
        "example": "cfdi-vault config validate examples/config/local-dev-dummy.json",
    },
    {
        "command": "secret register",
        "purpose": "Register a local credential reference without printing or storing the value in config.",
        "when": "Run after creating a profile that points to Windows Credential Manager references.",
        "example": "cfdi-vault secret register windows-credential-manager://cfdi-vault/profile/private-key --kind private-key",
    },
    {
        "command": "secret verify",
        "purpose": "Verify that a credential reference exists without reading or printing the value.",
        "when": "Run before SAT authentication or signing setup checks.",
        "example": "cfdi-vault secret verify windows-credential-manager://cfdi-vault/profile/private-key --kind private-key",
    },
    {
        "command": "secret delete",
        "purpose": "Delete a credential reference without printing the previous value.",
        "when": "Run when rotating or removing a local profile.",
        "example": "cfdi-vault secret delete windows-credential-manager://cfdi-vault/profile/private-key --kind private-key --yes",
    },
    {
        "command": "init",
        "purpose": "Create or update the tenant/RFC scope used by recovery jobs.",
        "when": "Run once per tenant/RFC before real recovery work.",
        "example": "cfdi-vault init --tenant-id acme --rfc AAA010101AAA",
    },
    {
        "command": "reconcile",
        "purpose": "Recompute metadata/XML reconciliation state.",
        "when": "Run after evidence changes or when pending/downloaded status looks stale.",
        "example": "cfdi-vault reconcile --tenant-id acme",
    },
    {
        "command": "search",
        "purpose": "Search normalized CFDI records by UUID, RFC, name, status, type, or concept text.",
        "when": "Use when the accountant/operator needs to find invoices quickly.",
        "example": "cfdi-vault search AAA010101AAA",
    },
    {
        "command": "show",
        "purpose": "Show one CFDI in terminal-readable form.",
        "when": "Use after search when a specific UUID needs detail.",
        "example": "cfdi-vault show <UUID>",
    },
    {
        "command": "print",
        "purpose": "Render one CFDI as text, HTML, or a basic PDF.",
        "when": "Use when an auditable human-readable output is needed.",
        "example": "cfdi-vault print <UUID> --format pdf --output storage/exports/<UUID>.pdf",
    },
    {
        "command": "export",
        "purpose": "Export normalized recovery data.",
        "when": "Use when accounting data needs to leave the vault as CSV.",
        "example": "cfdi-vault export --format csv --output storage/exports/cfdi.csv",
    },
    {
        "command": "import-xml",
        "purpose": "Import one local synthetic CFDI XML into the PostgreSQL-backed vault.",
        "when": "Use for synthetic lab/demo fixtures through the same DATABASE_URL boundary.",
        "example": "cfdi-vault import-xml examples/synthetic-cfdi/invoice-income.xml --database-url postgresql+psycopg://...",
    },
    {
        "command": "import-zip",
        "purpose": "Import local synthetic XML files from a ZIP into the PostgreSQL-backed vault.",
        "when": "Use for synthetic lab/demo fixtures through the same DATABASE_URL boundary.",
        "example": "cfdi-vault import-zip examples/synthetic-cfdi/invoices.zip --database-url postgresql+psycopg://...",
    },
    {
        "command": "summary",
        "purpose": "Show PostgreSQL totals grouped by month, issuer, and comprobante type.",
        "when": "Use with the local synthetic import path.",
        "example": "cfdi-vault summary --database-url postgresql+psycopg://...",
    },
    {
        "command": "export-csv",
        "purpose": "Export PostgreSQL imported CFDI records to CSV.",
        "when": "Use with the local synthetic import path.",
        "example": "cfdi-vault export-csv export.csv --database-url postgresql+psycopg://...",
    },
)

def help_command(
    topic: str | None = typer.Argument(None, help='Optional command name, e.g. "sync metadata".'),
) -> None:
    """Explain CFDI Vault MX workflows and command responsibilities."""

    if topic:
        command = _find_command_help(topic)
        if command is None:
            typer.echo(f"Unknown help topic: {topic}", err=True)
            typer.echo("Run: cfdi-vault help")
            raise typer.Exit(code=1)
        _print_command_help(command)
        return

    typer.echo("CFDI Vault MX help")
    typer.echo("")
    typer.echo("Recommended recovery flow:")
    typer.echo("  1. cfdi-vault doctor")
    typer.echo("  2. cfdi-vault setup --source-folder <external-folder>")
    typer.echo("  3. cfdi-vault status")
    typer.echo("  4. cfdi-vault init --tenant-id <tenant> --rfc <RFC>")
    typer.echo("  5. cfdi-vault sat campaign create --profile <profile>")
    typer.echo("  6. cfdi-vault sat campaign authorize --profile <profile> --campaign-ref <campaign-ref> ...")
    typer.echo("  7. cfdi-vault sat campaign run --profile <profile> --campaign-ref <campaign-ref> --grant <grant-ref>")
    typer.echo("  8. cfdi-vault search <text-or-rfc>")
    typer.echo("  9. cfdi-vault show <UUID>")
    typer.echo(" 10. cfdi-vault print <UUID> --format pdf")
    typer.echo("")
    typer.echo("Command catalog:")
    for command in COMMAND_HELP:
        typer.echo(f"  {command['command']:<14} {command['purpose']}")
    typer.echo("")
    typer.echo('For details: cfdi-vault help "sat campaign run"')
    typer.echo("For Typer options: cfdi-vault <command> --help")

def _find_command_help(topic: str) -> dict[str, str] | None:
    normalized = topic.strip().lower()
    for command in COMMAND_HELP:
        if command["command"] == normalized:
            return command
    return None

def _print_command_help(command: dict[str, str]) -> None:
    typer.echo(command["command"])
    typer.echo(f"Purpose: {command['purpose']}")
    typer.echo(f"When to use: {command['when']}")
    typer.echo(f"Example: {command['example']}")


def register(app: typer.Typer) -> None:
    """Register custom help commands on the root Typer app."""
    app.command("help")(help_command)
