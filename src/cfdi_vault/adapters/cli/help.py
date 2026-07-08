"""Custom CLI help catalog."""

from __future__ import annotations

import typer


COMMAND_HELP: tuple[dict[str, str], ...] = (
    {
        "command": "doctor",
        "purpose": "Check whether database, queue, cache, storage, and setup profile are reachable.",
        "when": "Run after install or when the CLI cannot connect to dependencies.",
        "example": "cfdi-vault doctor",
    },
    {
        "command": "setup",
        "purpose": "Create the local AppData RFC profile and import credential files without env vars.",
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
        "command": "sync metadata",
        "purpose": "Recover SAT metadata for a tenant/RFC/date range and load the metadata ledger.",
        "when": "Run before XML recovery so the system knows which UUIDs should exist.",
        "example": "cfdi-vault sync metadata --tenant-id acme --rfc AAA010101AAA --start 2024-01-01 --end 2024-01-31",
    },
    {
        "command": "sync xml",
        "purpose": "Recover SAT packages/XML evidence, register local file paths, parse known fields, and load data.",
        "when": "Run after or alongside metadata recovery when XML evidence is needed.",
        "example": "cfdi-vault sync xml --tenant-id acme --rfc AAA010101AAA --start 2024-01-01 --end 2024-01-31",
    },
    {
        "command": "download plan",
        "purpose": "Validate a safe fake/offline SAT download query from a setup profile.",
        "when": "Run before submitting a fake SAT request to confirm criteria without printing RFCs or paths.",
        "example": "cfdi-vault download plan --profile default --from 2024-01-01 --to 2024-01-31 --kind metadata --direction received",
    },
    {
        "command": "download request",
        "purpose": "Submit a fake/offline SAT download request and print the synthetic accepted result.",
        "when": "Run after planning when you need a synthetic request id for offline workflow tests.",
        "example": "cfdi-vault download request --profile default --from 2024-01-01 --to 2024-01-31 --kind cfdi --direction issued",
    },
    {
        "command": "download sync",
        "purpose": "Run a fake/offline SAT download sync from a setup profile and persist local recovery evidence.",
        "when": "Run when you need the offline request, verification, package, metadata, and XML pipeline to finish locally.",
        "example": "cfdi-vault download sync --profile default --from 2024-01-01 --to 2024-01-31 --kind cfdi --direction received",
    },
    {
        "command": "download status",
        "purpose": "Read safe fake/offline download status by job id or async verify scheduler aggregates without one.",
        "when": "Run after download sync with --job-id, or without --job-id to inspect pending verify work.",
        "example": "cfdi-vault download status --profile default",
    },
    {
        "command": "download live-smoke",
        "purpose": "Validate the guarded metadata-only live SAT smoke path without allowing CFDI/XML download.",
        "when": "Run only after explicit approval for one local SAT smoke attempt.",
        "example": "cfdi-vault download live-smoke --profile default --from YYYY-MM-DD --to YYYY-MM-DD --kind metadata --direction received --permit PERMIT_ID",
    },
    {
        "command": "sat auth-smoke",
        "purpose": "Validate live SAT authentication smoke gates before any real SAT auth attempt.",
        "when": "Run only on the operator machine after explicit human approval.",
        "example": "cfdi-vault sat auth-smoke --profile default --manual-real-sat --permit PERMIT_ID",
    },
    {
        "command": "sat metadata-request-state",
        "purpose": "List locally persisted live metadata requests pending verify using redacted request refs.",
        "when": "Run after a request-only smoke to recover the safe request-ref without printing IdSolicitud.",
        "example": "cfdi-vault sat metadata-request-state --profile default",
    },
    {
        "command": "sat verify-due",
        "purpose": "Run one non-live async verify scheduler attempt for due persisted metadata requests.",
        "when": "Run manually or from Task Scheduler; it verifies once, updates next_check_at, and exits.",
        "example": "cfdi-vault sat verify-due --profile default --limit 1",
    },
    {
        "command": "sat metadata-verify-smoke",
        "purpose": "Verify one locally persisted metadata request-ref without creating a new request or downloading packages.",
        "when": "Run only after explicit approval for one verify-only SAT smoke.",
        "example": "cfdi-vault sat metadata-verify-smoke --profile default --request-ref <request-ref> --permit PERMIT_ID",
    },
    {
        "command": "sat verify-live-gate",
        "purpose": "Run the controlled v1.5 production-signed verify gate after redacted preflight and local oracle parity.",
        "when": "Use for the single approved verify live gate only; it never downloads packages.",
        "example": "cfdi-vault sat verify-live-gate --profile default --request-ref <request-ref> --manual-real-sat --permit PERMIT_ID --connect-timeout-seconds 15 --read-timeout-seconds 60",
    },
    {
        "command": "sat download-live-gate",
        "purpose": "Run the controlled v1.5 package download gate for one package after EstadoSolicitud=3 and IdsPaquetes.",
        "when": "Use only after explicit approval; it validates ZIP bytes in memory and does not parse XML/PDF.",
        "example": "cfdi-vault sat download-live-gate --profile default --request-ref <request-ref> --manual-real-sat --permit PERMIT_ID --connect-timeout-seconds 15 --read-timeout-seconds 180",
    },
    {
        "command": "sat inspect-auth-contract",
        "purpose": "Fetch the public SAT auth WSDL and print only a redacted contract summary.",
        "when": "Run before auth envelope compatibility work; never stores or prints raw WSDL.",
        "example": "cfdi-vault sat inspect-auth-contract",
    },
    {
        "command": "sat lint-auth-envelope",
        "purpose": "Build a dummy SAT auth envelope and print redacted structural lint checks.",
        "when": "Run before any live auth retry; never prints raw XML, cert material, or signature values.",
        "example": "cfdi-vault sat lint-auth-envelope --fixture dummy",
    },
    {
        "command": "sat oracle-auth-fingerprint",
        "purpose": "Compare a redacted local auth envelope fingerprint with a phpcfdi oracle source when available.",
        "when": "Run before any further auth-smoke retry; never prints raw SOAP or credential material.",
        "example": "cfdi-vault sat oracle-auth-fingerprint --fixture dummy",
    },
    {
        "command": "sat diff-auth-oracle",
        "purpose": "Print a redacted structural diff between the local SAT auth envelope and a phpcfdi oracle source.",
        "when": "Run offline before deciding any SAT auth-smoke retry.",
        "example": "cfdi-vault sat diff-auth-oracle --oracle phpcfdi --fixture dummy --redacted --phpcfdi-builder-source C:\\path\\outside\\repo\\FielRequestBuilder.php",
    },
    {
        "command": "sat diagnose-live",
        "purpose": "Run a guarded metadata-only SAT live diagnostic with redacted stage output.",
        "when": "Run only after a live smoke failure and explicit human approval for one diagnostic attempt.",
        "example": "cfdi-vault sat diagnose-live --profile default --from YYYY-MM-DD --to YYYY-MM-DD --kind metadata --direction received --manual-real-sat",
    },
    {
        "command": "sat probe-transport",
        "purpose": "Probe public SAT DNS/TLS/WSDL transport without loading e.firma material.",
        "when": "Run before retrying #50 when live auth transport fails.",
        "example": "cfdi-vault sat probe-transport --profile default --permit PERMIT_ID",
    },
    {
        "command": "sat probe-auth-post",
        "purpose": "Probe auth HTTPS POST transport without loading e.firma material or requesting metadata.",
        "when": "Run after public transport passes and before any metadata-only smoke retry.",
        "example": "cfdi-vault sat probe-auth-post --profile default --permit PERMIT_ID",
    },
    {
        "command": "sat probe-auth-matrix",
        "purpose": "Run a no-credential auth GET/WSDL/POST matrix with Python and optional external clients.",
        "when": "Run after auth endpoint parity is merged to isolate Python/client/SAT/proxy transport behavior.",
        "example": "cfdi-vault sat probe-auth-matrix --profile default --permit PERMIT_ID",
    },
    {
        "command": "live permit create",
        "purpose": "Create one AppData-local, one-time, expiring permit for a scoped live SAT operation.",
        "when": "Use instead of an interactive confirmation prompt for an explicitly authorized live attempt.",
        "example": "cfdi-vault live permit create --scope auth_matrix_probe --profile default --kind metadata --direction received --from YYYY-MM-DD --to YYYY-MM-DD --expires-minutes 15 --reason \"Carlos authorized auth matrix probe\"",
    },
    {
        "command": "queue status",
        "purpose": "Show queue/job event counts from the durable event log.",
        "when": "Use when a job is pending, failed, or needs operational inspection.",
        "example": "cfdi-vault queue status",
    },
    {
        "command": "worker run",
        "purpose": "Process queued recovery work from RabbitMQ.",
        "when": "Use with --enqueue workflows or in the Docker Compose worker service.",
        "example": "cfdi-vault worker run --loop",
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
    typer.echo("  5. cfdi-vault sync metadata --tenant-id <tenant> --rfc <RFC> --start YYYY-MM-DD --end YYYY-MM-DD")
    typer.echo("  6. cfdi-vault sync xml --tenant-id <tenant> --rfc <RFC> --start YYYY-MM-DD --end YYYY-MM-DD")
    typer.echo("  7. cfdi-vault search <text-or-rfc>")
    typer.echo("  8. cfdi-vault show <UUID>")
    typer.echo("  9. cfdi-vault print <UUID> --format pdf")
    typer.echo("")
    typer.echo("Command catalog:")
    for command in COMMAND_HELP:
        typer.echo(f"  {command['command']:<14} {command['purpose']}")
    typer.echo("")
    typer.echo('For details: cfdi-vault help "sync metadata"')
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
