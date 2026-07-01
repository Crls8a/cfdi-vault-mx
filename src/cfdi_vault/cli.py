"""Typer CLI for CFDI Vault MX."""

from __future__ import annotations

from datetime import datetime, time, timezone
import os
from pathlib import Path

import typer

from cfdi_vault.config import ConfigValidationError, load_config
from cfdi_vault.domain import DownloadDirection, RequestType
from cfdi_vault.cache import RedisCache
from cfdi_vault.onboarding import (
    OnboardingError,
    OnboardingRequest,
    parse_download_mode,
    parse_iso_date,
    parse_schedule_mode,
    run_onboarding,
)
from cfdi_vault.queueing import RabbitMqQueue
from cfdi_vault.recovery_service import RecoveryService, build_default_query, write_minimal_pdf
from cfdi_vault.service import ImportBatchResult, ImportRecord, SummaryRow, VaultService
from cfdi_vault.worker import RecoveryWorker

app = typer.Typer(
    name="cfdi-vault",
    help="Recover, reconcile, search, and export CFDI data.",
    no_args_is_help=True,
)
config_app = typer.Typer(help="Validate local RFC profile configuration.", no_args_is_help=True)
queue_app = typer.Typer(help="Inspect queue state.", no_args_is_help=True)
worker_app = typer.Typer(help="Run recovery workers.", no_args_is_help=True)
sync_app = typer.Typer(help="Submit SAT recovery sync jobs.", no_args_is_help=True)

app.add_typer(config_app, name="config")
app.add_typer(queue_app, name="queue")
app.add_typer(worker_app, name="worker")
app.add_typer(sync_app, name="sync")


COMMAND_HELP: tuple[dict[str, str], ...] = (
    {
        "command": "doctor",
        "purpose": "Check whether database, queue, cache, and storage are reachable.",
        "when": "Run after install or when the CLI cannot connect to dependencies.",
        "example": "cfdi-vault doctor",
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
        "purpose": "Import one local synthetic CFDI XML into the legacy local-first SQLite vault.",
        "when": "Use for old lab/demo fixtures, not for SAT recovery.",
        "example": "cfdi-vault import-xml examples/synthetic-cfdi/invoice-income.xml",
    },
    {
        "command": "import-zip",
        "purpose": "Import local synthetic XML files from a ZIP into the legacy SQLite vault.",
        "when": "Use for old lab/demo fixtures, not for SAT recovery.",
        "example": "cfdi-vault import-zip examples/synthetic-cfdi/invoices.zip",
    },
    {
        "command": "summary",
        "purpose": "Show legacy SQLite totals grouped by month, issuer, and comprobante type.",
        "when": "Use with the local synthetic import path.",
        "example": "cfdi-vault summary",
    },
    {
        "command": "export-csv",
        "purpose": "Export legacy SQLite imported CFDI records to CSV.",
        "when": "Use with the local synthetic import path.",
        "example": "cfdi-vault export-csv export.csv",
    },
)


def _db_option() -> Path:
    return Path("cfdi-vault.sqlite3")


def _recovery_db_option() -> Path:
    return Path("cfdi-vault-recovery.sqlite3")


def _service(
    database_url: str | None = None,
    recovery_db: Path | None = None,
    storage: Path | None = None,
) -> RecoveryService:
    queue = RabbitMqQueue(os.environ["RABBITMQ_URL"]) if os.getenv("RABBITMQ_URL") else None
    cache = RedisCache(os.environ["REDIS_URL"]) if os.getenv("REDIS_URL") else None
    return RecoveryService(
        database_url=database_url or os.getenv("DATABASE_URL"),
        sqlite_path=recovery_db or _recovery_db_option(),
        storage_root=_resolve_storage_root(storage),
        queue=queue,
        cache=cache,
    )


def _resolve_storage_root(storage: Path | None = None) -> Path:
    return storage or Path(os.getenv("CFDI_STORAGE_ROOT", "storage"))


def _require_queue_for_enqueue(enqueue: bool) -> None:
    if enqueue and not os.getenv("RABBITMQ_URL"):
        typer.echo("--enqueue requires RABBITMQ_URL so another worker process can consume the job.", err=True)
        raise typer.Exit(code=1)


@app.command("help")
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
    typer.echo("  2. cfdi-vault init --tenant-id <tenant> --rfc <RFC>")
    typer.echo("  3. cfdi-vault sync metadata --tenant-id <tenant> --rfc <RFC> --start YYYY-MM-DD --end YYYY-MM-DD")
    typer.echo("  4. cfdi-vault sync xml --tenant-id <tenant> --rfc <RFC> --start YYYY-MM-DD --end YYYY-MM-DD")
    typer.echo("  5. cfdi-vault search <text-or-rfc>")
    typer.echo("  6. cfdi-vault show <UUID>")
    typer.echo("  7. cfdi-vault print <UUID> --format pdf")
    typer.echo("")
    typer.echo("Command catalog:")
    for command in COMMAND_HELP:
        typer.echo(f"  {command['command']:<14} {command['purpose']}")
    typer.echo("")
    typer.echo('For details: cfdi-vault help "sync metadata"')
    typer.echo("For Typer options: cfdi-vault <command> --help")


@config_app.command("validate")
def config_validate(
    config_path: Path = typer.Argument(..., exists=True, dir_okay=False, readable=True),
) -> None:
    """Validate a local RFC profile config file."""

    try:
        config = load_config(config_path)
    except ConfigValidationError as exc:
        typer.echo("Config validation failed:", err=True)
        for error in exc.errors:
            typer.echo(f"- {error}", err=True)
        raise typer.Exit(code=1) from exc

    typer.echo(f"Config OK: schemaVersion={config.schema_version}, profiles={len(config.profiles)}")
    for profile in config.profiles:
        typer.echo(
            f"- {profile.profile_id}: rfc={profile.rfc}, "
            f"storageRoot={profile.storage_root}, metadataFirst={profile.download.metadata_first}"
        )


@app.command("onboard")
def onboard(
    config_path: Path = typer.Option(Path("cfdi-vault.local.json"), "--config", help="Safe profile config to create or update."),
    profile_id: str | None = typer.Option(None, "--profile-id", help="Local profile identifier."),
    rfc: str | None = typer.Option(None, "--rfc", help="Taxpayer RFC for this local profile."),
    storage_root: Path | None = typer.Option(None, "--storage-root", help="Root folder for metadata, packages, XML, logs, and exports."),
    download_mode: str | None = typer.Option(None, "--download-mode", help="issued, received, or both."),
    start_date: str | None = typer.Option(None, "--start-date", help="Initial download start date: YYYY-MM-DD."),
    end_date: str | None = typer.Option(None, "--end-date", help="Optional initial download end date: YYYY-MM-DD."),
    periodicity: str | None = typer.Option(None, "--periodicity", help="disabled, interval, or daily."),
    interval_minutes: int | None = typer.Option(None, "--interval-minutes", min=1, help="Minutes between runs when periodicity is interval."),
    daily_at: str | None = typer.Option(None, "--daily-at", help="HH:MM local time when periodicity is daily."),
    max_concurrency: int | None = typer.Option(None, "--max-concurrency", min=1, max=10, help="Maximum concurrent SAT/recovery work."),
    certificate_path: Path | None = typer.Option(None, "--cer", help="Local .cer file to validate. The file is not copied."),
    private_key_path: Path | None = typer.Option(None, "--key", help="Local .key file to validate. The file is not copied."),
    timezone_name: str = typer.Option("America/Mexico_City", "--timezone", help="Schedule timezone stored in config."),
    credential_ref_prefix: str | None = typer.Option(None, "--credential-ref-prefix", help="Non-secret reference prefix for external credential custody."),
    replace_existing: bool = typer.Option(False, "--replace-existing", help="Replace an existing profile with the same profile id."),
) -> None:
    """Create the first safe local profile config without storing credential material."""

    typer.echo("Security warnings:")
    typer.echo("- Do not use real e.firma material in test or development fixtures.")
    typer.echo("- Do not share the private key file (`.key`).")
    typer.echo("- The private-key phrase is checked only for presence and is never written to config.")

    try:
        profile_id = _required_text(profile_id, "Profile id")
        rfc = _required_text(rfc, "RFC")
        storage_root = _required_path(storage_root, "Storage root")
        download_mode = _required_text(download_mode, "Download mode [issued/received/both]", default="both")
        start_date = _required_text(start_date, "Initial start date [YYYY-MM-DD]")
        if end_date is None:
            end_date = str(typer.prompt("Initial end date [YYYY-MM-DD, optional]", default="")).strip() or None
        periodicity = _required_text(periodicity, "Periodicity [disabled/interval/daily]", default="disabled")
        if max_concurrency is None:
            max_concurrency = int(typer.prompt("Maximum concurrency", default="2"))
        certificate_path = _required_path(certificate_path, "Path to .cer file")
        private_key_path = _required_path(private_key_path, "Path to .key file")
        schedule_mode = parse_schedule_mode(periodicity)
        if schedule_mode.value == "interval" and interval_minutes is None:
            interval_minutes = int(typer.prompt("Interval minutes"))
        if schedule_mode.value == "daily" and daily_at is None:
            daily_at = str(typer.prompt("Daily time [HH:MM]")).strip()
        request = OnboardingRequest(
            profile_id=profile_id,
            rfc=rfc,
            storage_root=storage_root,
            download_mode=parse_download_mode(download_mode),
            start_date=parse_iso_date(start_date, "start date"),
            end_date=parse_iso_date(end_date, "end date") if end_date else None,
            schedule_mode=schedule_mode,
            interval_minutes=interval_minutes,
            daily_at=daily_at,
            max_concurrency=max_concurrency,
            certificate_path=certificate_path,
            private_key_path=private_key_path,
            output_config=config_path,
            timezone=timezone_name,
            credential_ref_prefix=credential_ref_prefix,
            replace_existing=replace_existing,
        )
        phrase_value = typer.prompt(
            "Private-key phrase (hidden; discarded after validation)",
            hide_input=True,
            confirmation_prompt=True,
        )
        result = run_onboarding(request, str(phrase_value))
    except (OnboardingError, ValueError) as exc:
        typer.echo("Onboarding failed:", err=True)
        errors = exc.errors if isinstance(exc, OnboardingError) else (str(exc),)
        for error in errors:
            typer.echo(f"- {error}", err=True)
        raise typer.Exit(code=1) from exc

    typer.echo("Onboarding complete.")
    typer.echo(f"Config: {result.output_config}")
    typer.echo(f"Profile: {result.profile_id} ({result.rfc})")
    typer.echo(f"Storage root: {result.storage_root}")
    typer.echo(f"Certificate fingerprint: {result.certificate_fingerprint}")
    typer.echo("Credential material was not copied and the private-key phrase was not stored.")


@app.command("doctor")
def doctor(
    database_url: str | None = typer.Option(None, "--database-url", help="PostgreSQL URL. Defaults to DATABASE_URL."),
    recovery_db: Path = typer.Option(_recovery_db_option(), "--recovery-db", help="SQLite fallback path for local fake mode."),
    storage: Path | None = typer.Option(None, "--storage", help="Storage root. Defaults to CFDI_STORAGE_ROOT or storage/."),
) -> None:
    """Check database, queue, cache, and storage connectivity."""

    checks = _service(database_url, recovery_db, storage).doctor()
    for check in checks:
        status = "OK" if check.ok else "FAIL"
        typer.echo(f"{status} {check.name}: {check.detail}")
    if not all(check.ok for check in checks):
        raise typer.Exit(code=1)


@app.command("init")
def init(
    tenant_id: str = typer.Option("default", "--tenant-id", help="Tenant identifier."),
    rfc: str = typer.Option(..., "--rfc", help="Requester RFC."),
    name: str | None = typer.Option(None, "--name", help="Tenant display name."),
    database_url: str | None = typer.Option(None, "--database-url", help="PostgreSQL URL. Defaults to DATABASE_URL."),
    recovery_db: Path = typer.Option(_recovery_db_option(), "--recovery-db", help="SQLite fallback path for local fake mode."),
    storage: Path | None = typer.Option(None, "--storage", help="Storage root. Defaults to CFDI_STORAGE_ROOT or storage/."),
) -> None:
    """Initialize the recovery schema, storage folders, and tenant row."""

    service = _service(database_url, recovery_db, storage)
    service.init_tenant(tenant_id, rfc, name)
    typer.echo(f"Initialized tenant {tenant_id} for RFC {rfc.upper()}")


@queue_app.command("status")
def queue_status(
    database_url: str | None = typer.Option(None, "--database-url", help="PostgreSQL URL. Defaults to DATABASE_URL."),
    recovery_db: Path = typer.Option(_recovery_db_option(), "--recovery-db", help="SQLite fallback path for local fake mode."),
    storage: Path | None = typer.Option(None, "--storage", help="Storage root. Defaults to CFDI_STORAGE_ROOT or storage/."),
) -> None:
    """Show durable queue/job event counts."""

    rows = _service(database_url, recovery_db, storage).queue_status()
    typer.echo("queue,status,count")
    if not rows:
        typer.echo("(no queue events)")
        return
    for row in rows:
        typer.echo(f"{row['queue']},{row['status']},{row['count']}")


@worker_app.command("run")
def worker_run(
    once: bool = typer.Option(True, "--once/--loop", help="Run once or keep polling the configured queue."),
    poll_seconds: float = typer.Option(5.0, "--poll-seconds", min=0.5, help="Polling interval when --loop is used."),
    database_url: str | None = typer.Option(None, "--database-url", help="PostgreSQL URL. Defaults to DATABASE_URL."),
    recovery_db: Path = typer.Option(_recovery_db_option(), "--recovery-db", help="SQLite fallback path for local fake mode."),
    storage: Path | None = typer.Option(None, "--storage", help="Storage root. Defaults to CFDI_STORAGE_ROOT or storage/."),
) -> None:
    """Run the recovery worker shell."""

    worker = RecoveryWorker(_service(database_url, recovery_db, storage))
    if not once:
        worker.run_forever(poll_seconds=poll_seconds)
        return
    report = worker.run_once()
    typer.echo(f"processed={report.processed} detail={report.detail}")


@sync_app.command("metadata")
def sync_metadata(
    rfc: str = typer.Option(..., "--rfc", help="Requester RFC."),
    tenant_id: str = typer.Option("default", "--tenant-id", help="Tenant identifier."),
    start: str = typer.Option(..., "--start", help="Start date/datetime, e.g. 2024-01-01."),
    end: str = typer.Option(..., "--end", help="End date/datetime, e.g. 2024-01-31."),
    direction: DownloadDirection = typer.Option(DownloadDirection.RECEIVED, "--direction", help="Download direction."),
    live: bool = typer.Option(False, "--live", help="Use live SAT SOAP. Not implemented in this slice."),
    enqueue: bool = typer.Option(False, "--enqueue", help="Publish the job for a worker instead of processing synchronously."),
    database_url: str | None = typer.Option(None, "--database-url", help="PostgreSQL URL. Defaults to DATABASE_URL."),
    recovery_db: Path = typer.Option(_recovery_db_option(), "--recovery-db", help="SQLite fallback path for local fake mode."),
    storage: Path | None = typer.Option(None, "--storage", help="Storage root. Defaults to CFDI_STORAGE_ROOT or storage/."),
) -> None:
    """Submit a metadata sync. Fake SAT is used unless --live is passed."""

    query = build_default_query(
        tenant_id=tenant_id,
        rfc=rfc,
        direction=direction,
        request_type=RequestType.METADATA,
        start=_parse_cli_datetime(start, end_of_day=False),
        end=_parse_cli_datetime(end, end_of_day=True),
    )
    _require_queue_for_enqueue(enqueue)
    result = _service(database_url, recovery_db, storage).sync_metadata(query, live=live, enqueue=enqueue)
    typer.echo(f"job_id={result.job_id}")
    typer.echo(f"request_id={result.request_id}")
    typer.echo(f"status={result.status}")
    typer.echo(f"packages={','.join(result.packages)}")
    typer.echo(f"metadata_count={result.metadata_count}")


@sync_app.command("xml")
def sync_xml(
    rfc: str = typer.Option(..., "--rfc", help="Requester RFC."),
    tenant_id: str = typer.Option("default", "--tenant-id", help="Tenant identifier."),
    start: str = typer.Option(..., "--start", help="Start date/datetime, e.g. 2024-01-01."),
    end: str = typer.Option(..., "--end", help="End date/datetime, e.g. 2024-01-31."),
    direction: DownloadDirection = typer.Option(DownloadDirection.RECEIVED, "--direction", help="Download direction."),
    live: bool = typer.Option(False, "--live", help="Use live SAT SOAP. Not implemented in this slice."),
    enqueue: bool = typer.Option(False, "--enqueue", help="Publish the job for a worker instead of processing synchronously."),
    database_url: str | None = typer.Option(None, "--database-url", help="PostgreSQL URL. Defaults to DATABASE_URL."),
    recovery_db: Path = typer.Option(_recovery_db_option(), "--recovery-db", help="SQLite fallback path for local fake mode."),
    storage: Path | None = typer.Option(None, "--storage", help="Storage root. Defaults to CFDI_STORAGE_ROOT or storage/."),
) -> None:
    """Submit an XML/package sync. Fake mode stores packages and extracted XML evidence."""

    query = build_default_query(
        tenant_id=tenant_id,
        rfc=rfc,
        direction=direction,
        request_type=RequestType.CFDI,
        start=_parse_cli_datetime(start, end_of_day=False),
        end=_parse_cli_datetime(end, end_of_day=True),
    )
    _require_queue_for_enqueue(enqueue)
    result = _service(database_url, recovery_db, storage).sync_metadata(query, live=live, enqueue=enqueue)
    typer.echo(f"job_id={result.job_id}")
    typer.echo(f"request_id={result.request_id}")
    typer.echo(f"status={result.status}")
    typer.echo(f"packages={','.join(result.packages)}")
    typer.echo(f"metadata_count={result.metadata_count}")


@app.command("reconcile")
def reconcile(
    tenant_id: str | None = typer.Option(None, "--tenant-id", help="Tenant identifier."),
    database_url: str | None = typer.Option(None, "--database-url", help="PostgreSQL URL. Defaults to DATABASE_URL."),
    recovery_db: Path = typer.Option(_recovery_db_option(), "--recovery-db", help="SQLite fallback path for local fake mode."),
    storage: Path | None = typer.Option(None, "--storage", help="Storage root. Defaults to CFDI_STORAGE_ROOT or storage/."),
) -> None:
    """Recompute metadata/XML reconciliation states."""

    count = _service(database_url, recovery_db, storage).reconcile(tenant_id=tenant_id)
    typer.echo(f"Updated {count} reconciliation row(s)")


@app.command("search")
def search(
    text: str = typer.Argument("", help="Text, UUID, RFC, or party name to search."),
    tenant_id: str | None = typer.Option(None, "--tenant-id", help="Tenant identifier."),
    limit: int = typer.Option(20, "--limit", min=1, max=200, help="Maximum rows."),
    database_url: str | None = typer.Option(None, "--database-url", help="PostgreSQL URL. Defaults to DATABASE_URL."),
    recovery_db: Path = typer.Option(_recovery_db_option(), "--recovery-db", help="SQLite fallback path for local fake mode."),
    storage: Path | None = typer.Option(None, "--storage", help="Storage root. Defaults to CFDI_STORAGE_ROOT or storage/."),
) -> None:
    """Search normalized CFDI data."""

    rows = _service(database_url, recovery_db, storage).search(text, tenant_id=tenant_id, limit=limit)
    typer.echo("uuid,issuer_rfc,receiver_rfc,issue_date,total,status,parser_status")
    if not rows:
        typer.echo("(no matches)")
        return
    for row in rows:
        typer.echo(
            f"{row['uuid']},{row['issuer_rfc']},{row['receiver_rfc']},"
            f"{row['issue_date']},{row['total']},{row['status']},{row['parser_status']}"
        )


@app.command("show")
def show(
    uuid: str = typer.Argument(..., help="CFDI UUID."),
    tenant_id: str | None = typer.Option(None, "--tenant-id", help="Tenant identifier."),
    database_url: str | None = typer.Option(None, "--database-url", help="PostgreSQL URL. Defaults to DATABASE_URL."),
    recovery_db: Path = typer.Option(_recovery_db_option(), "--recovery-db", help="SQLite fallback path for local fake mode."),
    storage: Path | None = typer.Option(None, "--storage", help="Storage root. Defaults to CFDI_STORAGE_ROOT or storage/."),
) -> None:
    """Show one CFDI in terminal-friendly form."""

    service = _service(database_url, recovery_db, storage)
    try:
        typer.echo(service.render_text(uuid, tenant_id=tenant_id))
    except LookupError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc


@app.command("print")
def print_invoice(
    uuid: str = typer.Argument(..., help="CFDI UUID."),
    output_path: Path | None = typer.Option(None, "--output", "-o", help="Output file. Required for html/pdf."),
    format: str = typer.Option("text", "--format", help="text, html, or pdf."),
    tenant_id: str | None = typer.Option(None, "--tenant-id", help="Tenant identifier."),
    database_url: str | None = typer.Option(None, "--database-url", help="PostgreSQL URL. Defaults to DATABASE_URL."),
    recovery_db: Path = typer.Option(_recovery_db_option(), "--recovery-db", help="SQLite fallback path for local fake mode."),
    storage: Path | None = typer.Option(None, "--storage", help="Storage root. Defaults to CFDI_STORAGE_ROOT or storage/."),
) -> None:
    """Render a CFDI as text, HTML, or a basic PDF."""

    service = _service(database_url, recovery_db, storage)
    try:
        if format == "text":
            text = service.render_text(uuid, tenant_id=tenant_id)
            if output_path:
                output_path.parent.mkdir(parents=True, exist_ok=True)
                output_path.write_text(text, encoding="utf-8")
            else:
                typer.echo(text)
            return
        if output_path is None:
            output_path = _resolve_storage_root(storage) / "exports" / f"{uuid}.{format}"
        if format == "html":
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(service.render_html(uuid, tenant_id=tenant_id), encoding="utf-8")
        elif format == "pdf":
            write_minimal_pdf(output_path, service.render_text(uuid, tenant_id=tenant_id))
        else:
            raise ValueError("format must be text, html, or pdf")
    except (LookupError, ValueError) as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(f"Wrote {output_path}")


@app.command("export")
def export(
    output_path: Path | None = typer.Option(None, "--output", "-o", help="Output CSV path."),
    format: str = typer.Option("csv", "--format", help="Only csv is supported in this slice."),
    tenant_id: str | None = typer.Option(None, "--tenant-id", help="Tenant identifier."),
    database_url: str | None = typer.Option(None, "--database-url", help="PostgreSQL URL. Defaults to DATABASE_URL."),
    recovery_db: Path = typer.Option(_recovery_db_option(), "--recovery-db", help="SQLite fallback path for local fake mode."),
    storage: Path | None = typer.Option(None, "--storage", help="Storage root. Defaults to CFDI_STORAGE_ROOT or storage/."),
) -> None:
    """Export normalized CFDI data."""

    if format != "csv":
        typer.echo("Only csv export is supported in this slice.", err=True)
        raise typer.Exit(code=1)
    if output_path is None:
        output_path = _resolve_storage_root(storage) / "exports" / "cfdi.csv"
    count = _service(database_url, recovery_db, storage).export_csv(output_path, tenant_id=tenant_id)
    typer.echo(f"Exported {count} CFDI row(s) to {output_path}")


@app.command("import-xml")
def import_xml(
    xml_path: Path = typer.Argument(..., exists=True, dir_okay=False, readable=True),
    db: Path = typer.Option(_db_option(), "--db", help="SQLite database path."),
) -> None:
    """Import one synthetic CFDI XML file."""

    record = VaultService(db).import_xml_file(xml_path)
    _print_record(record)
    if record.error:
        raise typer.Exit(code=1)


@app.command("import-zip")
def import_zip(
    zip_path: Path = typer.Argument(..., exists=True, dir_okay=False, readable=True),
    db: Path = typer.Option(_db_option(), "--db", help="SQLite database path."),
) -> None:
    """Import all XML files from a ZIP archive."""

    result = VaultService(db).import_zip_file(zip_path)
    _print_batch(result)
    if result.failed:
        raise typer.Exit(code=1)


@app.command("summary")
def summary(
    db: Path = typer.Option(_db_option(), "--db", help="SQLite database path."),
) -> None:
    """Print totals grouped by month, issuer, and CFDI comprobante type."""

    vault_summary = VaultService(db).summary()
    _print_section("Totals by month", vault_summary.by_month)
    _print_section("Totals by issuer", vault_summary.by_issuer)
    _print_section("Totals by comprobante type", vault_summary.by_comprobante_type)


@app.command("export-csv")
def export_csv(
    output_path: Path = typer.Argument(..., dir_okay=False, writable=True),
    db: Path = typer.Option(_db_option(), "--db", help="SQLite database path."),
) -> None:
    """Export imported CFDI records to CSV."""

    count = VaultService(db).export_csv(output_path)
    typer.echo(f"Exported {count} invoice(s) to {output_path}")


def _print_record(record: ImportRecord) -> None:
    if record.error:
        typer.echo(f"ERROR {record.source_name}: {record.error}", err=True)
        return
    if record.duplicate:
        typer.echo(f"SKIPPED duplicate UUID {record.uuid} from {record.source_name}")
        return
    typer.echo(f"IMPORTED UUID {record.uuid} from {record.source_name}")
    typer.echo(f"SHA-256 {record.xml_sha256}")


def _print_batch(result: ImportBatchResult) -> None:
    for record in result.records:
        _print_record(record)
    typer.echo(
        f"Processed {result.total_files} XML file(s): "
        f"{result.imported} imported, {result.duplicates} duplicate(s), {result.failed} failed."
    )


def _print_section(title: str, rows: tuple[SummaryRow, ...]) -> None:
    typer.echo(f"\n{title}")
    typer.echo("label,count,subtotal,total")
    if not rows:
        typer.echo("(no rows)")
        return
    for row in rows:
        typer.echo(f"{row.label},{row.count},{row.subtotal:.2f},{row.total:.2f}")


def _parse_cli_datetime(value: str, *, end_of_day: bool) -> datetime:
    normalized = value.strip()
    if "T" in normalized or " " in normalized:
        parsed = datetime.fromisoformat(normalized.replace("Z", "+00:00"))
    else:
        parsed = datetime.combine(datetime.fromisoformat(normalized).date(), time.max if end_of_day else time.min)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


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


def _required_text(value: str | None, prompt: str, *, default: str | None = None) -> str:
    if value is None or not value.strip():
        value = str(typer.prompt(prompt, default=default)).strip()
    if not value:
        raise ValueError(f"{prompt} is required")
    return value


def _required_path(value: Path | None, prompt: str) -> Path:
    if value is None:
        raw_value = str(typer.prompt(prompt)).strip()
        if not raw_value:
            raise ValueError(f"{prompt} is required")
        value = Path(raw_value)
    return value
