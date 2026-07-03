"""Typer CLI for CFDI Vault MX."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, time, timezone
import os
from pathlib import Path
import subprocess
import sys

import typer

from cfdi_vault import setup as setup_flow
from cfdi_vault.config import ConfigValidationError, load_config
from cfdi_vault.domain import DateTimePeriod, DownloadDirection, DownloadQuery, RequestType
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
from cfdi_vault.recovery_service import (
    DownloadStatus,
    RecoveryService,
    build_default_query,
    read_download_status,
    write_minimal_pdf,
)
from cfdi_vault.secrets import CredentialKind, CredentialProviderError, CredentialReference, DummySecretProvider
from cfdi_vault.service import ImportBatchResult, ImportRecord, SummaryRow, VaultService
from cfdi_vault.sat_orchestration import DownloadRequestOrchestrator
from cfdi_vault.sat_simulator import FakeSatScenario, FakeSatScenarioClient
from cfdi_vault.sat_transport import LiveSatGuardError, LiveSatGuardInput, validate_live_sat_guard
from cfdi_vault.worker import RecoveryWorker
from cfdi_vault.windows_secrets import WindowsCredentialManagerSecretProvider

app = typer.Typer(
    name="cfdi-vault",
    help="Recover, reconcile, search, and export CFDI data.",
    no_args_is_help=True,
)
config_app = typer.Typer(help="Validate local RFC profile configuration.", no_args_is_help=True)
queue_app = typer.Typer(help="Inspect queue state.", no_args_is_help=True)
worker_app = typer.Typer(help="Run recovery workers.", no_args_is_help=True)
sync_app = typer.Typer(help="Submit SAT recovery sync jobs.", no_args_is_help=True)
download_app = typer.Typer(help="Plan and submit fake/offline SAT download requests.", no_args_is_help=True)
sat_app = typer.Typer(help="Run human-gated SAT live smoke checks.", no_args_is_help=True)
custody_app = typer.Typer(help="Manage local secret references without printing values.", no_args_is_help=True)

app.add_typer(config_app, name="config")
app.add_typer(queue_app, name="queue")
app.add_typer(worker_app, name="worker")
app.add_typer(sync_app, name="sync")
app.add_typer(download_app, name="download")
app.add_typer(sat_app, name="sat")
app.add_typer(custody_app, name="secret")


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
        "purpose": "Read safe persisted fake/offline download status aggregates by job id.",
        "when": "Run after download sync when you need durable local readback without printing storage paths or package details.",
        "example": "cfdi-vault download status --profile default --job-id <job-id>",
    },
    {
        "command": "download live-smoke",
        "purpose": "Validate the human-gated metadata-only live SAT smoke path without allowing CFDI/XML download.",
        "when": "Run only after #50 is explicitly approved for one local manual SAT smoke attempt.",
        "example": "cfdi-vault download live-smoke --profile default --from YYYY-MM-DD --to YYYY-MM-DD --kind metadata --direction received --manual-real-sat",
    },
    {
        "command": "sat auth-smoke",
        "purpose": "Validate live SAT authentication smoke gates before any real SAT auth attempt.",
        "when": "Run only on the operator machine after explicit human approval.",
        "example": "cfdi-vault sat auth-smoke --profile default --manual-real-sat",
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

LIVE_SMOKE_CONFIRMATION = "SAT REAL METADATA SMOKE"


@dataclass(frozen=True)
class LiveSmokeCliResult:
    """Redacted CLI result for injected live smoke adapters."""

    result: str
    auth: str = "not_run"
    request: str = "not_run"
    verification: str = "not_run"


class LiveSmokeAdapterUnavailable(RuntimeError):
    """Raised after guards pass when the real live adapter is not wired yet."""


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


@custody_app.command("register")
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


@custody_app.command("verify")
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


@custody_app.command("delete")
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


def _prompt_private_key_phrase() -> str:
    prompt_text = "Private-key phrase (masked; stored through secret provider)"
    if _supports_masked_phrase_prompt():
        return _prompt_masked_with_confirmation(prompt_text)
    return str(
        typer.prompt(
            "Private-key phrase (hidden; stored through secret provider)",
            hide_input=True,
            confirmation_prompt=True,
        )
    )


def _supports_masked_phrase_prompt() -> bool:
    return os.name == "nt" and sys.stdin.isatty() and sys.stdout.isatty()


def _prompt_masked_with_confirmation(prompt_text: str, *, attempts: int = 3) -> str:
    for _attempt in range(attempts):
        phrase_value = _read_masked_line(f"{prompt_text}: ")
        confirmation_value = _read_masked_line("Repeat for confirmation: ")
        if phrase_value == confirmation_value:
            return phrase_value
        typer.echo("Error: the two entered values do not match.", err=True)
    raise ValueError("private-key phrase confirmation did not match")


def _read_masked_line(
    prompt_text: str,
    *,
    read_char: Callable[[], str] | None = None,
    write_text: Callable[[str], None] | None = None,
) -> str:
    if read_char is None:
        if os.name != "nt":
            return str(typer.prompt(prompt_text.rstrip(": "), hide_input=True))
        import msvcrt

        read_char = msvcrt.getwch
    if write_text is None:
        write_text = _write_prompt_fragment

    chars: list[str] = []
    write_text(prompt_text)
    while True:
        char = read_char()
        if char in ("\r", "\n"):
            write_text("\n")
            return "".join(chars)
        if char == "\x03":
            raise KeyboardInterrupt
        if char in ("\x00", "\xe0"):
            read_char()
            continue
        if char in ("\b", "\x7f"):
            if chars:
                chars.pop()
                write_text("\b \b")
            continue
        if char in ("\x04", "\x1a"):
            continue
        chars.append(char)
        write_text("*")


def _write_prompt_fragment(text: str) -> None:
    typer.echo(text, nl=False)
    sys.stdout.flush()


@app.command("setup")
def setup_command(
    source_folder: Path | None = typer.Option(None, "--source-folder", help="External folder containing the credential files."),
    profile_id: str = typer.Option("default", "--profile-id", help="Local setup profile id."),
    rfc: str | None = typer.Option(None, "--rfc", help="RFC for this local setup profile."),
    certificate_path: Path | None = typer.Option(None, "--cer", help="Explicit certificate file when source folder has more than one candidate."),
    private_key_path: Path | None = typer.Option(None, "--key", help="Explicit private key file when source folder has more than one candidate."),
    credential_mode: str = typer.Option("copied", "--credential-mode", help="copied or referenced."),
    no_smoke: bool = typer.Option(False, "--no-smoke", help="Skip the local dummy sign/verify smoke check after setup."),
) -> None:
    """Create the local AppData profile and import credentials safely."""

    try:
        if source_folder is None:
            source_folder = Path(str(typer.prompt("External credential folder")).strip())
        rfc = _required_text(rfc, "RFC")
        mode = setup_flow.CredentialMode(credential_mode.strip().lower())
        phrase_value = _prompt_private_key_phrase()
        phrase_ref = setup_flow.default_phrase_reference(profile_id)
        provider = _provider_for_reference(CredentialReference(uri=phrase_ref, kind=CredentialKind.PHRASE))
        result = setup_flow.run_setup(
            profile_id=profile_id,
            rfc=rfc,
            source_folder=source_folder,
            certificate_path=certificate_path,
            private_key_path=private_key_path,
            phrase_value=str(phrase_value),
            provider=provider,
            mode=mode,
        )
        smoke_result = None if no_smoke else setup_flow.run_dummy_smoke(result.profile, provider)
    except (setup_flow.SetupError, CredentialProviderError, ValueError) as exc:
        typer.echo("Setup failed:", err=True)
        errors = exc.errors if isinstance(exc, setup_flow.SetupError) else (str(exc),)
        for error in errors:
            typer.echo(f"- {error}", err=True)
        raise typer.Exit(code=1) from exc

    typer.echo("Setup complete.")
    typer.echo(f"Profile: {result.profile.profile_id} ({setup_flow.redact_rfc(result.profile.rfc)})")
    typer.echo("Credential files were imported into the local AppData profile.")
    typer.echo("The private-key phrase was stored through the secret provider, not in profile.json.")
    if smoke_result is not None:
        typer.echo(f"Smoke: {smoke_result.detail} ({smoke_result.backend})")
    typer.echo("Run: cfdi-vault status")


@app.command("status")
def setup_status(
    profile_id: str = typer.Option("default", "--profile-id", help="Local setup profile id."),
) -> None:
    """Show redacted local setup profile readiness."""

    provider = _setup_provider(profile_id)
    inspection = setup_flow.inspect_profile(profile_id, provider=provider)
    typer.echo(setup_flow.format_profile_status(inspection))
    if inspection.status != setup_flow.LocalProfileStatus.READY:
        raise typer.Exit(code=1)


@app.command("doctor")
def doctor(
    database_url: str | None = typer.Option(None, "--database-url", help="PostgreSQL URL. Defaults to DATABASE_URL."),
    recovery_db: Path = typer.Option(_recovery_db_option(), "--recovery-db", help="SQLite fallback path for local fake mode."),
    storage: Path | None = typer.Option(None, "--storage", help="Storage root. Defaults to CFDI_STORAGE_ROOT or storage/."),
    profile_id: str = typer.Option("default", "--profile-id", help="Local setup profile id to inspect."),
) -> None:
    """Check database, queue, cache, storage, and setup profile readiness."""

    checks = _service(database_url, recovery_db, storage).doctor()
    for check in checks:
        status = "OK" if check.ok else "FAIL"
        typer.echo(f"{status} {check.name}: {check.detail}")
    typer.echo("")
    typer.echo(setup_flow.format_profile_status(setup_flow.inspect_profile(profile_id, provider=_setup_provider(profile_id))))
    if not all(check.ok for check in checks):
        raise typer.Exit(code=1)


@sat_app.command("auth-smoke")
def sat_auth_smoke(
    profile: str = typer.Option("default", "--profile", help="Local setup profile id."),
    manual_real_sat: bool = typer.Option(False, "--manual-real-sat", help="Required human gate for real SAT smoke."),
) -> None:
    """Run guarded SAT authentication smoke preflight before any live auth attempt."""

    _validate_live_smoke_guard(
        profile_id=profile,
        manual_real_sat=manual_real_sat,
        query=None,
        metadata_only=True,
        range_within_limit=True,
    )
    try:
        result = _run_live_auth_smoke(profile)
    except LiveSmokeAdapterUnavailable as exc:
        typer.echo("error=live_adapter_unavailable", err=True)
        raise typer.Exit(code=1) from exc
    _print_live_smoke_result(profile_id=profile, kind="auth", direction="n/a", result=result)


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
    loop: bool = typer.Option(False, "--loop", help="Keep polling the configured queue instead of running once."),
    poll_seconds: float = typer.Option(5.0, "--poll-seconds", min=0.5, help="Polling interval when --loop is used."),
    database_url: str | None = typer.Option(None, "--database-url", help="PostgreSQL URL. Defaults to DATABASE_URL."),
    recovery_db: Path = typer.Option(_recovery_db_option(), "--recovery-db", help="SQLite fallback path for local fake mode."),
    storage: Path | None = typer.Option(None, "--storage", help="Storage root. Defaults to CFDI_STORAGE_ROOT or storage/."),
) -> None:
    """Run the recovery worker shell."""

    worker = RecoveryWorker(_service(database_url, recovery_db, storage))
    if loop:
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


@download_app.command("plan")
def download_plan(
    profile: str = typer.Option(..., "--profile", help="Local setup profile id."),
    from_date: str = typer.Option(..., "--from", help="Start date: YYYY-MM-DD."),
    to_date: str = typer.Option(..., "--to", help="End date: YYYY-MM-DD."),
    kind: str = typer.Option(..., "--kind", help="metadata or cfdi."),
    direction: str = typer.Option(..., "--direction", help="received or issued."),
) -> None:
    """Validate and print a safe fake/offline SAT download plan."""

    query = _build_profile_download_query(
        profile_id=profile,
        from_date=from_date,
        to_date=to_date,
        kind=kind,
        direction=direction,
    )
    _print_download_query(profile_id=profile, query=query, will_submit=False)


@download_app.command("request")
def download_request(
    profile: str = typer.Option(..., "--profile", help="Local setup profile id."),
    from_date: str = typer.Option(..., "--from", help="Start date: YYYY-MM-DD."),
    to_date: str = typer.Option(..., "--to", help="End date: YYYY-MM-DD."),
    kind: str = typer.Option(..., "--kind", help="metadata or cfdi."),
    direction: str = typer.Option(..., "--direction", help="received or issued."),
) -> None:
    """Submit one fake/offline SAT download request without live SAT access."""

    query = _build_profile_download_query(
        profile_id=profile,
        from_date=from_date,
        to_date=to_date,
        kind=kind,
        direction=direction,
    )
    client = FakeSatScenarioClient(FakeSatScenario.REQUEST_ACCEPTED)
    registered = DownloadRequestOrchestrator(requester=client, verifier=client).submit_once(query)
    _print_download_query(profile_id=profile, query=query, will_submit=True)
    typer.echo(f"request_id={registered.request_id}")
    typer.echo(f"action={registered.request_result.action.value}")
    typer.echo(f"sat_code={registered.request_result.sat_code}")
    typer.echo(f"message={registered.request_result.message}")


@download_app.command("sync")
def download_sync(
    profile: str = typer.Option(..., "--profile", help="Local setup profile id."),
    from_date: str = typer.Option(..., "--from", help="Start date: YYYY-MM-DD."),
    to_date: str = typer.Option(..., "--to", help="End date: YYYY-MM-DD."),
    kind: str = typer.Option(..., "--kind", help="metadata or cfdi."),
    direction: str = typer.Option(..., "--direction", help="received or issued."),
) -> None:
    """Run one fake/offline SAT download sync using the setup profile storage root."""

    query, loaded_profile = _build_profile_download_query_with_profile(
        profile_id=profile,
        from_date=from_date,
        to_date=to_date,
        kind=kind,
        direction=direction,
    )
    service = _download_profile_service(loaded_profile)
    try:
        result = service.sync_metadata(query, live=False, enqueue=False)
    finally:
        service.close()

    _print_download_query(profile_id=profile, query=query, will_submit=True)
    typer.echo(f"job_id={result.job_id}")
    typer.echo(f"request_id={result.request_id}")
    typer.echo(f"status={result.status}")
    typer.echo(f"metadata_count={result.metadata_count}")


@download_app.command("live-smoke")
def download_live_smoke(
    profile: str = typer.Option(..., "--profile", help="Local setup profile id."),
    from_date: str = typer.Option(..., "--from", help="Start date: YYYY-MM-DD."),
    to_date: str = typer.Option(..., "--to", help="End date: YYYY-MM-DD."),
    kind: str = typer.Option(..., "--kind", help="metadata only in this version."),
    direction: str = typer.Option(..., "--direction", help="received or issued."),
    manual_real_sat: bool = typer.Option(False, "--manual-real-sat", help="Required human gate for real SAT smoke."),
) -> None:
    """Run a human-gated metadata-only live SAT smoke command."""

    query, _ = _build_profile_download_query_with_profile(
        profile_id=profile,
        from_date=from_date,
        to_date=to_date,
        kind=kind,
        direction=direction,
    )
    _validate_live_smoke_guard(
        profile_id=profile,
        manual_real_sat=manual_real_sat,
        query=query,
        metadata_only=query.request_type == RequestType.METADATA,
        range_within_limit=_is_minimal_live_smoke_range(query),
    )
    try:
        result = _run_live_metadata_smoke(profile, query)
    except LiveSmokeAdapterUnavailable as exc:
        typer.echo("error=live_adapter_unavailable", err=True)
        raise typer.Exit(code=1) from exc
    _print_live_smoke_result(profile_id=profile, kind=query.request_type.value, direction=query.direction.value, result=result)


@download_app.command("status")
def download_status(
    profile: str = typer.Option(..., "--profile", help="Local setup profile id."),
    job_id: str = typer.Option(..., "--job-id", help="Local download job id from download sync."),
) -> None:
    """Read safe persisted fake/offline download status aggregates."""

    loaded_profile = _load_download_profile(profile)
    status = read_download_status(
        loaded_profile.storage_root / "db" / "recovery.sqlite3",
        tenant_id=loaded_profile.profile_id,
        job_id=job_id,
    )
    if status is None:
        typer.echo("mode=fake", err=True)
        typer.echo(f"profile={profile}", err=True)
        typer.echo(f"job_id={job_id}", err=True)
        typer.echo("error=status_not_found", err=True)
        raise typer.Exit(code=1)
    _print_download_status(profile_id=profile, status=status)


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


def _build_profile_download_query(
    *,
    profile_id: str,
    from_date: str,
    to_date: str,
    kind: str,
    direction: str,
) -> DownloadQuery:
    query, _ = _build_profile_download_query_with_profile(
        profile_id=profile_id,
        from_date=from_date,
        to_date=to_date,
        kind=kind,
        direction=direction,
    )
    return query


def _build_profile_download_query_with_profile(
    *,
    profile_id: str,
    from_date: str,
    to_date: str,
    kind: str,
    direction: str,
) -> tuple[DownloadQuery, setup_flow.LocalProfile]:
    request_type = _parse_download_kind(kind)
    download_direction = _parse_download_direction(direction)
    start = _parse_download_date(from_date, label="--from", end_of_day=False)
    end = _parse_download_date(to_date, label="--to", end_of_day=True)
    profile = _load_download_profile(profile_id)

    try:
        period = DateTimePeriod(start=start, end=end)
    except ValueError as exc:
        typer.echo("error=invalid_date_range", err=True)
        typer.echo("detail=--from must be before or equal to --to", err=True)
        raise typer.Exit(code=1) from exc

    query = DownloadQuery(
        tenant_id=profile.profile_id,
        requester_rfc=profile.rfc,
        direction=download_direction,
        request_type=request_type,
        period=period,
    )
    errors = query.validate()
    if errors:
        typer.echo("error=invalid_download_query", err=True)
        for error in errors:
            typer.echo(f"detail={error}", err=True)
        raise typer.Exit(code=1)
    return query, profile


def _download_profile_service(profile: setup_flow.LocalProfile) -> RecoveryService:
    recovery_db = profile.storage_root / "db" / "recovery.sqlite3"
    recovery_db.parent.mkdir(parents=True, exist_ok=True)
    return RecoveryService(sqlite_path=recovery_db, storage_root=profile.storage_root)


def _validate_live_smoke_guard(
    *,
    profile_id: str,
    manual_real_sat: bool,
    query: DownloadQuery | None,
    metadata_only: bool,
    range_within_limit: bool,
) -> None:
    profile = _load_download_profile(profile_id)
    provider = _setup_provider(profile_id)
    inspection = setup_flow.inspect_profile(profile_id, provider=provider)
    doctor_ok = _live_smoke_doctor_ok(profile)
    repo_clean, scanner_passed = _checkout_guard_status()
    interactive = _terminal_is_interactive()
    confirmed = False
    if manual_real_sat and interactive:
        confirmed = _confirm_live_smoke()

    try:
        validate_live_sat_guard(
            LiveSatGuardInput(
                manual_real_sat=manual_real_sat,
                terminal_interactive=interactive,
                confirmation_verified=confirmed,
                profile_ready=inspection.status == setup_flow.LocalProfileStatus.READY,
                credentials_ready=all(
                    state == "loaded"
                    for state in (
                        inspection.certificate_state,
                        inspection.private_key_state,
                        inspection.phrase_state,
                        inspection.storage_state,
                    )
                ),
                doctor_ok=doctor_ok,
                scanner_passed=scanner_passed,
                repo_clean=repo_clean,
                metadata_only=metadata_only,
                range_within_limit=range_within_limit,
                environ=os.environ,
            )
        )
    except LiveSatGuardError as exc:
        typer.echo("error=live_sat_guard_denied", err=True)
        for reason in exc.reasons:
            typer.echo(f"reason={reason}", err=True)
        raise typer.Exit(code=1) from exc

    typer.echo("warning=live_sat_smoke_guards_passed", err=True)
    typer.echo("sat_real_execution=adapter_pending", err=True)
    if query is not None:
        _print_download_query(profile_id=profile_id, query=query, will_submit=False, mode="live-smoke")


def _live_smoke_doctor_ok(profile: setup_flow.LocalProfile) -> bool:
    service = _download_profile_service(profile)
    try:
        return all(check.ok for check in service.doctor())
    finally:
        service.close()


def _checkout_guard_status() -> tuple[bool, bool]:
    repo_root = _find_checkout_root(Path.cwd())
    if repo_root is None:
        return False, False

    status = subprocess.run(
        ["git", "status", "--short"],
        cwd=repo_root,
        capture_output=True,
        text=True,
        check=False,
    )
    repo_clean = status.returncode == 0 and not status.stdout.strip()
    scanner = repo_root / "scripts" / "scan_sensitive_fixtures.py"
    if not scanner.is_file():
        return repo_clean, False
    scanner_result = subprocess.run(
        [sys.executable, str(scanner), "--root", str(repo_root)],
        cwd=repo_root,
        capture_output=True,
        text=True,
        check=False,
    )
    return repo_clean, scanner_result.returncode == 0


def _find_checkout_root(start: Path) -> Path | None:
    current = start.resolve()
    for candidate in (current, *current.parents):
        if candidate.joinpath(".git").exists():
            return candidate
    return None


def _terminal_is_interactive() -> bool:
    return sys.stdin.isatty() and sys.stdout.isatty()


def _confirm_live_smoke() -> bool:
    typer.echo("WARNING: this command is gated for a real SAT metadata smoke.")
    typer.echo("Do not continue unless #50 has explicit approval for this one manual run.")
    typed = str(typer.prompt(f'Type "{LIVE_SMOKE_CONFIRMATION}" to continue')).strip()
    return typed == LIVE_SMOKE_CONFIRMATION


def _is_minimal_live_smoke_range(query: DownloadQuery) -> bool:
    return query.period is not None and query.period.start.date() == query.period.end.date()


def _run_live_auth_smoke(profile_id: str) -> LiveSmokeCliResult:
    raise LiveSmokeAdapterUnavailable(f"live SAT auth smoke adapter is not wired for profile {profile_id!r}")


def _run_live_metadata_smoke(profile_id: str, query: DownloadQuery) -> LiveSmokeCliResult:
    raise LiveSmokeAdapterUnavailable(
        f"live SAT metadata smoke adapter is not wired for profile {profile_id!r} and criteria {query.criteria_hash()}"
    )


def _print_live_smoke_result(
    *,
    profile_id: str,
    kind: str,
    direction: str,
    result: LiveSmokeCliResult,
) -> None:
    typer.echo("mode=live-smoke")
    typer.echo(f"profile={profile_id}")
    typer.echo(f"kind={kind}")
    typer.echo(f"direction={direction}")
    typer.echo(f"result={result.result}")
    typer.echo(f"auth={result.auth}")
    typer.echo(f"request={result.request}")
    typer.echo(f"verification={result.verification}")
    typer.echo("xml_downloaded=no")
    typer.echo("zip_downloaded=no")
    typer.echo("recurrent_automation=no")


def _load_download_profile(profile_id: str) -> setup_flow.LocalProfile:
    try:
        return setup_flow.load_profile(profile_id)
    except setup_flow.SetupError as exc:
        reason = "profile_not_configured" if _has_profile_not_configured_error(exc) else "profile_invalid"
        typer.echo(f"profile={profile_id}", err=True)
        typer.echo(f"error={reason}", err=True)
        raise typer.Exit(code=1) from exc


def _has_profile_not_configured_error(exc: setup_flow.SetupError) -> bool:
    return any(error.startswith("profile is not configured:") for error in exc.errors)


def _parse_download_kind(value: str) -> RequestType:
    normalized = value.strip().lower()
    try:
        return RequestType(normalized)
    except ValueError as exc:
        raise typer.BadParameter("kind must be metadata or cfdi") from exc


def _parse_download_direction(value: str) -> DownloadDirection:
    normalized = value.strip().lower()
    if normalized == DownloadDirection.RECEIVED.value:
        return DownloadDirection.RECEIVED
    if normalized == DownloadDirection.ISSUED.value:
        return DownloadDirection.ISSUED
    raise typer.BadParameter("direction must be received or issued")


def _parse_download_date(value: str, *, label: str, end_of_day: bool) -> datetime:
    try:
        return _parse_cli_datetime(value, end_of_day=end_of_day)
    except ValueError as exc:
        raise typer.BadParameter(f"{label} must be a valid YYYY-MM-DD date") from exc


def _print_download_query(*, profile_id: str, query: DownloadQuery, will_submit: bool, mode: str = "fake") -> None:
    typer.echo(f"mode={mode}")
    typer.echo(f"profile={profile_id}")
    typer.echo(f"kind={query.request_type.value}")
    typer.echo(f"direction={query.direction.value}")
    if query.period is not None:
        typer.echo(f"from={query.period.start.isoformat()}")
        typer.echo(f"to={query.period.end.isoformat()}")
    typer.echo(f"will_submit={str(will_submit).lower()}")
    typer.echo(f"criteria_hash={query.criteria_hash()}")


def _print_download_status(*, profile_id: str, status: DownloadStatus) -> None:
    typer.echo("mode=fake")
    typer.echo(f"profile={profile_id}")
    typer.echo(f"job_id={status.job_id}")
    typer.echo(f"request_id={status.request_id}")
    typer.echo(f"status={status.status}")
    typer.echo(f"sat_state={status.sat_state}")
    typer.echo(f"kind={status.kind}")
    typer.echo(f"direction={status.direction}")
    typer.echo(f"criteria_hash={status.criteria_hash}")
    typer.echo(f"metadata_count={status.metadata_count}")
    typer.echo(f"package_count={status.package_count}")
    typer.echo(f"downloaded_package_count={status.downloaded_package_count}")
    typer.echo(f"xml_count={status.xml_count}")


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


def _credential_reference(reference_uri: str, raw_kind: str) -> CredentialReference:
    normalized = raw_kind.strip().lower().replace("-", "_")
    try:
        kind = CredentialKind(normalized)
    except ValueError as exc:
        raise typer.BadParameter("kind must be certificate, private-key, phrase, or generic") from exc
    return CredentialReference(uri=reference_uri, kind=kind)


def _provider_for_reference(reference: CredentialReference) -> object:
    if reference.provider_scheme == WindowsCredentialManagerSecretProvider.provider_scheme:
        return WindowsCredentialManagerSecretProvider()
    if reference.provider_scheme == DummySecretProvider.provider_scheme:
        return DummySecretProvider()
    raise typer.BadParameter(f"unsupported credential reference scheme: {reference.provider_scheme}")


def _setup_provider(profile_id: str) -> object:
    phrase_ref = setup_flow.default_phrase_reference(profile_id)
    return _provider_for_reference(CredentialReference(uri=phrase_ref, kind=CredentialKind.PHRASE))


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
