"""Typer CLI for CFDI Vault MX."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, replace
from datetime import date, datetime, time, timezone
import os
from pathlib import Path
import re
import subprocess
import sys
from time import perf_counter

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
from cfdi_vault.metadata_parser import parse_metadata_bytes
from cfdi_vault.package_processor import PackageProcessingError, ProcessedPackage, process_sat_package
from cfdi_vault.secrets import CredentialKind, CredentialProviderError, CredentialReference, DummySecretProvider
from cfdi_vault.service import ImportBatchResult, ImportRecord, SummaryRow, VaultService
from cfdi_vault.sat_async_verify import VerifyBackoffPolicy, VerifyDueReport, run_verify_due
from cfdi_vault.sat_backfill import BackfillPlan, build_backfill_plan
from cfdi_vault.sat_orchestration import DownloadRequestOrchestrator
from cfdi_vault.sat_simulator import FakeSatScenario, FakeSatScenarioClient
from cfdi_vault.sat_live_smoke import (
    DIAGNOSTIC_STAGES,
    SatLiveMetadataSmokeAdapter,
    SatLiveSmokeError,
    _build_auth_envelope,
    load_sat_efirma_material,
)
from cfdi_vault.sat_download_live_gate import (
    DEFAULT_DOWNLOAD_CONNECT_TIMEOUT_SECONDS,
    DEFAULT_DOWNLOAD_READ_TIMEOUT_SECONDS,
    MAX_DOWNLOAD_CONNECT_TIMEOUT_SECONDS,
    MAX_DOWNLOAD_READ_TIMEOUT_SECONDS,
    DownloadLiveGatePreflight,
    DownloadOracleParityResult,
    DownloadWsdlCheckResult,
    build_download_live_gate_preflight,
    check_download_wsdl_endpoint,
    resolve_download_gate_timeout_config,
    run_download_oracle_parity,
)
from cfdi_vault.sat_live_request_state import (
    LiveMetadataRequestRecord,
    LiveMetadataRequestSummary,
    LiveRequestStateError,
    PACKAGE_DOWNLOADED,
    PACKAGE_READY,
    VERIFY_SCHEDULED,
    list_live_metadata_requests,
    load_live_metadata_request,
    persist_live_metadata_request,
    redact_package_ref,
    summarize_live_metadata_requests,
    upsert_live_metadata_request,
)
from cfdi_vault.sat_auth_envelope_lint import AuthEnvelopeLintResult, build_dummy_auth_envelope, lint_auth_envelope
from cfdi_vault.sat_auth_contract import AuthWsdlContract, fetch_auth_wsdl_contract
from cfdi_vault.sat_auth_endpoints import resolve_auth_endpoint
from cfdi_vault.sat_auth_matrix_probe import SatAuthMatrixProbeResult, run_sat_auth_matrix_probe
from cfdi_vault.sat_auth_oracle import (
    AuthEnvelopeFingerprint,
    AuthOracleDiffResult,
    PHP_CFDI_BUILDER_SOURCE_DISABLED_IN_CI,
    PhpCfdiOracleFingerprint,
    diff_auth_oracle,
    fingerprint_auth_envelope,
    fingerprint_phpcfdi_oracle,
)
from cfdi_vault.sat_auth_post_probe import SatAuthPostProbeResult, run_sat_auth_post_probe
from cfdi_vault.sat_contract import SatDownloadResult, SatOutcomeAction, SatVerificationResult
from cfdi_vault.sat_package_download_offline import evaluate_package_download_gate, inspect_package_zip_bytes
from cfdi_vault.sat_transport_probe import SatProbeResult, run_sat_transport_probe
from cfdi_vault.sat_verify_post_probe import SatVerifyPostProbeResult, run_sat_verify_post_probe
from cfdi_vault.sat_verify_live_gate import (
    DEFAULT_VERIFY_CONNECT_TIMEOUT_SECONDS,
    DEFAULT_VERIFY_READ_TIMEOUT_SECONDS,
    MAX_VERIFY_CONNECT_TIMEOUT_SECONDS,
    MAX_VERIFY_READ_TIMEOUT_SECONDS,
    VerifyLiveGatePreflight,
    VerifyOracleParityResult,
    VerifyWsdlCheckResult,
    build_verify_live_gate_preflight,
    check_verify_wsdl_endpoint,
    resolve_verify_gate_timeout_config,
    run_verify_oracle_parity,
)
from cfdi_vault.live_permit import (
    BACKFILL_SUBMIT_SCOPE,
    LivePermitError,
    LivePermitRequest,
    MAX_BACKFILL_RANGE_DAYS,
    METADATA_LIVE_SMOKE_SCOPE,
    PACKAGE_DOWNLOAD_SCOPE,
    auth_live_smoke_permit_expectation,
    create_live_execution_permit,
    load_live_execution_permit,
    permit_expectation_from_query,
    transport_probe_permit_expectation,
    validate_and_consume_live_permit,
)
from cfdi_vault.sat_auth_constants import AUTH_ENVELOPE_VARIANT_SECURITY_ONLY, AUTH_ENVELOPE_VARIANTS, DEFAULT_AUTH_ENVELOPE_VARIANT
from cfdi_vault.sat_transport import (
    GuardedSoapHttpTransport,
    LiveSatGuardError,
    LiveSatGuardInput,
    validate_live_sat_guard,
)
from cfdi_vault.worker import RecoveryWorker
from cfdi_vault.storage import LocalStorage
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
backfill_app = typer.Typer(help="Plan safe SAT metadata historical backfills.", no_args_is_help=True)
custody_app = typer.Typer(help="Manage local secret references without printing values.", no_args_is_help=True)
live_app = typer.Typer(help="Create one-time local live execution permits.", no_args_is_help=True)

app.add_typer(config_app, name="config")
app.add_typer(queue_app, name="queue")
app.add_typer(worker_app, name="worker")
app.add_typer(sync_app, name="sync")
app.add_typer(download_app, name="download")
app.add_typer(sat_app, name="sat")
app.add_typer(custody_app, name="secret")
app.add_typer(live_app, name="live")
sat_app.add_typer(backfill_app, name="backfill")


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
LIVE_TRANSPORT_PROBE_CONFIRMATION = "SAT REAL TRANSPORT PROBE"


@dataclass(frozen=True)
class LiveSmokeCliResult:
    """Redacted CLI result for injected live smoke adapters."""

    result: str
    auth: str = "not_run"
    request: str = "not_run"
    verification: str = "not_run"
    operation: str = ""
    request_ref: str = ""
    id_solicitud_redacted: str = ""
    sat_state: str = ""
    package_count: int = 0
    request_body_bytes_len: int | None = None
    envelope_sha256: str | None = None
    signed_reference_count: int | None = None
    duration_ms: int | None = None


@dataclass(frozen=True)
class PackageDownloadCliResult:
    """Redacted one-package download result for CLI output."""

    request_ref: str
    package_ref: str
    request_status_before: str
    download_result: str
    sat_code: str
    message_redacted: str
    package_size_bytes: int
    zip_valid: bool
    txt_files: int
    metadata_accepted_count: int
    metadata_rejected_count: int
    status_after: str


@dataclass(frozen=True)
class DownloadLiveGateCliResult:
    request_ref: str
    package_ref: str
    verify_executed: bool
    download_executed: bool
    estado_solicitud: str
    codigo_estado: str
    numero_cfdis: int | None
    ids_paquetes_count: int
    package_received: bool
    decoded_bytes: int
    zip_valid: bool
    zip_entries_count: int
    zip_persisted: bool = False


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


permit_app = typer.Typer(help="Create one-time local live execution permits.", no_args_is_help=True)
live_app.add_typer(permit_app, name="permit")


@permit_app.command("create")
def live_permit_create(
    scope: str = typer.Option(..., "--scope", help="transport_probe, auth_post_probe, verify_post_probe, auth_matrix_probe, auth_live_smoke, metadata_live_smoke, metadata_backfill_submit, or package_download_smoke."),
    profile: str = typer.Option(..., "--profile", help="Local setup profile id."),
    kind: str = typer.Option(..., "--kind", help="metadata only."),
    direction: str = typer.Option(..., "--direction", help="received or issued."),
    from_date: str = typer.Option(..., "--from", help="YYYY-MM-DD."),
    to_date: str = typer.Option(..., "--to", help="YYYY-MM-DD."),
    expires_minutes: int = typer.Option(15, "--expires-minutes", min=1, max=15),
    reason: str = typer.Option(..., "--reason", help="Auditable local reason."),
    auth_envelope_variant: str | None = typer.Option(None, "--auth-envelope-variant", help="auth_live_smoke only: security_only, action_before_security, or security_before_action."),
    wcf_action_header_enabled: bool | None = typer.Option(None, "--wcf-action-header-enabled/--no-wcf-action-header-enabled", help="auth_live_smoke only; defaults to false for security_only and true for Action variants."),
) -> None:
    """Create a one-time local permit outside the repository for one live operation."""

    try:
        permit = create_live_execution_permit(
            LivePermitRequest(
                scope=scope,
                profile_id=profile,
                kind=kind,
                direction=direction,
                date_from=from_date,
                date_to=to_date,
                expires_minutes=expires_minutes,
                reason=reason,
                auth_envelope_variant=auth_envelope_variant if scope == "auth_live_smoke" else None,
                wcf_action_header_enabled=wcf_action_header_enabled if scope == "auth_live_smoke" else None,
            )
        )
    except LivePermitError as exc:
        typer.echo("error=live_permit_denied", err=True)
        typer.echo(f"reason={exc.reason}", err=True)
        raise typer.Exit(code=1) from exc
    typer.echo("mode=live-permit")
    typer.echo(f"permit_id={permit.permit_id}")
    typer.echo(f"scope={scope}")
    typer.echo(f"profile={profile}")
    typer.echo(f"kind={kind}")
    typer.echo(f"direction={direction}")
    typer.echo(f"date_from={from_date}")
    typer.echo(f"date_to={to_date}")
    typer.echo(f"max_range_days={permit.max_range_days}")
    typer.echo("max_attempts=1")
    typer.echo(f"expires_at={permit.expires_at.isoformat().replace('+00:00', 'Z')}")
    typer.echo("permit_storage=appdata-local")
    typer.echo("consumed=false")
    typer.echo("redaction_required=true")
    if permit.auth_envelope_variant is not None:
        typer.echo(f"auth_envelope_variant={permit.auth_envelope_variant}")
    if permit.wcf_action_header_enabled is not None:
        typer.echo(f"wcf_action_header_enabled={'true' if permit.wcf_action_header_enabled else 'false'}")


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
    permit: str | None = typer.Option(None, "--permit", help="One-time local auth_live_smoke permit id."),
) -> None:
    """Run guarded SAT authentication smoke preflight before any live auth attempt."""

    live_permit_verified = _validate_live_smoke_guard(
        profile_id=profile,
        manual_real_sat=manual_real_sat,
        query=None,
        metadata_only=True,
        range_within_limit=True,
        mode="auth-smoke",
        permit_ref=permit,
        permit_scope="auth_live_smoke",
    )
    auth_envelope_variant = DEFAULT_AUTH_ENVELOPE_VARIANT
    wcf_action_header_enabled = DEFAULT_AUTH_ENVELOPE_VARIANT != AUTH_ENVELOPE_VARIANT_SECURITY_ONLY
    if permit is not None:
        consumed_permit = load_live_execution_permit(permit, env=os.environ)
        auth_envelope_variant = consumed_permit.auth_envelope_variant or DEFAULT_AUTH_ENVELOPE_VARIANT
        wcf_action_header_enabled = consumed_permit.wcf_action_header_enabled is True
    try:
        result = _run_live_auth_smoke(
            profile,
            live_permit_verified=live_permit_verified,
            auth_envelope_variant=auth_envelope_variant,
            wcf_action_header_enabled=wcf_action_header_enabled,
        )
    except LiveSmokeAdapterUnavailable as exc:
        typer.echo("error=live_adapter_unavailable", err=True)
        raise typer.Exit(code=1) from exc
    except SatLiveSmokeError as exc:
        _print_live_adapter_error(exc)
        raise typer.Exit(code=1) from exc
    _print_live_smoke_result(profile_id=profile, kind="auth", direction="n/a", result=result)


@sat_app.command("metadata-request-smoke")
def sat_metadata_request_smoke(
    profile: str = typer.Option(..., "--profile", help="Local setup profile id."),
    from_date: str = typer.Option(..., "--from", help="Start date: YYYY-MM-DD."),
    to_date: str = typer.Option(..., "--to", help="End date: YYYY-MM-DD."),
    direction: str = typer.Option("received", "--direction", help="received or issued."),
    manual_real_sat: bool = typer.Option(False, "--manual-real-sat", help="Required human gate for real SAT request smoke."),
    permit: str | None = typer.Option(None, "--permit", help="One-time local metadata_live_smoke permit id."),
) -> None:
    """Run guarded auth + SAT v1.5 metadata request only; no verify or package download."""

    query, _ = _build_profile_download_query_with_profile(
        profile_id=profile,
        from_date=from_date,
        to_date=to_date,
        kind=RequestType.METADATA.value,
        direction=direction,
    )
    permit_verified = _validate_live_smoke_guard(
        profile_id=profile,
        manual_real_sat=manual_real_sat,
        query=query,
        metadata_only=True,
        range_within_limit=_is_minimal_live_smoke_range(query),
        mode="metadata-request-smoke",
        permit_ref=permit,
    )
    try:
        result = _run_live_metadata_request_smoke(profile, query, live_permit_verified=permit_verified, permit_ref=permit)
    except LiveRequestStateError as exc:
        typer.echo("error=request_state_persist_failed", err=True)
        typer.echo(f"reason={exc.reason}", err=True)
        raise typer.Exit(code=1) from exc
    except LiveSmokeAdapterUnavailable as exc:
        typer.echo("error=live_adapter_unavailable", err=True)
        raise typer.Exit(code=1) from exc
    except SatLiveSmokeError as exc:
        _print_live_adapter_error(exc)
        raise typer.Exit(code=1) from exc
    _print_live_smoke_result(profile_id=profile, kind=query.request_type.value, direction=query.direction.value, result=result)


@sat_app.command("metadata-request-state")
def sat_metadata_request_state(
    profile: str = typer.Option("default", "--profile", help="Local setup profile id."),
) -> None:
    """List redacted locally persisted live metadata requests pending verify."""

    local_profile = _load_download_profile(profile)
    try:
        records = list_live_metadata_requests(local_profile.storage_root, pending_only=True)
    except LiveRequestStateError as exc:
        typer.echo("error=request_state_unavailable", err=True)
        typer.echo(f"reason={exc.reason}", err=True)
        raise typer.Exit(code=1) from exc
    _print_live_metadata_request_state(profile_id=profile, records=records)


@backfill_app.command("plan")
def sat_backfill_plan(
    profile: str = typer.Option("default", "--profile", help="Local setup profile id."),
    from_date: str = typer.Option(..., "--from", help="Start date: YYYY-MM-DD."),
    to_date: str = typer.Option(..., "--to", help="End date: YYYY-MM-DD."),
    direction: str = typer.Option("received", "--direction", help="received or issued."),
    kind: str = typer.Option("metadata", "--kind", help="metadata only in this version."),
    window: str = typer.Option("weekly", "--window", help="weekly or daily."),
) -> None:
    """Plan historical metadata windows without calling SAT."""

    local_profile = _load_download_profile(profile)
    request_type = _parse_download_kind(kind)
    download_direction = _parse_download_direction(direction)
    try:
        plan = build_backfill_plan(
            storage_root=local_profile.storage_root,
            profile_id=local_profile.profile_id,
            requester_rfc=local_profile.rfc,
            start_date=_parse_backfill_date(from_date, label="--from"),
            end_date=_parse_backfill_date(to_date, label="--to"),
            direction=download_direction,
            kind=request_type,
            window=window,
        )
    except LiveRequestStateError as exc:
        typer.echo("error=request_state_unavailable", err=True)
        typer.echo(f"reason={exc.reason}", err=True)
        raise typer.Exit(code=1) from exc
    except ValueError as exc:
        typer.echo("error=invalid_backfill_plan", err=True)
        typer.echo(f"reason={exc}", err=True)
        raise typer.Exit(code=1) from exc
    _print_backfill_plan(plan)


@backfill_app.command("submit")
def sat_backfill_submit(
    profile: str = typer.Option("default", "--profile", help="Local setup profile id."),
    from_date: str = typer.Option(..., "--from", help="Start date: YYYY-MM-DD."),
    to_date: str = typer.Option(..., "--to", help="End date: YYYY-MM-DD."),
    direction: str = typer.Option("received", "--direction", help="received or issued."),
    kind: str = typer.Option("metadata", "--kind", help="metadata only in this version."),
    window: str = typer.Option("weekly", "--window", help="weekly or daily."),
    limit_windows: int | None = typer.Option(None, "--limit-windows", min=1, help="Required; first live version allows exactly 1."),
    manual_real_sat: bool = typer.Option(False, "--manual-real-sat", help="Required human gate for real SAT backfill submit."),
    permit: str | None = typer.Option(None, "--permit", help="One-time local metadata_backfill_submit permit id."),
) -> None:
    """Submit one planned historical metadata request; no verify or package download."""

    if not manual_real_sat:
        _deny_backfill_submit("manual-real-sat-required")
    if permit is None:
        _deny_backfill_submit("permit-required-for-live")
    if limit_windows is None:
        _deny_backfill_submit("limit-windows-required")
    if limit_windows != 1:
        _deny_backfill_submit("limit-one-required")
    local_profile = _load_download_profile(profile)
    try:
        plan = build_backfill_plan(
            storage_root=local_profile.storage_root,
            profile_id=local_profile.profile_id,
            requester_rfc=local_profile.rfc,
            start_date=_parse_backfill_date(from_date, label="--from"),
            end_date=_parse_backfill_date(to_date, label="--to"),
            direction=_parse_download_direction(direction),
            kind=_parse_download_kind(kind),
            window=window,
        )
    except LiveRequestStateError as exc:
        typer.echo("error=request_state_unavailable", err=True)
        typer.echo(f"reason={exc.reason}", err=True)
        raise typer.Exit(code=1) from exc
    except ValueError as exc:
        typer.echo("error=invalid_backfill_submit", err=True)
        typer.echo(f"reason={exc}", err=True)
        raise typer.Exit(code=1) from exc
    pending = tuple(window_plan for window_plan in plan.windows if not window_plan.existing_request_ref)
    selected = pending[:limit_windows]
    if not selected:
        _print_backfill_submit_result(plan=plan, selected=(), result=None)
        return
    selected_window = selected[0]
    permit_verified = _validate_live_smoke_guard(
        profile_id=profile,
        manual_real_sat=manual_real_sat,
        query=selected_window.query,
        metadata_only=True,
        range_within_limit=_is_backfill_submit_range(selected_window.query),
        mode="backfill-submit",
        permit_ref=permit,
        permit_scope=BACKFILL_SUBMIT_SCOPE,
    )
    try:
        result = _run_live_metadata_request_smoke(
            profile,
            selected_window.query,
            live_permit_verified=permit_verified,
            permit_ref=permit,
            source_command="sat backfill submit",
            status=VERIFY_SCHEDULED,
            max_range_days=MAX_BACKFILL_RANGE_DAYS,
        )
    except LiveRequestStateError as exc:
        typer.echo("error=request_state_persist_failed", err=True)
        typer.echo(f"reason={exc.reason}", err=True)
        raise typer.Exit(code=1) from exc
    except LiveSmokeAdapterUnavailable as exc:
        typer.echo("error=live_adapter_unavailable", err=True)
        raise typer.Exit(code=1) from exc
    except SatLiveSmokeError as exc:
        _print_live_adapter_error(exc)
        raise typer.Exit(code=1) from exc
    _print_backfill_submit_result(plan=plan, selected=selected, result=result)




@sat_app.command("verify-due")
def sat_verify_due(
    profile: str = typer.Option("default", "--profile", help="Local setup profile id."),
    limit: int = typer.Option(1, "--limit", min=1, max=50, help="Maximum due requests to verify once."),
    dry_run: bool = typer.Option(False, "--dry-run", help="List due verifications without calling the verifier."),
    request_ref: str | None = typer.Option(None, "--request-ref", help="Optional local request reference to verify through the scheduler."),
    manual_real_sat: bool = typer.Option(False, "--manual-real-sat", help="Required human gate for live SAT scheduler verify."),
    permit: str | None = typer.Option(None, "--permit", help="One-time local metadata_live_smoke permit id for live scheduler verify."),
) -> None:
    """Verify due SAT metadata requests once; live runs require an explicit permit."""

    local_profile = _load_download_profile(profile)
    live_requested = manual_real_sat or permit is not None
    if live_requested and dry_run:
        typer.echo("error=live_scheduler_verify_denied", err=True)
        typer.echo("reason=dry-run-cannot-use-live-gate", err=True)
        raise typer.Exit(code=1)
    if live_requested:
        if not manual_real_sat:
            typer.echo("error=live_scheduler_verify_denied", err=True)
            typer.echo("reason=manual-real-sat-required", err=True)
            raise typer.Exit(code=1)
        if permit is None:
            typer.echo("error=live_scheduler_verify_denied", err=True)
            typer.echo("reason=permit-required-for-live", err=True)
            raise typer.Exit(code=1)
        if limit != 1:
            typer.echo("error=live_scheduler_verify_denied", err=True)
            typer.echo("reason=limit-one-required", err=True)
            raise typer.Exit(code=1)
        if not request_ref:
            typer.echo("error=live_scheduler_verify_denied", err=True)
            typer.echo("reason=request-ref-required-for-live", err=True)
            raise typer.Exit(code=1)
        try:
            preflight = run_verify_due(
                storage_root=local_profile.storage_root,
                profile_id=profile,
                verifier=FakeSatScenarioClient(FakeSatScenario.VERIFY_IN_PROCESS),
                limit=1,
                dry_run=True,
                request_ref=request_ref,
                policy=VerifyBackoffPolicy(),
            )
            record = load_live_metadata_request(local_profile.storage_root, request_ref)
        except LiveRequestStateError as exc:
            typer.echo("error=request_state_unavailable", err=True)
            typer.echo(f"reason={exc.reason}", err=True)
            raise typer.Exit(code=1) from exc
        if preflight.selected_count != 1:
            typer.echo("error=live_scheduler_verify_denied", err=True)
            typer.echo("reason=request-not-due", err=True)
            _print_verify_due_report(preflight)
            raise typer.Exit(code=1)
        query = _query_from_live_request_record(local_profile.rfc, record)
        permit_verified = _validate_live_smoke_guard(
            profile_id=profile,
            manual_real_sat=manual_real_sat,
            query=query,
            metadata_only=True,
            range_within_limit=_is_backfill_submit_range(query),
            mode="verify-due",
            permit_ref=permit,
            permit_scope=METADATA_LIVE_SMOKE_SCOPE,
        )
        verifier = _live_verify_due_verifier(profile, live_permit_verified=permit_verified)
    else:
        verifier = FakeSatScenarioClient(FakeSatScenario.VERIFY_IN_PROCESS)
    try:
        report = run_verify_due(
            storage_root=local_profile.storage_root,
            profile_id=profile,
            verifier=verifier,
            limit=limit,
            dry_run=dry_run,
            request_ref=request_ref,
            policy=VerifyBackoffPolicy(),
        )
    except LiveRequestStateError as exc:
        typer.echo("error=request_state_unavailable", err=True)
        typer.echo(f"reason={exc.reason}", err=True)
        raise typer.Exit(code=1) from exc
    _print_verify_due_report(report, sat_real_execution="adapter_enabled" if live_requested else "no")


@sat_app.command("package-download-smoke")
def sat_package_download_smoke(
    profile: str = typer.Option("default", "--profile", help="Local setup profile id."),
    request_ref: str = typer.Option(..., "--request-ref", help="Local request reference with PACKAGE_READY state."),
    package_ref: str = typer.Option(..., "--package-ref", help="Redacted package reference from scheduler state."),
    manual_real_sat: bool = typer.Option(False, "--manual-real-sat", help="Required human gate for real SAT package download."),
    permit: str | None = typer.Option(None, "--permit", help="One-time local package_download_smoke permit id."),
) -> None:
    """Download exactly one metadata package and extract TXT only."""

    if not manual_real_sat:
        _deny_package_download("manual-real-sat-required")
    if permit is None:
        _deny_package_download("permit-required-for-live")
    local_profile = _load_download_profile(profile)
    try:
        record = load_live_metadata_request(local_profile.storage_root, request_ref)
    except LiveRequestStateError as exc:
        typer.echo("error=request_state_not_found", err=True)
        typer.echo(f"reason={exc.reason}", err=True)
        raise typer.Exit(code=1) from exc
    if record.profile_id != profile:
        _deny_package_download("request-state-profile-mismatch")
    if record.status != PACKAGE_READY:
        _deny_package_download("request-not-package-ready")
    package_id = _resolve_package_id(record, package_ref)
    query = _query_from_live_request_record(local_profile.rfc, record)
    permit_verified = _validate_live_smoke_guard(
        profile_id=profile,
        manual_real_sat=manual_real_sat,
        query=query,
        metadata_only=True,
        range_within_limit=_is_backfill_submit_range(query),
        mode="package-download-smoke",
        permit_ref=permit,
        permit_scope=PACKAGE_DOWNLOAD_SCOPE,
    )
    try:
        result = _run_live_package_download_smoke(
            profile,
            record,
            package_id,
            package_ref=package_ref,
            live_permit_verified=permit_verified,
        )
    except PackageProcessingError as exc:
        typer.echo("error=package_process_failed", err=True)
        typer.echo(f"reason={_safe_error_reason(str(exc))}", err=True)
        raise typer.Exit(code=1) from exc
    except (UnicodeDecodeError, ValueError) as exc:
        typer.echo("error=metadata_parse_failed", err=True)
        typer.echo(f"reason={_safe_error_reason(str(exc))}", err=True)
        raise typer.Exit(code=1) from exc
    except SatLiveSmokeError as exc:
        _print_live_adapter_error(exc)
        raise typer.Exit(code=1) from exc
    _print_package_download_result(profile_id=profile, result=result)


@sat_app.command("metadata-verify-smoke")
def sat_metadata_verify_smoke(
    profile: str = typer.Option(..., "--profile", help="Local setup profile id."),
    request_ref: str = typer.Option(..., "--request-ref", help="Local redacted request reference from metadata-request-state."),
    manual_real_sat: bool = typer.Option(False, "--manual-real-sat", help="Required human gate for real SAT verify smoke."),
    permit: str | None = typer.Option(None, "--permit", help="One-time local metadata_live_smoke permit id."),
) -> None:
    """Verify one stored metadata request only; no new request or package download."""

    local_profile = _load_download_profile(profile)
    try:
        record = load_live_metadata_request(local_profile.storage_root, request_ref)
    except LiveRequestStateError as exc:
        typer.echo("error=request_state_not_found", err=True)
        typer.echo(f"reason={exc.reason}", err=True)
        raise typer.Exit(code=1) from exc
    if record.profile_id != profile:
        typer.echo("error=request_state_profile_mismatch", err=True)
        typer.echo("reason=request-state-profile-mismatch", err=True)
        raise typer.Exit(code=1)
    query = _query_from_live_request_record(local_profile.rfc, record)
    permit_verified = _validate_live_smoke_guard(
        profile_id=profile,
        manual_real_sat=manual_real_sat,
        query=query,
        metadata_only=True,
        range_within_limit=_is_minimal_live_smoke_range(query),
        mode="metadata-verify-smoke",
        permit_ref=permit,
    )
    try:
        result = _run_live_metadata_verify_smoke(profile, record.id_solicitud, live_permit_verified=permit_verified)
    except LiveSmokeAdapterUnavailable as exc:
        typer.echo("error=live_adapter_unavailable", err=True)
        raise typer.Exit(code=1) from exc
    except SatLiveSmokeError as exc:
        _print_live_adapter_error(exc)
        raise typer.Exit(code=1) from exc
    _print_live_smoke_result(profile_id=profile, kind=query.request_type.value, direction=query.direction.value, result=result)


@sat_app.command("verify-live-gate")
def sat_verify_live_gate(
    profile: str = typer.Option("default", "--profile", help="Local setup profile id."),
    request_ref: str | None = typer.Option(None, "--request-ref", help="Local redacted request reference from metadata-request-state."),
    manual_real_sat: bool = typer.Option(False, "--manual-real-sat", help="Required human gate for real SAT verify."),
    permit: str | None = typer.Option(None, "--permit", help="One-time local metadata_live_smoke permit id."),
    connect_timeout_seconds: float | None = typer.Option(
        None,
        "--connect-timeout-seconds",
        min=1.0,
        max=MAX_VERIFY_CONNECT_TIMEOUT_SECONDS,
        help=f"Gate-only connect timeout in seconds. Defaults to {DEFAULT_VERIFY_CONNECT_TIMEOUT_SECONDS:g}.",
    ),
    read_timeout_seconds: float | None = typer.Option(
        None,
        "--read-timeout-seconds",
        min=1.0,
        max=MAX_VERIFY_READ_TIMEOUT_SECONDS,
        help=f"Gate-only verify read timeout in seconds. Defaults to {DEFAULT_VERIFY_READ_TIMEOUT_SECONDS:g}; maximum {MAX_VERIFY_READ_TIMEOUT_SECONDS:g}.",
    ),
) -> None:
    """Run the controlled v1.5 production-signed verify live gate only when preflight passes."""

    local_profile = _load_download_profile_or_none(profile)
    provider = _setup_provider(profile) if local_profile is not None else None
    record = _load_request_record_or_none(local_profile, request_ref) if local_profile is not None and request_ref else None
    timeout_config = resolve_verify_gate_timeout_config(
        connect_timeout_seconds=connect_timeout_seconds,
        read_timeout_seconds=read_timeout_seconds,
        env=os.environ,
    )
    preflight = build_verify_live_gate_preflight(
        profile=local_profile,
        record=record,
        provider=provider,
        env=os.environ,
        manual_real_sat=manual_real_sat,
        permit_ref=permit,
        connect_timeout_seconds=timeout_config.connect_timeout_seconds,
        read_timeout_seconds=timeout_config.read_timeout_seconds,
        timeout_invalid=timeout_config.invalid,
        repo_root=_find_checkout_root(Path.cwd()),
    )
    oracle = VerifyOracleParityResult(status="not-run", reason="preflight-not-ready")
    wsdl_check = VerifyWsdlCheckResult(status="not-run", reachable=False)
    result: LiveSmokeCliResult | None = None
    live_executed = False
    error_kind = ""
    verify_elapsed_ms: int | None = None
    if preflight.ready and local_profile is not None and record is not None and provider is not None:
        try:
            oracle = run_verify_oracle_parity(profile=local_profile, record=record, provider=provider)
        except SatLiveSmokeError as exc:
            oracle = VerifyOracleParityResult(status="failed", reason=exc.error_kind)
        if oracle.status == "passed":
            wsdl_check = check_verify_wsdl_endpoint(
                endpoint_verify=preflight.endpoint_verify,
                connect_timeout_seconds=preflight.connect_timeout_seconds,
            )
            if wsdl_check.status == "passed":
                query = _query_from_live_request_record(local_profile.rfc, record)
                permit_verified = _validate_live_smoke_guard(
                    profile_id=profile,
                    manual_real_sat=manual_real_sat,
                    query=query,
                    metadata_only=True,
                    range_within_limit=_is_minimal_live_smoke_range(query),
                    mode="verify-live-gate",
                    permit_ref=permit,
                )
                try:
                    started = perf_counter()
                    result = _run_live_metadata_verify_smoke(
                        profile,
                        record.id_solicitud,
                        live_permit_verified=permit_verified,
                        connect_timeout_seconds=preflight.connect_timeout_seconds,
                        read_timeout_seconds=preflight.read_timeout_seconds,
                    )
                    verify_elapsed_ms = result.duration_ms
                    live_executed = True
                except SatLiveSmokeError as exc:
                    live_executed = exc.failed_stage in {"auth_transport", "auth_response_parse", "token_extract", "verify_transport", "verify_response_parse"}
                    error_kind = exc.error_kind
                    verify_elapsed_ms = exc.diagnostic.duration_ms if exc.failed_stage == "verify_transport" else None
            else:
                error_kind = wsdl_check.error_kind
    _print_verify_live_gate_result(
        profile_id=profile,
        preflight=preflight,
        oracle=oracle,
        wsdl_check=wsdl_check,
        result=result,
        live_executed=live_executed,
        error_kind=error_kind,
        verify_elapsed_ms=verify_elapsed_ms,
    )
    if not preflight.ready or oracle.status != "passed" or result is None:
        raise typer.Exit(code=1)


@sat_app.command("download-live-gate")
def sat_download_live_gate(
    profile: str = typer.Option("default", "--profile", help="Local setup profile id."),
    request_ref: str | None = typer.Option(None, "--request-ref", help="Local request reference to verify before download."),
    package_ref: str | None = typer.Option(None, "--package-ref", help="Redacted package reference from local finished verify state."),
    manual_real_sat: bool = typer.Option(False, "--manual-real-sat", help="Required human gate for real SAT download."),
    permit: str | None = typer.Option(None, "--permit", help="One-time local package download permit id."),
    connect_timeout_seconds: float | None = typer.Option(
        None,
        "--connect-timeout-seconds",
        min=1.0,
        max=MAX_DOWNLOAD_CONNECT_TIMEOUT_SECONDS,
        help=f"Gate-only connect timeout in seconds. Defaults to {DEFAULT_DOWNLOAD_CONNECT_TIMEOUT_SECONDS:g}.",
    ),
    read_timeout_seconds: float | None = typer.Option(
        None,
        "--read-timeout-seconds",
        min=1.0,
        max=MAX_DOWNLOAD_READ_TIMEOUT_SECONDS,
        help=f"Gate-only download read timeout in seconds. Defaults to {DEFAULT_DOWNLOAD_READ_TIMEOUT_SECONDS:g}.",
    ),
) -> None:
    """Run the controlled v1.5 package download live gate for one package only."""

    local_profile = _load_download_profile_or_none(profile)
    provider = _setup_provider(profile) if local_profile is not None else None
    request_record = _load_request_record_or_none(local_profile, request_ref) if local_profile is not None and request_ref else None
    package_record = (
        _load_package_record_or_none(local_profile, package_ref)
        if local_profile is not None and package_ref and request_record is None
        else None
    )
    record = request_record or package_record
    local_package_id = _resolve_package_id_or_none(record, package_ref) if record is not None and package_ref else None
    timeout_config = resolve_download_gate_timeout_config(
        connect_timeout_seconds=connect_timeout_seconds,
        read_timeout_seconds=read_timeout_seconds,
        env=os.environ,
    )
    preflight = build_download_live_gate_preflight(
        profile=local_profile,
        record=record,
        provider=provider,
        env=os.environ,
        manual_real_sat=manual_real_sat,
        permit_ref=permit,
        request_ref=request_ref,
        package_ref=package_ref,
        package_id=local_package_id,
        connect_timeout_seconds=timeout_config.connect_timeout_seconds,
        read_timeout_seconds=timeout_config.read_timeout_seconds,
        timeout_invalid=timeout_config.invalid,
        repo_root=_find_checkout_root(Path.cwd()),
    )
    wsdl_check = DownloadWsdlCheckResult(status="not-run", reachable=False)
    oracle = DownloadOracleParityResult(status="not-run", reason="preflight-not-ready")
    result = DownloadLiveGateCliResult(
        request_ref=record.request_ref if record is not None else "",
        package_ref=package_ref or "",
        verify_executed=False,
        download_executed=False,
        estado_solicitud="not-run",
        codigo_estado="not_reported",
        numero_cfdis=None,
        ids_paquetes_count=0,
        package_received=False,
        decoded_bytes=0,
        zip_valid=False,
        zip_entries_count=0,
    )
    live_executed = False
    error_kind = ""
    if preflight.ready and local_profile is not None and provider is not None and record is not None:
        wsdl_check = check_download_wsdl_endpoint(connect_timeout_seconds=preflight.connect_timeout_seconds)
        error_kind = wsdl_check.error_kind
        if wsdl_check.status == "passed":
            query = _query_from_live_request_record(local_profile.rfc, record)
            permit_verified = _validate_live_smoke_guard(
                profile_id=profile,
                manual_real_sat=manual_real_sat,
                query=query,
                metadata_only=True,
                range_within_limit=_is_backfill_submit_range(query),
                mode="download-live-gate",
                permit_ref=permit,
                permit_scope=PACKAGE_DOWNLOAD_SCOPE,
            )
            package_id = local_package_id
            verification: SatVerificationResult | None = None
            if request_ref:
                try:
                    verification, _verify_elapsed_ms = _run_live_download_gate_verify(
                        profile,
                        record.id_solicitud,
                        live_permit_verified=permit_verified,
                        connect_timeout_seconds=preflight.connect_timeout_seconds,
                        read_timeout_seconds=preflight.read_timeout_seconds,
                    )
                    live_executed = True
                    package_id = _select_verified_package_id(verification, package_ref)
                    gate = evaluate_package_download_gate(verification.state, verification.package_ids)
                    result = replace(
                        result,
                        verify_executed=True,
                        estado_solicitud=verification.state.value,
                        codigo_estado=verification.sat_code,
                        numero_cfdis=len(verification.package_ids),
                        ids_paquetes_count=len(verification.package_ids),
                        package_ref=redact_package_ref(package_id or "") if package_id else (package_ref or ""),
                    )
                    if not gate.allowed:
                        error_kind = gate.reason
                        package_id = None
                    elif package_id is None:
                        error_kind = "package-ref-not-in-live-verify"
                except SatLiveSmokeError as exc:
                    live_executed = exc.failed_stage in {
                        "auth_transport",
                        "auth_response_parse",
                        "token_extract",
                        "verify_transport",
                        "verify_response_parse",
                    }
                    error_kind = exc.error_kind
            elif package_id is not None:
                gate = evaluate_package_download_gate(record.sat_estado_solicitud or "3", record.package_ids)
                result = replace(
                    result,
                    estado_solicitud=record.sat_estado_solicitud or "finished",
                    codigo_estado=record.sat_codigo_estado or record.sat_code,
                    numero_cfdis=record.numero_cfdis,
                    ids_paquetes_count=len(record.package_ids),
                )
                if not gate.allowed:
                    error_kind = gate.reason
                    package_id = None
            if package_id:
                try:
                    oracle = run_download_oracle_parity(profile=local_profile, package_id=package_id, provider=provider)
                except SatLiveSmokeError as exc:
                    oracle = DownloadOracleParityResult(status="failed", reason=exc.error_kind)
                if oracle.status == "passed":
                    try:
                        download, _download_elapsed_ms = _run_live_download_gate_download(
                            profile,
                            package_id,
                            live_permit_verified=permit_verified,
                            connect_timeout_seconds=preflight.connect_timeout_seconds,
                            read_timeout_seconds=preflight.read_timeout_seconds,
                        )
                        live_executed = True
                        content = download.content if download.action == SatOutcomeAction.FINISHED else None
                        inspection = inspect_package_zip_bytes(content or b"")
                        result = replace(
                            result,
                            download_executed=True,
                            package_received=content is not None,
                            decoded_bytes=len(content or b""),
                            zip_valid=inspection.zip_valid,
                            zip_entries_count=inspection.entry_count,
                            package_ref=redact_package_ref(package_id),
                        )
                        if download.action != SatOutcomeAction.FINISHED:
                            error_kind = download.action.value
                        elif not inspection.zip_valid:
                            error_kind = "zip-invalid"
                    except SatLiveSmokeError as exc:
                        live_executed = exc.failed_stage in {
                            "auth_transport",
                            "auth_response_parse",
                            "token_extract",
                            "package_download",
                        }
                        error_kind = exc.error_kind
                else:
                    error_kind = oracle.reason
    _print_download_live_gate_result(
        profile_id=profile,
        preflight=preflight,
        oracle=oracle,
        wsdl_check=wsdl_check,
        result=result,
        live_executed=live_executed,
        error_kind=error_kind or oracle.reason,
    )
    if not result.download_executed or not result.zip_valid:
        raise typer.Exit(code=1)


@sat_app.command("inspect-auth-contract")
def sat_inspect_auth_contract() -> None:
    """Inspect public SAT auth WSDL without printing raw WSDL."""

    try:
        contract = fetch_auth_wsdl_contract()
    except ValueError as exc:
        typer.echo("error=auth_contract_unavailable", err=True)
        typer.echo(f"reason={exc}", err=True)
        raise typer.Exit(code=1) from exc
    _print_auth_contract(contract)


@sat_app.command("lint-auth-envelope")
def sat_lint_auth_envelope(
    fixture: str = typer.Option("dummy", "--fixture", help="Only dummy is supported for normal offline lint."),
    profile: str | None = typer.Option(None, "--profile", help="Local setup profile id for redacted offline lint."),
    redacted: bool = typer.Option(False, "--redacted", help="Required for profile-backed offline lint."),
    auth_envelope_variant: str = typer.Option(DEFAULT_AUTH_ENVELOPE_VARIANT, "--auth-envelope-variant", help="Expected auth envelope variant."),
) -> None:
    """Lint a SAT auth envelope offline without printing XML."""

    if auth_envelope_variant not in AUTH_ENVELOPE_VARIANTS:
        typer.echo("error=auth_envelope_lint_denied", err=True)
        typer.echo("reason=invalid-auth-envelope-variant", err=True)
        raise typer.Exit(code=1)
    if profile is not None:
        if not redacted:
            typer.echo("error=auth_envelope_lint_denied", err=True)
            typer.echo("reason=redacted-required-for-profile", err=True)
            raise typer.Exit(code=1)
        try:
            envelope = _build_profile_auth_envelope(profile, auth_envelope_variant=auth_envelope_variant)
        except SatLiveSmokeError as exc:
            _print_live_adapter_error(exc)
            raise typer.Exit(code=1) from exc
        _print_auth_envelope_lint("profile-redacted", lint_auth_envelope(envelope, expected_header_action_order=auth_envelope_variant))
        return
    if fixture != "dummy":
        typer.echo("error=auth_envelope_lint_denied", err=True)
        typer.echo("reason=dummy-fixture-required", err=True)
        raise typer.Exit(code=1)
    envelope = build_dummy_auth_envelope("https://auth.example.test/Autenticacion/Autenticacion.svc", auth_envelope_variant=auth_envelope_variant)
    _print_auth_envelope_lint("dummy", lint_auth_envelope(envelope, expected_header_action_order=auth_envelope_variant))


@sat_app.command("oracle-auth-fingerprint")
def sat_oracle_auth_fingerprint(
    fixture: str = typer.Option("dummy", "--fixture", help="Only dummy is supported for local offline fingerprinting."),
    auth_envelope_variant: str = typer.Option(DEFAULT_AUTH_ENVELOPE_VARIANT, "--auth-envelope-variant", help="Local auth envelope variant to fingerprint."),
    phpcfdi_builder_source: Path | None = typer.Option(None, "--phpcfdi-builder-source", help="External path to phpcfdi FielRequestBuilder.php; never vendor it in this repo."),
) -> None:
    """Print redacted local/phpcfdi auth envelope fingerprints without SOAP or secrets."""

    if fixture != "dummy":
        typer.echo("error=auth_oracle_denied", err=True)
        typer.echo("reason=dummy-fixture-required", err=True)
        raise typer.Exit(code=1)
    if auth_envelope_variant not in AUTH_ENVELOPE_VARIANTS:
        typer.echo("error=auth_oracle_denied", err=True)
        typer.echo("reason=invalid-auth-envelope-variant", err=True)
        raise typer.Exit(code=1)
    oracle_fingerprint = fingerprint_phpcfdi_oracle(phpcfdi_builder_source)
    _abort_disabled_phpcfdi_external_oracle(oracle_fingerprint, "auth_oracle_denied")
    envelope = build_dummy_auth_envelope("https://auth.example.test/Autenticacion/Autenticacion.svc", auth_envelope_variant=auth_envelope_variant)
    _print_auth_oracle_fingerprint(
        fingerprint_auth_envelope(envelope),
        oracle_fingerprint,
    )


@sat_app.command("diff-auth-oracle")
def sat_diff_auth_oracle(
    oracle: str = typer.Option("phpcfdi", "--oracle", help="Only phpcfdi is supported."),
    fixture: str = typer.Option("dummy", "--fixture", help="Only dummy is supported for local offline diffing."),
    redacted: bool = typer.Option(False, "--redacted", help="Required; confirms no raw SOAP output is requested."),
    auth_envelope_variant: str = typer.Option(DEFAULT_AUTH_ENVELOPE_VARIANT, "--auth-envelope-variant", help="Local auth envelope variant to diff."),
    phpcfdi_builder_source: Path | None = typer.Option(None, "--phpcfdi-builder-source", help="External path to phpcfdi FielRequestBuilder.php; never vendor it in this repo."),
) -> None:
    """Print a redacted local/phpcfdi auth envelope structural diff."""

    if oracle != "phpcfdi" or fixture != "dummy" or not redacted:
        typer.echo("error=auth_oracle_diff_denied", err=True)
        typer.echo("reason=phpcfdi-dummy-redacted-required", err=True)
        raise typer.Exit(code=1)
    if auth_envelope_variant not in AUTH_ENVELOPE_VARIANTS:
        typer.echo("error=auth_oracle_diff_denied", err=True)
        typer.echo("reason=invalid-auth-envelope-variant", err=True)
        raise typer.Exit(code=1)
    oracle_fingerprint = fingerprint_phpcfdi_oracle(phpcfdi_builder_source)
    _abort_disabled_phpcfdi_external_oracle(oracle_fingerprint, "auth_oracle_diff_denied")
    envelope = build_dummy_auth_envelope("https://auth.example.test/Autenticacion/Autenticacion.svc", auth_envelope_variant=auth_envelope_variant)
    _print_auth_oracle_diff(
        diff_auth_oracle(
            fingerprint_auth_envelope(envelope),
            oracle_fingerprint,
        )
    )


@sat_app.command("diagnose-live")
def sat_diagnose_live(
    profile: str = typer.Option(..., "--profile", help="Local setup profile id."),
    from_date: str = typer.Option(..., "--from", help="Start date: YYYY-MM-DD."),
    to_date: str = typer.Option(..., "--to", help="End date: YYYY-MM-DD."),
    kind: str = typer.Option(..., "--kind", help="metadata only in this version."),
    direction: str = typer.Option(..., "--direction", help="received or issued."),
    manual_real_sat: bool = typer.Option(False, "--manual-real-sat", help="Required human gate for real SAT diagnostic."),
) -> None:
    """Run a human-gated metadata-only live SAT diagnostic command."""

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
        mode="diagnose-live",
    )
    try:
        result = _run_live_diagnose(profile, query)
    except LiveSmokeAdapterUnavailable as exc:
        typer.echo("error=live_adapter_unavailable", err=True)
        raise typer.Exit(code=1) from exc
    except SatLiveSmokeError as exc:
        _print_live_diagnose_result(profile_id=profile, kind=query.request_type.value, direction=query.direction.value, result=None, failed=exc)
        raise typer.Exit(code=1) from exc
    _print_live_diagnose_result(profile_id=profile, kind=query.request_type.value, direction=query.direction.value, result=result)


@sat_app.command("probe-transport")
def sat_probe_transport(
    profile: str = typer.Option("default", "--profile", help="Local setup profile id used for readiness gates only."),
    from_date: str = typer.Option("", "--from", help="Permit date: YYYY-MM-DD when --permit is used."),
    to_date: str = typer.Option("", "--to", help="Permit date: YYYY-MM-DD when --permit is used."),
    manual_real_sat: bool = typer.Option(False, "--manual-real-sat", help="Required human gate for real SAT transport probing."),
    permit: str | None = typer.Option(None, "--permit", help="One-time local live execution permit id."),
) -> None:
    """Probe public SAT DNS/TLS/WSDL transport without e.firma material."""

    _validate_live_transport_probe_guard(
        profile_id=profile,
        manual_real_sat=manual_real_sat,
        permit_ref=permit,
        date_from=from_date,
        date_to=to_date,
    )
    results = tuple(_run_transport_probe())
    _print_transport_probe_results(profile_id=profile, results=results)
    if _has_required_transport_probe_failure(results):
        raise typer.Exit(code=1)


@sat_app.command("probe-auth-post")
def sat_probe_auth_post(
    profile: str = typer.Option("default", "--profile", help="Local setup profile id used for readiness gates only."),
    manual_real_sat: bool = typer.Option(False, "--manual-real-sat", help="Legacy flag accepted but permit is required."),
    permit: str | None = typer.Option(None, "--permit", help="Required one-time local auth_post_probe permit id."),
) -> None:
    """Probe SAT auth HTTPS POST transport without e.firma material or metadata requests."""

    _validate_live_auth_post_probe_guard(profile_id=profile, manual_real_sat=manual_real_sat, permit_ref=permit)
    result = _run_auth_post_probe()
    _print_auth_post_probe_result(profile_id=profile, result=result)
    if result.status != "ok":
        raise typer.Exit(code=1)


@sat_app.command("probe-verify-post")
def sat_probe_verify_post(
    profile: str = typer.Option("default", "--profile", help="Local setup profile id."),
    manual_real_sat: bool = typer.Option(False, "--manual-real-sat", help="Required for live SAT verify POST probe."),
    permit: str | None = typer.Option(None, "--permit", help="Required one-time local verify_post_probe permit id."),
) -> None:
    """Probe SAT verify HTTPS POST transport without e.firma material, real token, or real request id."""

    _validate_live_verify_post_probe_guard(profile_id=profile, manual_real_sat=manual_real_sat, permit_ref=permit)
    result = _run_verify_post_probe()
    _print_verify_post_probe_result(profile_id=profile, result=result)
    if result.status != "ok":
        raise typer.Exit(code=1)


@sat_app.command("probe-auth-matrix")
def sat_probe_auth_matrix(
    profile: str = typer.Option("default", "--profile", help="Local setup profile id used for readiness gates only."),
    manual_real_sat: bool = typer.Option(False, "--manual-real-sat", help="Legacy flag accepted but permit is required."),
    permit: str | None = typer.Option(None, "--permit", help="Required one-time local auth_matrix_probe permit id."),
) -> None:
    """Probe SAT auth transport matrix without e.firma material or metadata requests."""

    _validate_live_auth_matrix_probe_guard(profile_id=profile, manual_real_sat=manual_real_sat, permit_ref=permit)
    results = _run_auth_matrix_probe()
    _print_auth_matrix_probe_results(profile_id=profile, results=results)
    if any(result.status != "ok" for result in results):
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
    permit: str | None = typer.Option(None, "--permit", help="One-time local live execution permit id."),
) -> None:
    """Run a human-gated metadata-only live SAT smoke command."""

    query, _ = _build_profile_download_query_with_profile(
        profile_id=profile,
        from_date=from_date,
        to_date=to_date,
        kind=kind,
        direction=direction,
    )
    permit_verified = _validate_live_smoke_guard(
        profile_id=profile,
        manual_real_sat=manual_real_sat,
        query=query,
        metadata_only=query.request_type == RequestType.METADATA,
        range_within_limit=_is_minimal_live_smoke_range(query),
        permit_ref=permit,
    )
    try:
        if permit_verified:
            result = _run_live_metadata_smoke(profile, query, live_permit_verified=True)
        else:
            result = _run_live_metadata_smoke(profile, query)
    except LiveSmokeAdapterUnavailable as exc:
        typer.echo("error=live_adapter_unavailable", err=True)
        raise typer.Exit(code=1) from exc
    except SatLiveSmokeError as exc:
        _print_live_adapter_error(exc)
        raise typer.Exit(code=1) from exc
    _print_live_smoke_result(profile_id=profile, kind=query.request_type.value, direction=query.direction.value, result=result)


@download_app.command("status")
def download_status(
    profile: str = typer.Option(..., "--profile", help="Local setup profile id."),
    job_id: str | None = typer.Option(None, "--job-id", help="Local download job id from download sync."),
) -> None:
    """Read safe fake download status or async verify scheduler aggregates."""

    loaded_profile = _load_download_profile(profile)
    if job_id is None:
        try:
            records = tuple(record for record in list_live_metadata_requests(loaded_profile.storage_root) if record.profile_id == profile)
        except LiveRequestStateError as exc:
            typer.echo("error=request_state_unavailable", err=True)
            typer.echo(f"reason={exc.reason}", err=True)
            raise typer.Exit(code=1) from exc
        _print_live_metadata_scheduler_status(
            profile_id=profile,
            summary=summarize_live_metadata_requests(records),
        )
        return

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
    mode: str = "live-smoke",
    permit_ref: str | None = None,
    permit_scope: str = "metadata_live_smoke",
) -> bool:
    profile = _load_download_profile(profile_id)
    provider = _setup_provider(profile_id)
    inspection = setup_flow.inspect_profile(profile_id, provider=provider)
    doctor_ok = _live_smoke_doctor_ok(profile)
    repo_clean, scanner_passed = _checkout_guard_status()
    interactive = _terminal_is_interactive()
    confirmed = False
    if permit_ref is None and manual_real_sat and interactive:
        confirmed = _confirm_live_smoke()
    permit_verified = False
    permit_allows_real_credentials = False
    if permit_ref is not None:
        if query is None and permit_scope != "auth_live_smoke":
            typer.echo("error=live_permit_denied", err=True)
            typer.echo("reason=permit-query-required", err=True)
            raise typer.Exit(code=1)
        expected = (
            auth_live_smoke_permit_expectation(profile_id, permit_ref, env=os.environ)
            if permit_scope == "auth_live_smoke"
            else permit_expectation_from_query(permit_scope, profile_id, query)  # type: ignore[arg-type]
        )
        try:
            consumed_permit = validate_and_consume_live_permit(
                permit_ref,
                **expected,
                env=os.environ,
                repo_root=_find_checkout_root(Path.cwd()),
            )
            permit_verified = True
            permit_allows_real_credentials = consumed_permit.allow_real_credentials
        except LivePermitError as exc:
            typer.echo("error=live_permit_denied", err=True)
            typer.echo(f"reason={exc.reason}", err=True)
            raise typer.Exit(code=1) from exc

    try:
        validate_live_sat_guard(
            LiveSatGuardInput(
                manual_real_sat=manual_real_sat,
                terminal_interactive=interactive or permit_verified,
                confirmation_verified=confirmed or permit_verified,
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
                live_permit_verified=permit_verified,
                live_permit_allows_real_credentials=permit_allows_real_credentials,
                real_credentials_required=True,
                environ=os.environ,
            )
        )
    except LiveSatGuardError as exc:
        typer.echo("error=live_sat_guard_denied", err=True)
        for reason in exc.reasons:
            typer.echo(f"reason={reason}", err=True)
        raise typer.Exit(code=1) from exc

    typer.echo("warning=live_sat_smoke_guards_passed", err=True)
    typer.echo("sat_real_execution=adapter_enabled", err=True)
    if query is not None:
        _print_download_query(profile_id=profile_id, query=query, will_submit=False, mode=mode)
    return permit_verified
    return permit_verified


def _validate_live_transport_probe_guard(
    *,
    profile_id: str,
    manual_real_sat: bool,
    permit_ref: str | None = None,
    date_from: str = "",
    date_to: str = "",
) -> None:
    profile = _load_download_profile(profile_id)
    provider = _setup_provider(profile_id)
    inspection = setup_flow.inspect_profile(profile_id, provider=provider)
    doctor_ok = _live_smoke_doctor_ok(profile)
    repo_clean, scanner_passed = _checkout_guard_status()
    interactive = _terminal_is_interactive()
    confirmed = False
    if permit_ref is None and manual_real_sat and interactive:
        confirmed = _confirm_live_transport_probe()
    permit_verified = False
    if permit_ref is not None:
        try:
            expected = transport_probe_permit_expectation(profile_id, permit_ref, env=os.environ)
            if date_from:
                expected["date_from"] = date_from
            if date_to:
                expected["date_to"] = date_to
            validate_and_consume_live_permit(
                permit_ref,
                **expected,
                env=os.environ,
                repo_root=_find_checkout_root(Path.cwd()),
            )
            permit_verified = True
        except LivePermitError as exc:
            typer.echo("error=live_permit_denied", err=True)
            typer.echo(f"reason={exc.reason}", err=True)
            raise typer.Exit(code=1) from exc

    try:
        validate_live_sat_guard(
            LiveSatGuardInput(
                manual_real_sat=manual_real_sat,
                terminal_interactive=interactive or permit_verified,
                confirmation_verified=confirmed or permit_verified,
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
                metadata_only=True,
                range_within_limit=True,
                live_permit_verified=permit_verified,
                live_permit_allows_real_credentials=False,
                real_credentials_required=False,
                environ=os.environ,
            )
        )
    except LiveSatGuardError as exc:
        typer.echo("error=live_sat_guard_denied", err=True)
        for reason in exc.reasons:
            typer.echo(f"reason={reason}", err=True)
        raise typer.Exit(code=1) from exc

    typer.echo("warning=live_sat_transport_probe_guards_passed", err=True)
    typer.echo("sat_real_execution=transport_probe_enabled", err=True)
    return permit_verified


def _validate_live_auth_post_probe_guard(
    *,
    profile_id: str,
    manual_real_sat: bool,
    permit_ref: str | None,
) -> None:
    if permit_ref is None:
        typer.echo("error=live_permit_denied", err=True)
        typer.echo("reason=permit-required", err=True)
        raise typer.Exit(code=1)
    profile = _load_download_profile(profile_id)
    doctor_ok = _live_smoke_doctor_ok(profile)
    repo_clean, scanner_passed = _checkout_guard_status()
    try:
        permit = load_live_execution_permit(permit_ref, env=os.environ)
        validate_and_consume_live_permit(
            permit_ref,
            scope="auth_post_probe",
            profile_id=profile_id,
            kind="metadata",
            direction=permit.direction,
            date_from=permit.date_from,
            date_to=permit.date_to,
            env=os.environ,
            repo_root=_find_checkout_root(Path.cwd()),
        )
    except LivePermitError as exc:
        typer.echo("error=live_permit_denied", err=True)
        typer.echo(f"reason={exc.reason}", err=True)
        raise typer.Exit(code=1) from exc

    try:
        validate_live_sat_guard(
            LiveSatGuardInput(
                manual_real_sat=manual_real_sat,
                terminal_interactive=True,
                confirmation_verified=True,
                profile_ready=profile.status == setup_flow.LocalProfileStatus.READY,
                credentials_ready=False,
                doctor_ok=doctor_ok,
                scanner_passed=scanner_passed,
                repo_clean=repo_clean,
                metadata_only=True,
                range_within_limit=True,
                live_permit_verified=True,
                live_permit_allows_real_credentials=False,
                real_credentials_required=False,
                environ=os.environ,
            )
        )
    except LiveSatGuardError as exc:
        typer.echo("error=live_sat_guard_denied", err=True)
        for reason in exc.reasons:
            typer.echo(f"reason={reason}", err=True)
        raise typer.Exit(code=1) from exc

    typer.echo("warning=live_sat_auth_post_probe_guards_passed", err=True)
    typer.echo("sat_real_execution=auth_post_probe_enabled", err=True)


def _validate_live_verify_post_probe_guard(
    *,
    profile_id: str,
    manual_real_sat: bool,
    permit_ref: str | None,
) -> None:
    if permit_ref is None:
        typer.echo("error=live_permit_denied", err=True)
        typer.echo("reason=permit-required", err=True)
        raise typer.Exit(code=1)
    profile = _load_download_profile(profile_id)
    doctor_ok = _live_smoke_doctor_ok(profile)
    repo_clean, scanner_passed = _checkout_guard_status()
    try:
        permit = load_live_execution_permit(permit_ref, env=os.environ)
        validate_and_consume_live_permit(
            permit_ref,
            scope="verify_post_probe",
            profile_id=profile_id,
            kind="metadata",
            direction=permit.direction,
            date_from=permit.date_from,
            date_to=permit.date_to,
            env=os.environ,
            repo_root=_find_checkout_root(Path.cwd()),
        )
    except LivePermitError as exc:
        typer.echo("error=live_permit_denied", err=True)
        typer.echo(f"reason={exc.reason}", err=True)
        raise typer.Exit(code=1) from exc

    try:
        validate_live_sat_guard(
            LiveSatGuardInput(
                manual_real_sat=manual_real_sat,
                terminal_interactive=True,
                confirmation_verified=True,
                profile_ready=profile.status == setup_flow.LocalProfileStatus.READY,
                credentials_ready=False,
                doctor_ok=doctor_ok,
                scanner_passed=scanner_passed,
                repo_clean=repo_clean,
                metadata_only=True,
                range_within_limit=True,
                live_permit_verified=True,
                live_permit_allows_real_credentials=False,
                real_credentials_required=False,
                environ=os.environ,
            )
        )
    except LiveSatGuardError as exc:
        typer.echo("error=live_sat_guard_denied", err=True)
        for reason in exc.reasons:
            typer.echo(f"reason={reason}", err=True)
        raise typer.Exit(code=1) from exc

    typer.echo("warning=live_sat_verify_post_probe_guards_passed", err=True)
    typer.echo("sat_real_execution=verify_post_probe_enabled", err=True)


def _validate_live_auth_matrix_probe_guard(
    *,
    profile_id: str,
    manual_real_sat: bool,
    permit_ref: str | None,
) -> None:
    if permit_ref is None:
        typer.echo("error=live_permit_denied", err=True)
        typer.echo("reason=permit-required", err=True)
        raise typer.Exit(code=1)
    profile = _load_download_profile(profile_id)
    doctor_ok = _live_smoke_doctor_ok(profile)
    repo_clean, scanner_passed = _checkout_guard_status()
    try:
        permit = load_live_execution_permit(permit_ref, env=os.environ)
        validate_and_consume_live_permit(
            permit_ref,
            scope="auth_matrix_probe",
            profile_id=profile_id,
            kind="metadata",
            direction=permit.direction,
            date_from=permit.date_from,
            date_to=permit.date_to,
            env=os.environ,
            repo_root=_find_checkout_root(Path.cwd()),
        )
    except LivePermitError as exc:
        typer.echo("error=live_permit_denied", err=True)
        typer.echo(f"reason={exc.reason}", err=True)
        raise typer.Exit(code=1) from exc

    try:
        validate_live_sat_guard(
            LiveSatGuardInput(
                manual_real_sat=manual_real_sat,
                terminal_interactive=True,
                confirmation_verified=True,
                profile_ready=profile.status == setup_flow.LocalProfileStatus.READY,
                credentials_ready=False,
                doctor_ok=doctor_ok,
                scanner_passed=scanner_passed,
                repo_clean=repo_clean,
                metadata_only=True,
                range_within_limit=True,
                live_permit_verified=True,
                live_permit_allows_real_credentials=False,
                real_credentials_required=False,
                environ=os.environ,
            )
        )
    except LiveSatGuardError as exc:
        typer.echo("error=live_sat_guard_denied", err=True)
        for reason in exc.reasons:
            typer.echo(f"reason={reason}", err=True)
        raise typer.Exit(code=1) from exc

    typer.echo("warning=live_sat_auth_matrix_probe_guards_passed", err=True)
    typer.echo("sat_real_execution=auth_matrix_probe_enabled", err=True)


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


def _confirm_live_transport_probe() -> bool:
    typer.echo("WARNING: this command probes public SAT transport endpoints.")
    typer.echo("Do not continue unless #50 has explicit approval for this one manual probe.")
    typed = str(typer.prompt(f'Type "{LIVE_TRANSPORT_PROBE_CONFIRMATION}" to continue')).strip()
    return typed == LIVE_TRANSPORT_PROBE_CONFIRMATION


def _is_minimal_live_smoke_range(query: DownloadQuery) -> bool:
    if query.period is None:
        return False
    elapsed_seconds = (query.period.end - query.period.start).total_seconds()
    return query.period.start.date() == query.period.end.date() and 2 <= elapsed_seconds <= 86_400


def _is_backfill_submit_range(query: DownloadQuery) -> bool:
    if query.period is None:
        return False
    elapsed_seconds = (query.period.end - query.period.start).total_seconds()
    elapsed_days = (query.period.end.date() - query.period.start.date()).days + 1
    return 2 <= elapsed_seconds and elapsed_days <= MAX_BACKFILL_RANGE_DAYS


def _deny_backfill_submit(reason: str) -> None:
    typer.echo("error=backfill_submit_denied", err=True)
    typer.echo(f"reason={reason}", err=True)
    raise typer.Exit(code=1)


def _deny_package_download(reason: str) -> None:
    typer.echo("error=package_download_denied", err=True)
    typer.echo(f"reason={reason}", err=True)
    raise typer.Exit(code=1)


def _build_profile_auth_envelope(profile_id: str, *, auth_envelope_variant: str = DEFAULT_AUTH_ENVELOPE_VARIANT) -> bytes:
    profile = _load_download_profile(profile_id)
    material = load_sat_efirma_material(profile, _setup_provider(profile_id))
    return _build_auth_envelope(material, resolve_auth_endpoint(os.environ), auth_envelope_variant=auth_envelope_variant)


def _run_live_auth_smoke(
    profile_id: str,
    *,
    live_permit_verified: bool = False,
    auth_envelope_variant: str = DEFAULT_AUTH_ENVELOPE_VARIANT,
    wcf_action_header_enabled: bool = True,
) -> LiveSmokeCliResult:
    profile = _load_download_profile(profile_id)
    adapter = SatLiveMetadataSmokeAdapter(
        profile=profile,
        provider=_setup_provider(profile_id),
        transport=_live_smoke_transport(live_permit_verified=live_permit_verified),
        auth_envelope_variant=auth_envelope_variant,
        wcf_action_header_enabled=wcf_action_header_enabled,
    )
    result = adapter.auth_smoke()
    return _live_smoke_cli_result(result)


def _run_live_metadata_smoke(
    profile_id: str,
    query: DownloadQuery,
    *,
    live_permit_verified: bool = False,
) -> LiveSmokeCliResult:
    profile = _load_download_profile(profile_id)
    adapter = SatLiveMetadataSmokeAdapter(
        profile=profile,
        provider=_setup_provider(profile_id),
        transport=_live_smoke_transport(live_permit_verified=live_permit_verified),
    )
    result = adapter.metadata_smoke(query)
    return _live_smoke_cli_result(result)


def _run_live_metadata_request_smoke(
    profile_id: str,
    query: DownloadQuery,
    *,
    live_permit_verified: bool = False,
    permit_ref: str | None = None,
    source_command: str = "sat metadata-request-smoke",
    status: str = "accepted",
    max_range_days: int = 1,
) -> LiveSmokeCliResult:
    profile = _load_download_profile(profile_id)
    adapter = SatLiveMetadataSmokeAdapter(
        profile=profile,
        provider=_setup_provider(profile_id),
        transport=_live_smoke_transport(live_permit_verified=live_permit_verified),
    )
    result = adapter.metadata_request_smoke(query, max_range_days=max_range_days)
    request_ref = ""
    if getattr(result, "request", "") == "accepted" and getattr(result, "id_solicitud", ""):
        stored = persist_live_metadata_request(
            storage_root=profile.storage_root,
            profile_id=profile_id,
            query=query,
            operation=getattr(result, "operation", ""),
            id_solicitud=getattr(result, "id_solicitud"),
            sat_code=getattr(result, "sat_code", ""),
            sat_message=getattr(result, "sat_message", ""),
            source_command=source_command,
            permit_ref=permit_ref,
            status=status,
        )
        request_ref = stored.request_ref
    return _live_smoke_cli_result(result, request_ref=request_ref)


def _run_live_metadata_verify_smoke(
    profile_id: str,
    request_id: str,
    *,
    live_permit_verified: bool = False,
    connect_timeout_seconds: float | None = None,
    read_timeout_seconds: float = DEFAULT_VERIFY_READ_TIMEOUT_SECONDS,
) -> LiveSmokeCliResult:
    profile = _load_download_profile(profile_id)
    adapter = SatLiveMetadataSmokeAdapter(
        profile=profile,
        provider=_setup_provider(profile_id),
        transport=_live_smoke_transport(live_permit_verified=live_permit_verified),
        timeout_seconds=read_timeout_seconds,
        connect_timeout_seconds=connect_timeout_seconds,
        read_timeout_seconds=read_timeout_seconds if connect_timeout_seconds is not None else None,
    )
    started = perf_counter()
    result = adapter.metadata_verify_smoke(request_id)
    elapsed_ms = max(0, int((perf_counter() - started) * 1000))
    return replace(_live_smoke_cli_result(result), duration_ms=elapsed_ms)


def _live_verify_due_verifier(profile_id: str, *, live_permit_verified: bool = False) -> SatLiveMetadataSmokeAdapter:
    profile = _load_download_profile(profile_id)
    return SatLiveMetadataSmokeAdapter(
        profile=profile,
        provider=_setup_provider(profile_id),
        transport=_live_smoke_transport(live_permit_verified=live_permit_verified),
    )


def _live_package_downloader(profile_id: str, *, live_permit_verified: bool = False) -> SatLiveMetadataSmokeAdapter:
    profile = _load_download_profile(profile_id)
    return SatLiveMetadataSmokeAdapter(
        profile=profile,
        provider=_setup_provider(profile_id),
        transport=_live_smoke_transport(live_permit_verified=live_permit_verified),
    )


def _live_download_gate_adapter(
    profile_id: str,
    *,
    live_permit_verified: bool = False,
    connect_timeout_seconds: float | None = None,
    read_timeout_seconds: float | None = None,
) -> SatLiveMetadataSmokeAdapter:
    profile = _load_download_profile(profile_id)
    timeout_seconds = read_timeout_seconds or DEFAULT_DOWNLOAD_READ_TIMEOUT_SECONDS
    return SatLiveMetadataSmokeAdapter(
        profile=profile,
        provider=_setup_provider(profile_id),
        transport=_live_smoke_transport(live_permit_verified=live_permit_verified),
        timeout_seconds=timeout_seconds,
        connect_timeout_seconds=connect_timeout_seconds,
        read_timeout_seconds=read_timeout_seconds if connect_timeout_seconds is not None else None,
    )


def _run_live_download_gate_verify(
    profile_id: str,
    request_id: str,
    *,
    live_permit_verified: bool = False,
    connect_timeout_seconds: float | None = None,
    read_timeout_seconds: float | None = None,
) -> tuple[SatVerificationResult, int]:
    started = perf_counter()
    result = _live_download_gate_adapter(
        profile_id,
        live_permit_verified=live_permit_verified,
        connect_timeout_seconds=connect_timeout_seconds,
        read_timeout_seconds=read_timeout_seconds,
    ).verify_request(request_id)
    return result, max(0, int((perf_counter() - started) * 1000))


def _run_live_download_gate_download(
    profile_id: str,
    package_id: str,
    *,
    live_permit_verified: bool = False,
    connect_timeout_seconds: float | None = None,
    read_timeout_seconds: float | None = None,
) -> tuple[SatDownloadResult, int]:
    started = perf_counter()
    result = _live_download_gate_adapter(
        profile_id,
        live_permit_verified=live_permit_verified,
        connect_timeout_seconds=connect_timeout_seconds,
        read_timeout_seconds=read_timeout_seconds,
    ).download_package(package_id)
    return result, max(0, int((perf_counter() - started) * 1000))


def _load_package_record_or_none(
    profile: setup_flow.LocalProfile | None,
    package_ref: str | None,
) -> LiveMetadataRequestRecord | None:
    if profile is None or not package_ref:
        return None
    requested = str(package_ref).strip()
    try:
        records = list_live_metadata_requests(profile.storage_root)
    except LiveRequestStateError:
        return None
    for record in records:
        if record.profile_id == profile.profile_id and requested in record.package_refs_redacted:
            return record
    return None


def _resolve_package_id_or_none(record: LiveMetadataRequestRecord | None, package_ref: str | None) -> str | None:
    if record is None or not package_ref:
        return None
    requested = str(package_ref).strip()
    for package_id in record.package_ids:
        if redact_package_ref(package_id) == requested:
            return package_id
    return None


def _select_verified_package_id(verification: SatVerificationResult, package_ref: str | None) -> str | None:
    if not verification.package_ids:
        return None
    if not package_ref:
        return verification.package_ids[0]
    requested = str(package_ref).strip()
    return next((package_id for package_id in verification.package_ids if redact_package_ref(package_id) == requested), None)


def _resolve_package_id(record: LiveMetadataRequestRecord, package_ref: str) -> str:
    requested = str(package_ref or "").strip()
    if not requested:
        _deny_package_download("package-ref-required")
    for package_id in record.package_ids:
        if redact_package_ref(package_id) == requested:
            return package_id
    _deny_package_download("package-ref-not-found")


def _run_live_package_download_smoke(
    profile_id: str,
    record: LiveMetadataRequestRecord,
    package_id: str,
    *,
    package_ref: str,
    live_permit_verified: bool = False,
) -> PackageDownloadCliResult:
    downloader = _live_package_downloader(profile_id, live_permit_verified=live_permit_verified)
    download = downloader.download_package(package_id)
    if download.action != SatOutcomeAction.FINISHED or download.content is None:
        return PackageDownloadCliResult(
            request_ref=record.request_ref,
            package_ref=package_ref,
            request_status_before=record.status,
            download_result=download.action.value,
            sat_code=download.sat_code,
            message_redacted=_safe_error_reason(download.message),
            package_size_bytes=0,
            zip_valid=False,
            txt_files=0,
            metadata_accepted_count=0,
            metadata_rejected_count=0,
            status_after=record.status,
        )

    storage = LocalStorage(_load_download_profile(profile_id).storage_root)
    processed = process_sat_package(package_id, download.content, storage, allowed_extensions=frozenset({".txt"}))
    accepted, rejected = _parse_extracted_metadata_txt(storage, processed, source_package_id=package_id)
    updated = replace(
        record,
        status=PACKAGE_DOWNLOADED,
        updated_at=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    )
    upsert_live_metadata_request(storage_root=storage.root, record=updated)
    return PackageDownloadCliResult(
        request_ref=record.request_ref,
        package_ref=package_ref,
        request_status_before=record.status,
        download_result=download.action.value,
        sat_code=download.sat_code,
        message_redacted=_safe_error_reason(download.message),
        package_size_bytes=processed.size,
        zip_valid=True,
        txt_files=sum(1 for entry in processed.entries if entry.kind == "txt"),
        metadata_accepted_count=accepted,
        metadata_rejected_count=rejected,
        status_after=updated.status,
    )


def _parse_extracted_metadata_txt(storage: LocalStorage, processed: ProcessedPackage, *, source_package_id: str) -> tuple[int, int]:
    accepted = 0
    rejected = 0
    for entry in processed.entries:
        if entry.kind != "txt":
            continue
        content = storage.path_for_key(entry.storage_key).read_bytes()
        parsed = parse_metadata_bytes(content, source_package_id=source_package_id)
        accepted += parsed.accepted_count
        rejected += parsed.rejected_count
    return accepted, rejected


def _live_smoke_cli_result(result: object, *, request_ref: str = "") -> LiveSmokeCliResult:
    return LiveSmokeCliResult(
        result=getattr(result, "result"),
        auth=getattr(result, "auth"),
        request=getattr(result, "request"),
        verification=getattr(result, "verification"),
        operation=getattr(result, "operation", ""),
        request_ref=request_ref,
        id_solicitud_redacted=getattr(result, "id_solicitud_redacted", ""),
        sat_state=getattr(result, "sat_state", ""),
        package_count=getattr(result, "package_count", 0),
        request_body_bytes_len=getattr(result, "request_body_bytes_len", None),
        envelope_sha256=getattr(result, "envelope_sha256", None),
        signed_reference_count=getattr(result, "signed_reference_count", None),
    )


def _run_live_diagnose(profile_id: str, query: DownloadQuery) -> LiveSmokeCliResult:
    return _run_live_metadata_smoke(profile_id, query)


def _query_from_live_request_record(requester_rfc: str, record: LiveMetadataRequestRecord) -> DownloadQuery:
    try:
        start = _parse_state_datetime(record.fecha_inicial)
        end = _parse_state_datetime(record.fecha_final)
        direction = DownloadDirection(record.direction)
        request_type = RequestType(record.kind)
    except (ValueError, TypeError) as exc:
        typer.echo("error=request_state_invalid", err=True)
        typer.echo("reason=request-state-query-invalid", err=True)
        raise typer.Exit(code=1) from exc
    return DownloadQuery(
        record.profile_id,
        requester_rfc,
        direction,
        request_type,
        DateTimePeriod(start, end),
    )


def _parse_state_datetime(value: str) -> datetime:
    normalized = value.replace("Z", "+00:00")
    parsed = datetime.fromisoformat(normalized)
    return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=timezone.utc)


def _run_transport_probe() -> tuple[SatProbeResult, ...]:
    return run_sat_transport_probe()


def _run_auth_post_probe() -> SatAuthPostProbeResult:
    return run_sat_auth_post_probe()


def _run_verify_post_probe() -> SatVerifyPostProbeResult:
    return run_sat_verify_post_probe()


def _run_auth_matrix_probe() -> tuple[SatAuthMatrixProbeResult, ...]:
    return run_sat_auth_matrix_probe()


def _print_live_metadata_request_state(
    *,
    profile_id: str,
    records: tuple[LiveMetadataRequestRecord, ...],
) -> None:
    summary = summarize_live_metadata_requests(records)
    typer.echo("mode=metadata-request-state")
    typer.echo(f"profile={profile_id}")
    typer.echo(f"pending_count={len(records)}")
    typer.echo(f"pending_verify_count={summary.pending_verify_count}")
    typer.echo(f"due_verify_count={summary.due_verify_count}")
    typer.echo(f"next_due_verification={summary.next_due_verification}")
    typer.echo(f"package_ready_count={summary.package_ready_count}")
    typer.echo(f"failed_requests={summary.failed_requests}")
    for record in records:
        fields = [
            f"request_ref={record.request_ref}",
            f"kind={record.kind}",
            f"direction={record.direction}",
            f"operation={record.operation}",
            f"status={record.status}",
            f"attempt_count={record.attempt_count}",
            f"next_check_at={record.next_check_at}",
            f"last_checked_at={record.last_checked_at}",
            f"id_solicitud_redacted={record.id_solicitud_redacted}",
            f"criteria_hash_prefix={record.criteria_hash[:12]}",
            f"created_at={record.created_at}",
            "full_id_printed=no",
        ]
        typer.echo("request_state=" + "|".join(fields))


def _print_live_metadata_scheduler_status(*, profile_id: str, summary: LiveMetadataRequestSummary) -> None:
    typer.echo("mode=metadata-verify-scheduler")
    typer.echo(f"profile={profile_id}")
    typer.echo(f"pending_verify_count={summary.pending_verify_count}")
    typer.echo(f"due_verify_count={summary.due_verify_count}")
    typer.echo(f"next_due_verification={summary.next_due_verification}")
    typer.echo(f"finished_requests={summary.finished_requests}")
    typer.echo(f"failed_requests={summary.failed_requests}")
    typer.echo(f"package_ready_count={summary.package_ready_count}")
    typer.echo("redacted=true")


def _print_backfill_plan(plan: BackfillPlan) -> None:
    typer.echo("mode=backfill-plan")
    typer.echo(f"profile={plan.profile_id}")
    typer.echo(f"kind={plan.kind.value}")
    typer.echo(f"direction={plan.direction.value}")
    typer.echo(f"window={plan.window}")
    typer.echo(f"from={plan.start_date.isoformat()}")
    typer.echo(f"to={plan.end_date.isoformat()}")
    typer.echo(f"window_count={len(plan.windows)}")
    typer.echo(f"existing_count={plan.existing_count}")
    typer.echo(f"new_count={plan.new_count}")
    typer.echo("sat_real_execution=no")
    typer.echo("package_downloaded=no")
    typer.echo("zip_downloaded=no")
    typer.echo("xml_downloaded=no")
    typer.echo("pdf_generated=no")
    typer.echo("redacted=true")
    for window in plan.windows:
        period = window.query.period
        fields = [
            f"index={window.index}",
            f"from={period.start.isoformat() if period else ''}",
            f"to={period.end.isoformat() if period else ''}",
            f"operation={window.operation}",
            f"criteria_hash={window.criteria_hash}",
            f"exists={str(bool(window.existing_request_ref)).lower()}",
            f"request_ref={window.existing_request_ref}",
            f"status={window.existing_status}",
        ]
        typer.echo("window_plan=" + "|".join(fields))


def _print_backfill_submit_result(
    *,
    plan: BackfillPlan,
    selected: tuple[object, ...],
    result: LiveSmokeCliResult | None,
) -> None:
    typer.echo("mode=backfill-submit")
    typer.echo(f"profile={plan.profile_id}")
    typer.echo(f"kind={plan.kind.value}")
    typer.echo(f"direction={plan.direction.value}")
    typer.echo(f"window={plan.window}")
    typer.echo(f"window_count={len(plan.windows)}")
    typer.echo(f"existing_count={plan.existing_count}")
    typer.echo(f"selected_count={len(selected)}")
    typer.echo(f"submitted_count={1 if result and result.request == 'accepted' else 0}")
    typer.echo(f"sat_real_execution={'adapter_enabled' if selected else 'no'}")
    typer.echo("verification=not_run")
    typer.echo("package_downloaded=no")
    typer.echo("zip_downloaded=no")
    typer.echo("xml_downloaded=no")
    typer.echo("pdf_generated=no")
    if result is not None:
        typer.echo(f"criteria_hash={getattr(selected[0], 'criteria_hash', '')}")
        typer.echo(f"operation={result.operation}")
        typer.echo(f"request={result.request}")
        typer.echo(f"request_ref={result.request_ref}")
        typer.echo(f"id_solicitud_redacted={result.id_solicitud_redacted}")
        typer.echo(f"scheduler_status={VERIFY_SCHEDULED}")


def _print_verify_due_report(report: VerifyDueReport, *, sat_real_execution: str = "no") -> None:
    typer.echo("mode=verify-due")
    typer.echo(f"profile={report.profile_id}")
    typer.echo(f"dry_run={str(report.dry_run).lower()}")
    typer.echo(f"due_count={report.due_count}")
    typer.echo(f"selected_count={report.selected_count}")
    typer.echo(f"processed_count={report.processed_count}")
    typer.echo(f"pending_verify_count={report.pending_verify_count}")
    typer.echo(f"next_due_verification={report.next_due_verification}")
    typer.echo(f"package_ready_count={report.package_ready_count}")
    typer.echo(f"failed_requests={report.failed_requests}")
    typer.echo(f"sat_real_execution={sat_real_execution}")
    typer.echo("package_downloaded=no")
    typer.echo("zip_downloaded=no")
    typer.echo("xml_downloaded=no")
    typer.echo("sleep_used=no")
    typer.echo("loop_used=no")
    for item in report.items:
        fields = [
            f"request_ref={item.request_ref}",
            f"status={item.status}",
            f"attempt_count={item.attempt_count}",
            f"next_check_at={item.next_check_at}",
            f"last_error_kind={item.last_error_kind}",
            f"package_count={item.package_count}",
            "full_id_printed=no",
        ]
        typer.echo("verify_item=" + "|".join(fields))


def _print_package_download_result(*, profile_id: str, result: PackageDownloadCliResult) -> None:
    typer.echo("mode=package-download-smoke")
    typer.echo(f"profile={profile_id}")
    typer.echo(f"request_ref={result.request_ref}")
    typer.echo(f"request_status_before={result.request_status_before}")
    typer.echo(f"package_ref={result.package_ref}")
    typer.echo(f"download_result={result.download_result}")
    typer.echo(f"CodEstatus={result.sat_code}")
    if result.message_redacted:
        typer.echo(f"Mensaje_redacted={result.message_redacted}")
    typer.echo("package_downloaded=yes" if result.zip_valid else "package_downloaded=no")
    typer.echo("zip_downloaded=yes" if result.zip_valid else "zip_downloaded=no")
    typer.echo(f"zip_valid={'true' if result.zip_valid else 'false'}")
    typer.echo("path_traversal=blocked")
    typer.echo(f"package_size_bytes={result.package_size_bytes}")
    typer.echo(f"txt_files={result.txt_files}")
    typer.echo("xml_files=0")
    typer.echo(f"metadata_accepted_count={result.metadata_accepted_count}")
    typer.echo(f"metadata_rejected_count={result.metadata_rejected_count}")
    typer.echo("raw_response_printed=no")
    typer.echo("IdPaquete_full_printed=no")
    typer.echo(f"status_after={result.status_after}")


def _safe_error_reason(value: str) -> str:
    text = " ".join(str(value or "").replace("\\", "/").split())
    return re.sub(r"(?i)\b[0-9a-z][0-9a-z_-]{12,}[0-9a-z]\b", "<redacted>", text)[:160]


def _live_smoke_transport(*, live_permit_verified: bool = False) -> GuardedSoapHttpTransport:
    return GuardedSoapHttpTransport(
        guard_input_factory=lambda: LiveSatGuardInput(
            manual_real_sat=True,
            terminal_interactive=True,
            confirmation_verified=True,
            profile_ready=True,
            credentials_ready=True,
            doctor_ok=True,
            scanner_passed=True,
            repo_clean=True,
            metadata_only=True,
            range_within_limit=True,
            live_permit_verified=live_permit_verified,
            live_permit_allows_real_credentials=live_permit_verified,
            real_credentials_required=True,
            environ=os.environ,
        )
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
    if result.operation:
        typer.echo(f"operation={result.operation}")
    if result.request_ref:
        typer.echo(f"request_ref={result.request_ref}")
    if result.id_solicitud_redacted:
        typer.echo(f"id_solicitud_redacted={result.id_solicitud_redacted}")
    if result.sat_state:
        typer.echo(f"sat_state={result.sat_state}")
    typer.echo(f"package_count={result.package_count}")
    if result.request_body_bytes_len is not None:
        typer.echo(f"request_body_bytes_len={result.request_body_bytes_len}")
    if result.envelope_sha256 is not None:
        typer.echo(f"envelope_sha256={result.envelope_sha256}")
    if result.signed_reference_count is not None:
        typer.echo(f"signed_reference_count={result.signed_reference_count}")
    typer.echo("xml_downloaded=no")
    typer.echo("zip_downloaded=no")
    typer.echo("package_downloaded=no")
    typer.echo("recurrent_automation=no")


def _print_verify_live_gate_result(
    *,
    profile_id: str,
    preflight: VerifyLiveGatePreflight,
    oracle: VerifyOracleParityResult,
    wsdl_check: VerifyWsdlCheckResult | None = None,
    result: LiveSmokeCliResult | None,
    live_executed: bool,
    error_kind: str,
    verify_elapsed_ms: int | None = None,
) -> None:
    completed = result is not None and oracle.status == "passed"
    package_summary = (
        "not-run"
        if result is None
        else f"present_count={result.package_count}"
        if result.package_count > 0
        else "none"
    )
    typer.echo("mode=verify-live-gate")
    typer.echo(f"profile={profile_id}")
    typer.echo(f"completed={_yes_no(completed)}")
    typer.echo(f"live_sat_executed={_yes_no(live_executed)}")
    typer.echo(f"production_signed={_yes_no(preflight.opt_in_production_signed and oracle.status == 'passed')}")
    typer.echo(f"oracle_parity={oracle.status}")
    typer.echo(f"wsdl_check={wsdl_check.status if wsdl_check else 'not-run'}")
    typer.echo(f"connect_timeout_seconds={preflight.connect_timeout_seconds:g}")
    typer.echo(f"read_timeout_seconds={preflight.read_timeout_seconds:g}")
    typer.echo(f"preflight_ready={_yes_no(preflight.ready)}")
    typer.echo(f"preflight_missing={','.join(preflight.missing) if preflight.missing else 'none'}")
    typer.echo(f"opt_in_live={_yes_no(preflight.opt_in_live)}")
    typer.echo(f"opt_in_production_signed={_yes_no(preflight.opt_in_production_signed)}")
    typer.echo(f"manual_real_sat={_yes_no(preflight.manual_real_sat)}")
    typer.echo(f"permit_present={_yes_no(preflight.permit_present)}")
    typer.echo(f"profile_ready={_yes_no(preflight.profile_ready)}")
    typer.echo(f"certificate_local_detected={_yes_no(preflight.certificate_local_detected)}")
    typer.echo(f"private_key_local_detected={_yes_no(preflight.private_key_local_detected)}")
    typer.echo(f"phrase_available={_yes_no(preflight.phrase_available)}")
    typer.echo(f"rfc_redacted={preflight.rfc_redacted}")
    typer.echo(f"id_solicitud_redacted={preflight.id_solicitud_redacted}")
    typer.echo(f"endpoint_verify={preflight.endpoint_verify}")
    typer.echo(f"soap_action={preflight.soap_action}")
    typer.echo(f"wsdl_reachable={_yes_no(wsdl_check.reachable) if wsdl_check else 'no'}")
    typer.echo(f"wsdl_http_status={wsdl_check.status_code if wsdl_check and wsdl_check.status_code is not None else 'not_reported'}")
    typer.echo(f"wsdl_elapsed_ms={wsdl_check.elapsed_ms if wsdl_check and wsdl_check.elapsed_ms is not None else 'not_reported'}")
    typer.echo(f"wsdl_error_kind={wsdl_check.error_kind if wsdl_check and wsdl_check.error_kind else 'none'}")
    typer.echo("raw_wsdl_persisted=no")
    typer.echo(f"oracle_operation={oracle.operation or 'not-run'}")
    typer.echo(f"oracle_namespace={oracle.namespace or 'not-run'}")
    typer.echo(f"oracle_signature_placement={oracle.signature_placement or 'not-run'}")
    typer.echo(f"oracle_signed_target={oracle.signed_target or 'not-run'}")
    typer.echo(f"oracle_canonicalization={oracle.canonicalization or 'not-run'}")
    typer.echo(f"oracle_x509_issuer_serial={_yes_no(oracle.x509_issuer_serial)}")
    typer.echo(f"oracle_x509_certificate={_yes_no(oracle.x509_certificate)}")
    typer.echo(f"result={result.result if result else 'not-run'}")
    typer.echo(f"auth={result.auth if result else 'not-run'}")
    typer.echo(f"request={result.request if result else 'not-run'}")
    typer.echo(f"verification={result.verification if result else 'not-run'}")
    typer.echo(f"estado_solicitud={result.sat_state if result and result.sat_state else 'not-run'}")
    typer.echo("codigo_estado=not_reported")
    typer.echo("numero_cfdis=not_reported")
    typer.echo(f"ids_paquetes={package_summary}")
    typer.echo("download_executed=no")
    typer.echo("raw_soap_persisted=no")
    typer.echo("raw_response_persisted=no")
    typer.echo("authorization_value_visible=no")
    typer.echo("full_rfc_visible=no")
    typer.echo("full_id_solicitud_visible=no")
    typer.echo("full_id_paquete_visible=no")
    typer.echo(f"verify_elapsed_ms={verify_elapsed_ms if verify_elapsed_ms is not None else 'not_reported'}")
    typer.echo(f"error_kind={error_kind or oracle.reason or 'none'}")


def _print_download_live_gate_result(
    *,
    profile_id: str,
    preflight: DownloadLiveGatePreflight,
    oracle: DownloadOracleParityResult,
    wsdl_check: DownloadWsdlCheckResult,
    result: DownloadLiveGateCliResult,
    live_executed: bool,
    error_kind: str,
) -> None:
    completed = result.download_executed and result.zip_valid and oracle.status == "passed"
    typer.echo("mode=download-live-gate")
    typer.echo(f"profile={profile_id}")
    typer.echo(f"completed={_yes_no(completed)}")
    typer.echo(f"live_sat_executed={_yes_no(live_executed)}")
    typer.echo(f"verify_executed={_yes_no(result.verify_executed)}")
    typer.echo(f"download_live_executed={_yes_no(result.download_executed)}")
    typer.echo(f"production_signed={_yes_no(preflight.opt_in_production_signed and oracle.status == 'passed')}")
    typer.echo(f"oracle_parity={oracle.status}")
    typer.echo(f"wsdl_check={wsdl_check.status}")
    typer.echo(f"connect_timeout_seconds={preflight.connect_timeout_seconds:g}")
    typer.echo(f"read_timeout_seconds={preflight.read_timeout_seconds:g}")
    typer.echo(f"preflight_ready={_yes_no(preflight.ready)}")
    typer.echo(f"preflight_missing={','.join(preflight.missing) if preflight.missing else 'none'}")
    typer.echo(f"opt_in_live={_yes_no(preflight.opt_in_live)}")
    typer.echo(f"opt_in_production_signed={_yes_no(preflight.opt_in_production_signed)}")
    typer.echo(f"manual_real_sat={_yes_no(preflight.manual_real_sat)}")
    typer.echo(f"permit_present={_yes_no(preflight.permit_present)}")
    typer.echo(f"request_ref_present={_yes_no(preflight.request_ref_present)}")
    typer.echo(f"package_ref_present={_yes_no(preflight.package_ref_present)}")
    typer.echo(f"profile_ready={_yes_no(preflight.profile_ready)}")
    typer.echo(f"certificate_local_detected={_yes_no(preflight.certificate_local_detected)}")
    typer.echo(f"private_key_local_detected={_yes_no(preflight.private_key_local_detected)}")
    typer.echo(f"phrase_available={_yes_no(preflight.phrase_available)}")
    typer.echo(f"rfc_redacted={preflight.rfc_redacted}")
    typer.echo(f"id_solicitud_redacted={preflight.id_solicitud_redacted}")
    typer.echo(f"id_paquete_redacted={result.package_ref or preflight.id_paquete_redacted}")
    typer.echo(f"endpoint_download={preflight.endpoint_download}")
    typer.echo(f"soap_action={preflight.soap_action}")
    typer.echo(f"wsdl_reachable={_yes_no(wsdl_check.reachable)}")
    typer.echo(f"wsdl_http_status={wsdl_check.status_code if wsdl_check.status_code is not None else 'not_reported'}")
    typer.echo(f"wsdl_elapsed_ms={wsdl_check.elapsed_ms if wsdl_check.elapsed_ms is not None else 'not_reported'}")
    typer.echo(f"wsdl_error_kind={wsdl_check.error_kind or 'none'}")
    typer.echo("raw_wsdl_persisted=no")
    typer.echo(f"oracle_operation={oracle.operation or 'not-run'}")
    typer.echo(f"oracle_namespace={oracle.namespace or 'not-run'}")
    typer.echo(f"oracle_signature_placement={oracle.signature_placement or 'not-run'}")
    typer.echo(f"oracle_signed_target={oracle.signed_target or 'not-run'}")
    typer.echo(f"oracle_canonicalization={oracle.canonicalization or 'not-run'}")
    typer.echo(f"oracle_x509_issuer_serial={_yes_no(oracle.x509_issuer_serial)}")
    typer.echo(f"oracle_x509_certificate={_yes_no(oracle.x509_certificate)}")
    typer.echo(f"oracle_expected_response={oracle.expected_response}")
    typer.echo(f"request_ref={result.request_ref or 'not_reported'}")
    typer.echo(f"package_ref={result.package_ref or 'not_reported'}")
    typer.echo(f"estado_solicitud={result.estado_solicitud}")
    typer.echo(f"codigo_estado={result.codigo_estado}")
    typer.echo(f"numero_cfdis={result.numero_cfdis if result.numero_cfdis is not None else 'not_reported'}")
    typer.echo(f"ids_paquetes_count={result.ids_paquetes_count}")
    typer.echo("ids_paquetes_full_visible=no")
    typer.echo(f"paquete_recibido={_yes_no(result.package_received)}")
    typer.echo("base64_printed=no")
    typer.echo(f"bytes_decoded={result.decoded_bytes}")
    typer.echo(f"zip_valid={_yes_no(result.zip_valid)}")
    typer.echo(f"zip_entries_count={result.zip_entries_count}")
    typer.echo("xml_parsed=no")
    typer.echo("pdf_generated=no")
    typer.echo(f"zip_persisted={_yes_no(result.zip_persisted)}")
    typer.echo("raw_soap_persisted=no")
    typer.echo("raw_response_persisted=no")
    typer.echo("authorization_value_visible=no")
    typer.echo("full_rfc_visible=no")
    typer.echo("full_id_solicitud_visible=no")
    typer.echo("full_id_paquete_visible=no")
    typer.echo(f"error_kind={error_kind or 'none'}")


def _print_auth_contract(contract: AuthWsdlContract) -> None:
    typer.echo("mode=auth-contract")
    typer.echo(f"operation={contract.operation_name}")
    typer.echo(f"soap_action={contract.soap_action}")
    typer.echo(f"soap_version={contract.soap_version}")
    typer.echo(f"binding_transport={contract.binding_transport}")
    typer.echo(f"target_namespace={contract.target_namespace}")
    typer.echo(f"endpoint_scheme={contract.endpoint_scheme}")
    typer.echo(f"endpoint_host={contract.endpoint_host}")
    typer.echo(f"endpoint_port={contract.endpoint_port}")
    typer.echo(f"endpoint_path={contract.endpoint_path}")
    typer.echo(f"expected_action_uri={contract.expected_action_uri}")
    typer.echo(f"wsdl_size={contract.wsdl_size}")
    typer.echo("raw_wsdl_printed=no")
    typer.echo("raw_headers_printed=no")


def _print_auth_envelope_lint(fixture: str, result: AuthEnvelopeLintResult) -> None:
    typer.echo("mode=auth-envelope-lint")
    typer.echo(f"fixture={fixture}")
    typer.echo(f"all_checks_passed={'yes' if result.all_checks_passed else 'no'}")
    typer.echo(f"envelope_sha256={result.envelope_sha256}")
    typer.echo(f"envelope_size={result.envelope_size}")
    typer.echo(f"request_body_bytes_len={result.envelope_size}")
    typer.echo(f"xmlsig_profile={result.xmlsig_profile}")
    typer.echo(f"c14n_algorithm={result.c14n_algorithm}")
    typer.echo(f"signature_algorithm={result.signature_algorithm}")
    typer.echo(f"digest_algorithms={_join_lint_values(result.digest_algorithms)}")
    typer.echo(f"reference_uris={_join_lint_values(result.reference_uris_redacted)}")
    typer.echo(f"reference_transform_algorithms={_join_lint_values(result.reference_transform_algorithms)}")
    typer.echo(f"key_info_reference_uri={result.key_info_reference_uri_redacted}")
    typer.echo(f"header_action_order={result.header_action_order}")
    typer.echo(f"expected_header_action_order={result.expected_header_action_order}")
    if result.timestamp_window_seconds is not None:
        typer.echo(f"timestamp_window_seconds={result.timestamp_window_seconds}")
    typer.echo(f"reference_count={result.reference_count}")
    typer.echo(f"bst_size={result.bst_size}")
    for name in (
        "soap_envelope",
        "soap_header",
        "soap_body",
        "operation_auth",
        "ws_security",
        "timestamp",
        "timestamp_id_present",
        "timestamp_created_utc_z",
        "timestamp_expires_utc_z",
        "timestamp_window_ok",
        "bst_present",
        "bst_id_present",
        "bst_der",
        "bst_no_pem",
        "bst_value_type",
        "bst_encoding_type",
        "signature",
        "signed_info",
        "c14n_method",
        "signature_method",
        "digest_method",
        "reference_transforms",
        "reference_uris",
        "references_resolve",
        "references_use_wsu_id",
        "signed_nodes_exist",
        "digest_value",
        "signature_value",
        "key_info",
        "sec_ref",
        "sec_ref_uri",
        "sec_ref_value_type",
        "sec_ref_resolves_bst",
        "timestamp_signed",
        "to_header_present",
        "action_header_present",
        "action_header_value",
        "action_header_namespace",
        "action_header_must_understand",
        "action_header_before_security",
        "action_header_order_ok",
        "security_must_understand",
        "local_signature_verify",
    ):
        typer.echo(f"check_{name}={'yes' if getattr(result, name) else 'no'}")
    typer.echo("raw_xml_printed=no")
    typer.echo("certificate_printed=no")
    typer.echo("signature_value_printed=no")
    typer.echo("key_material_printed=no")


def _abort_disabled_phpcfdi_external_oracle(oracle: PhpCfdiOracleFingerprint, error: str) -> None:
    if oracle.reason != PHP_CFDI_BUILDER_SOURCE_DISABLED_IN_CI:
        return
    typer.echo(f"error={error}", err=True)
    typer.echo(f"reason={oracle.reason}", err=True)
    typer.echo("sat_real_executed=no", err=True)
    typer.echo("raw_xml_printed=no", err=True)
    typer.echo("raw_xml_saved=no", err=True)
    typer.echo("key_material_printed=no", err=True)
    raise typer.Exit(code=1)


def _print_auth_oracle_fingerprint(local: AuthEnvelopeFingerprint, oracle: PhpCfdiOracleFingerprint) -> None:
    typer.echo("mode=auth-oracle-fingerprint")
    typer.echo("local_available=yes")
    for key, value in (
        ("local_envelope_sha256", local.envelope_sha256),
        ("local_envelope_size", local.envelope_size),
        ("local_ordered_element_paths", _join_lint_values(local.ordered_element_paths)),
        ("local_namespaces", _join_lint_values(local.namespaces)),
        ("local_attributes", _join_lint_values(local.attributes)),
        ("local_c14n_algorithm", local.c14n_algorithm),
        ("local_signature_algorithm", local.signature_algorithm),
        ("local_digest_algorithms", _join_lint_values(local.digest_algorithms)),
        ("local_reference_uris", _join_lint_values(local.reference_uris_redacted)),
        ("local_bst_length", local.bst_length),
        ("local_signature_value_length", local.signature_value_length),
        ("local_digest_value_lengths", _join_lint_values(tuple(str(value) for value in local.digest_value_lengths))),
        ("local_has_header_action", _yes_no(local.has_header_action)),
        ("local_header_action_order", local.header_action_order),
        ("local_sec_ref_shape", local.sec_ref_shape),
    ):
        typer.echo(f"{key}={value}")
    typer.echo(f"phpcfdi_available={'yes' if oracle.available else 'no'}")
    typer.echo(f"php_available={'yes' if oracle.php_available else 'no'}")
    typer.echo(f"composer_available={'yes' if oracle.composer_available else 'no'}")
    typer.echo(f"phpcfdi_reason={oracle.reason}")
    if oracle.available:
        for key, value in (
            ("phpcfdi_source_sha256", oracle.source_sha256),
            ("phpcfdi_has_header_action", _yes_no(oracle.has_header_action)),
            ("phpcfdi_header_action_order", oracle.header_action_order),
            ("phpcfdi_c14n_algorithm", oracle.c14n_algorithm),
            ("phpcfdi_signature_algorithm", oracle.signature_algorithm),
            ("phpcfdi_digest_algorithm", oracle.digest_algorithm),
            ("phpcfdi_reference_uri", oracle.reference_uri_redacted),
            ("phpcfdi_sec_ref_shape", oracle.sec_ref_shape),
            ("phpcfdi_request_operations", _join_lint_values(oracle.request_operations)),
        ):
            typer.echo(f"{key}={value}")
    else:
        for index, step in enumerate(oracle.setup_steps, start=1):
            typer.echo(f"phpcfdi_setup_step_{index}={step}")
    for flag in ("sat_real_executed", "raw_xml_printed", "certificate_printed", "signature_value_printed", "digest_value_printed", "key_material_printed"):
        typer.echo(f"{flag}=no")


def _print_auth_oracle_diff(result: AuthOracleDiffResult) -> None:
    typer.echo("mode=auth-oracle-diff")
    typer.echo(f"oracle={result.oracle}")
    typer.echo(f"phpcfdi_available={'yes' if result.oracle_available else 'no'}")
    typer.echo(f"local_envelope_sha256={result.local_envelope_sha256}")
    typer.echo(f"local_envelope_size={result.local_envelope_size}")
    typer.echo(f"phpcfdi_source_sha256={result.oracle_source_sha256 or 'none'}")
    typer.echo(f"likely_breaking={'yes' if result.likely_breaking else 'no'}")
    typer.echo(f"recommended_fix={result.recommended_fix}")
    for item in result.items:
        typer.echo(
            f"diff field={item.field} status={item.status} "
            f"likely_breaking={'yes' if item.likely_breaking else 'no'} "
            f"ours={item.ours} oracle={item.oracle} safe_hint={item.safe_hint}"
        )
    for flag in ("sat_real_executed", "raw_xml_printed", "raw_xml_saved", "certificate_printed", "signature_value_printed", "digest_value_printed", "key_material_printed"):
        typer.echo(f"{flag}=no")


def _join_lint_values(values: tuple[str, ...]) -> str:
    return ",".join(values) if values else "none"


def _print_live_diagnose_result(
    *,
    profile_id: str,
    kind: str,
    direction: str,
    result: LiveSmokeCliResult | None,
    failed: SatLiveSmokeError | None = None,
) -> None:
    typer.echo("mode=diagnose-live")
    typer.echo(f"profile={profile_id}")
    typer.echo(f"kind={kind}")
    typer.echo(f"direction={direction}")
    typer.echo(f"diagnostic_status={'failed' if failed else 'ok'}")
    typer.echo(f"stages={_diagnostic_stage_summary(failed.failed_stage if failed else None)}")
    if result is not None:
        typer.echo(f"result={result.result}")
        typer.echo(f"auth={result.auth}")
        typer.echo(f"request={result.request}")
        typer.echo(f"verification={result.verification}")
    typer.echo("xml_downloaded=no")
    typer.echo("zip_downloaded=no")
    typer.echo("package_downloaded=no")
    typer.echo("recurrent_automation=no")
    if failed is not None:
        _print_live_adapter_error(failed)


def _print_transport_probe_results(*, profile_id: str, results: tuple[SatProbeResult, ...]) -> None:
    typer.echo("mode=transport-probe")
    typer.echo(f"profile={profile_id}")
    typer.echo(f"probe_status={'failed' if _has_required_transport_probe_failure(results) else 'ok'}")
    for result in results:
        fields = [
            f"endpoint={result.endpoint}",
            f"check={result.check}",
            f"required={'no' if result.endpoint == 'package_download' else 'yes'}",
            f"scheme={result.scheme}",
            f"host={result.host}",
            f"port={result.port}",
            f"path={result.path}",
            f"query_present={'yes' if result.query_present else 'no'}",
            f"status={result.status}",
            f"error_kind={result.error_kind}",
            f"safe_hint={result.safe_hint}",
            f"duration_ms={result.duration_ms}",
            f"correlation_id={result.correlation_id}",
        ]
        if result.http_status is not None:
            fields.append(f"http_status={result.http_status}")
        if result.payload_size is not None:
            fields.append(f"payload_size={result.payload_size}")
        typer.echo("probe_result=" + "|".join(fields))
    typer.echo("efirma_loaded=no")
    typer.echo("credential_material_loaded=no")
    typer.echo("metadata_requested=no")
    typer.echo("xml_downloaded=no")
    typer.echo("zip_downloaded=no")
    typer.echo("raw_wsdl_printed=no")


def _has_required_transport_probe_failure(results: tuple[SatProbeResult, ...]) -> bool:
    return any(result.status != "ok" and result.endpoint != "package_download" for result in results)


def _print_auth_post_probe_result(*, profile_id: str, result: SatAuthPostProbeResult) -> None:
    typer.echo("mode=auth-post-probe")
    typer.echo(f"profile={profile_id}")
    typer.echo(f"probe_status={result.status}")
    fields = [
        f"endpoint={result.endpoint}",
        f"check={result.check}",
        "required=yes",
        f"scheme={result.scheme}",
        f"host={result.host}",
        f"port={result.port}",
        f"path={result.path}",
        f"query_present={'yes' if result.query_present else 'no'}",
        f"status={result.status}",
        f"error_kind={result.error_kind}",
        f"safe_hint={result.safe_hint}",
        f"duration_ms={result.duration_ms}",
        f"correlation_id={result.correlation_id}",
    ]
    if result.http_status is not None:
        fields.append(f"http_status={result.http_status}")
    if result.payload_size is not None:
        fields.append(f"payload_size={result.payload_size}")
    typer.echo("probe_result=" + "|".join(fields))
    typer.echo("efirma_loaded=no")
    typer.echo("credential_material_loaded=no")
    typer.echo("metadata_requested=no")
    typer.echo("xml_downloaded=no")
    typer.echo("zip_downloaded=no")
    typer.echo("raw_request_printed=no")
    typer.echo("raw_response_printed=no")
    typer.echo("raw_soap_printed=no")
    typer.echo("raw_headers_printed=no")


def _print_verify_post_probe_result(*, profile_id: str, result: SatVerifyPostProbeResult) -> None:
    typer.echo("mode=verify-post-probe")
    typer.echo(f"profile={profile_id}")
    typer.echo(f"probe_status={result.status}")
    fields = [
        f"endpoint={result.endpoint}",
        f"check={result.check}",
        f"host={result.host}",
        f"scheme={result.scheme}",
        f"port={result.port}",
        f"path={result.path}",
        f"query_present={'yes' if result.query_present else 'no'}",
        f"error_kind={result.error_kind}",
        f"duration_ms={result.duration_ms}",
        f"correlation_id={result.correlation_id}",
        f"request_body_bytes_len={result.request_body_bytes_len}",
        f"has_authorization={'yes' if result.has_authorization else 'no'}",
    ]
    if result.http_status is not None:
        fields.append(f"http_status={result.http_status}")
    if result.payload_size is not None:
        fields.append(f"payload_size={result.payload_size}")
    typer.echo("probe_result=" + "|".join(fields))
    typer.echo(f"safe_hint={result.safe_hint}")
    typer.echo("efirma_loaded=no")
    typer.echo("credential_material_loaded=no")
    typer.echo("real_authorization_value_used=no")
    typer.echo("real_request_id_used=no")
    typer.echo("metadata_requested=no")
    typer.echo("xml_downloaded=no")
    typer.echo("zip_downloaded=no")
    typer.echo("raw_request_printed=no")
    typer.echo("raw_response_printed=no")
    typer.echo("raw_soap_printed=no")
    typer.echo("raw_headers_printed=no")


def _print_auth_matrix_probe_results(*, profile_id: str, results: tuple[SatAuthMatrixProbeResult, ...]) -> None:
    typer.echo("mode=auth-matrix-probe")
    typer.echo(f"profile={profile_id}")
    typer.echo(f"probe_status={'failed' if any(result.status != 'ok' for result in results) else 'ok'}")
    for result in results:
        fields = [
            f"client_kind={result.client_kind}",
            f"method={result.method}",
            f"endpoint={result.logical_endpoint}",
            f"check={result.check}",
            f"scheme={result.scheme}",
            f"host={result.host}",
            f"port={result.port}",
            f"path={result.path}",
            f"query_present={'yes' if result.query_present else 'no'}",
            f"sni_host={result.sni_host}",
            f"tls_result={result.tls_result}",
            f"status={result.status}",
            f"error_kind={result.error_kind}",
            f"safe_hint={result.safe_hint}",
            f"proxy_detected={'yes' if result.proxy_detected else 'no'}",
            f"ca_mode={result.ca_mode}",
            f"timeout={result.timeout_seconds:g}",
            f"duration_ms={result.duration_ms}",
            f"correlation_id={result.correlation_id}",
        ]
        if result.http_status is not None:
            fields.append(f"http_status={result.http_status}")
        if result.soap_fault_present is not None:
            fields.append(f"soap_fault_present={'yes' if result.soap_fault_present else 'no'}")
        if result.exception_class is not None:
            fields.append(f"exception_class={result.exception_class}")
        if result.exception_errno is not None:
            fields.append(f"exception_errno={result.exception_errno}")
        typer.echo("matrix_result=" + "|".join(fields))
    typer.echo("efirma_loaded=no")
    typer.echo("credential_material_loaded=no")
    typer.echo("credential_reference_resolved=no")
    typer.echo("metadata_requested=no")
    typer.echo("xml_downloaded=no")
    typer.echo("zip_downloaded=no")
    typer.echo("raw_request_printed=no")
    typer.echo("raw_response_printed=no")
    typer.echo("raw_soap_printed=no")
    typer.echo("raw_headers_printed=no")
    typer.echo("raw_wsdl_printed=no")
    typer.echo("raw_html_printed=no")


def _print_live_adapter_error(exc: SatLiveSmokeError) -> None:
    diagnostic = exc.diagnostic
    typer.echo("error=live_adapter_failed", err=True)
    typer.echo(f"failed_stage={diagnostic.stage}", err=True)
    typer.echo(f"error_kind={diagnostic.error_kind}", err=True)
    typer.echo(f"safe_hint={diagnostic.safe_hint}", err=True)
    typer.echo(f"correlation_id={diagnostic.correlation_id}", err=True)
    for key, value in (
        ("endpoint", diagnostic.endpoint),
        ("http_status", diagnostic.http_status),
        ("soap_fault_code", diagnostic.soap_fault_code),
        ("sat_code", diagnostic.sat_code),
        ("operation", diagnostic.operation),
        ("payload_size", diagnostic.payload_size),
        ("envelope_sha256", diagnostic.envelope_sha256),
        ("exception_class", diagnostic.exception_class),
        ("exception_errno", diagnostic.exception_errno),
        ("transport_layer", diagnostic.transport_layer),
        ("duration_ms", diagnostic.duration_ms),
        ("request_body_bytes_len", diagnostic.request_body_bytes_len),
        ("soap_action", diagnostic.soap_action),
        ("content_type", diagnostic.content_type),
        ("timestamp_window_seconds", diagnostic.timestamp_window_seconds),
        ("has_ws_security", _yes_no(diagnostic.has_ws_security)),
        ("has_binary_security_token", _yes_no(diagnostic.has_bst)),
        ("cert_der_bytes_len", diagnostic.cert_der_bytes_len),
        ("signature_method", diagnostic.signature_method),
        ("digest_method", diagnostic.digest_method),
        ("signed_reference_count", diagnostic.signed_reference_count),
        ("signed_reference_targets_exist", _yes_no(diagnostic.signed_reference_targets_exist)),
        ("has_header_action", _yes_no(diagnostic.has_header_action)),
        ("header_action_value_ok", _yes_no(diagnostic.header_action_value_ok)),
        ("header_action_must_understand", _yes_no(diagnostic.header_action_must_understand)),
        ("header_action_order", diagnostic.header_action_order),
        ("security_must_understand", _yes_no(diagnostic.security_must_understand)),
        ("has_authorization", _yes_no(diagnostic.has_authorization)),
        ("token_len", diagnostic.authorization_value_len),
        ("has_id_solicitud", _yes_no(diagnostic.has_id_solicitud)),
        ("id_solicitud_redacted", diagnostic.id_solicitud_redacted),
        ("has_rfc_solicitante", _yes_no(diagnostic.has_rfc_solicitante)),
        ("has_signature", _yes_no(diagnostic.has_signature)),
        ("endpoint_url_ok", _yes_no(diagnostic.endpoint_url_ok)),
    ):
        if value is not None:
            typer.echo(f"{key}={value}", err=True)


def _yes_no(value: bool | None) -> str | None:
    if value is None:
        return None
    return "yes" if value else "no"


def _diagnostic_stage_summary(failed_stage: str | None) -> str:
    statuses: list[str] = []
    failed_seen = False
    for stage in DIAGNOSTIC_STAGES:
        if stage in {"package_download", "package_process"}:
            status = "skipped"
        elif failed_stage == stage:
            status = "failed"
            failed_seen = True
        else:
            status = "skipped" if failed_seen else "ok"
        statuses.append(f"{stage}:{status}")
    if failed_stage and failed_stage not in DIAGNOSTIC_STAGES:
        statuses.append(f"{failed_stage}:failed")
    return ",".join(statuses)


def _load_download_profile(profile_id: str) -> setup_flow.LocalProfile:
    try:
        return setup_flow.load_profile(profile_id)
    except setup_flow.SetupError as exc:
        reason = "profile_not_configured" if _has_profile_not_configured_error(exc) else "profile_invalid"
        typer.echo(f"profile={profile_id}", err=True)
        typer.echo(f"error={reason}", err=True)
        raise typer.Exit(code=1) from exc


def _load_download_profile_or_none(profile_id: str) -> setup_flow.LocalProfile | None:
    try:
        return setup_flow.load_profile(profile_id)
    except setup_flow.SetupError:
        return None


def _load_request_record_or_none(
    profile: setup_flow.LocalProfile,
    request_ref: str | None,
) -> LiveMetadataRequestRecord | None:
    if not request_ref:
        return None
    try:
        return load_live_metadata_request(profile.storage_root, request_ref)
    except LiveRequestStateError:
        return None


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


def _parse_backfill_date(value: str, *, label: str) -> date:
    try:
        return datetime.fromisoformat(value.strip()).date()
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
