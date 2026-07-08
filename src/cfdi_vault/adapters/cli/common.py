"""Shared CLI dependencies and helpers."""

from __future__ import annotations
from collections.abc import Callable
from dataclasses import dataclass, replace
from datetime import date, datetime, time, timezone
import os
from pathlib import Path
import re
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
from cfdi_vault.sat_contract import SatOutcomeAction
from cfdi_vault.sat_transport_probe import SatProbeResult, run_sat_transport_probe
from cfdi_vault.sat_verify_post_probe import SatVerifyPostProbeResult, run_sat_verify_post_probe
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

class LiveSmokeAdapterUnavailable(RuntimeError):
    """Raised after guards pass when the real live adapter is not wired yet."""

def _service(
    database_url: str | None = None,
    storage: Path | None = None,
) -> RecoveryService:
    queue = RabbitMqQueue(os.environ["RABBITMQ_URL"]) if os.getenv("RABBITMQ_URL") else None
    cache = RedisCache(os.environ["REDIS_URL"]) if os.getenv("REDIS_URL") else None
    return RecoveryService(
        database_url=_require_database_url(database_url),
        storage_root=_resolve_storage_root(storage),
        queue=queue,
        cache=cache,
    )

def _require_database_url(database_url: str | None = None) -> str:
    resolved_url = database_url or os.getenv("DATABASE_URL")
    if not resolved_url:
        typer.echo("error=database_url_required", err=True)
        typer.echo("detail=Set DATABASE_URL or pass --database-url.", err=True)
        raise typer.Exit(code=1)
    return resolved_url

def _resolve_storage_root(storage: Path | None = None) -> Path:
    return storage or Path(os.getenv("CFDI_STORAGE_ROOT", "storage"))

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

def _download_profile_service(profile: setup_flow.LocalProfile, database_url: str | None = None) -> RecoveryService:
    return RecoveryService(database_url=_require_database_url(database_url), storage_root=profile.storage_root)

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
    if query.period is None:
        return False
    elapsed_seconds = (query.period.end - query.period.start).total_seconds()
    return query.period.start.date() == query.period.end.date() and 2 <= elapsed_seconds <= 86_400

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
        duration_ms=getattr(result, "duration_ms", None),
    )

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

def _parse_cli_datetime(value: str, *, end_of_day: bool) -> datetime:
    normalized = value.strip()
    if "T" in normalized or " " in normalized:
        parsed = datetime.fromisoformat(normalized.replace("Z", "+00:00"))
    else:
        parsed = datetime.combine(datetime.fromisoformat(normalized).date(), time.max if end_of_day else time.min)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed

def _provider_for_reference(reference: CredentialReference) -> object:
    if reference.provider_scheme == WindowsCredentialManagerSecretProvider.provider_scheme:
        return WindowsCredentialManagerSecretProvider()
    if reference.provider_scheme == DummySecretProvider.provider_scheme:
        return DummySecretProvider()
    raise typer.BadParameter(f"unsupported credential reference scheme: {reference.provider_scheme}")

def _setup_provider(profile_id: str) -> object:
    phrase_ref = setup_flow.default_phrase_reference(profile_id)
    return _provider_for_reference(CredentialReference(uri=phrase_ref, kind=CredentialKind.PHRASE))

__all__ = tuple(name for name in globals() if not name.startswith("__") and name != "__all__")
