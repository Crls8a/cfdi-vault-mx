"""SAT verify and package download CLI commands."""

from __future__ import annotations

from time import perf_counter

from cfdi_vault.sat_contract import SatDownloadResult, SatVerificationResult
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
from cfdi_vault.sat_package_download_offline import evaluate_package_download_gate, inspect_package_zip_bytes
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

from .common import *
from .sat_common import _is_backfill_submit_range, _query_from_live_request_record


def _deny_package_download(reason: str) -> None:
    typer.echo("error=package_download_denied", err=True)
    typer.echo(f"reason={reason}", err=True)
    raise typer.Exit(code=1)

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
                    live_executed = exc.failed_stage in {
                        "auth_transport",
                        "auth_response_parse",
                        "token_extract",
                        "verify_transport",
                        "verify_response_parse",
                    }
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
