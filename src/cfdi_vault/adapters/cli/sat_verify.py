"""SAT verify and package download CLI commands."""

from __future__ import annotations

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
) -> LiveSmokeCliResult:
    profile = _load_download_profile(profile_id)
    adapter = SatLiveMetadataSmokeAdapter(
        profile=profile,
        provider=_setup_provider(profile_id),
        transport=_live_smoke_transport(live_permit_verified=live_permit_verified),
    )
    result = adapter.metadata_verify_smoke(request_id)
    return _live_smoke_cli_result(result)

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
