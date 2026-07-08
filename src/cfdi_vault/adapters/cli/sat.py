"""Sat CLI commands."""

from __future__ import annotations

from .common import *


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

def _confirm_live_transport_probe() -> bool:
    typer.echo("WARNING: this command probes public SAT transport endpoints.")
    typer.echo("Do not continue unless #50 has explicit approval for this one manual probe.")
    typed = str(typer.prompt(f'Type "{LIVE_TRANSPORT_PROBE_CONFIRMATION}" to continue')).strip()
    return typed == LIVE_TRANSPORT_PROBE_CONFIRMATION

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

def _parse_backfill_date(value: str, *, label: str) -> date:
    try:
        return datetime.fromisoformat(value.strip()).date()
    except ValueError as exc:
        raise typer.BadParameter(f"{label} must be a valid YYYY-MM-DD date") from exc

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

def sat_inspect_auth_contract() -> None:
    """Inspect public SAT auth WSDL without printing raw WSDL."""

    try:
        contract = fetch_auth_wsdl_contract()
    except ValueError as exc:
        typer.echo("error=auth_contract_unavailable", err=True)
        typer.echo(f"reason={exc}", err=True)
        raise typer.Exit(code=1) from exc
    _print_auth_contract(contract)

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


def register(sat_app: typer.Typer, backfill_app: typer.Typer) -> None:
    """Register sat commands."""

    sat_app.command("auth-smoke")(sat_auth_smoke)

    sat_app.command("metadata-request-smoke")(sat_metadata_request_smoke)

    sat_app.command("metadata-request-state")(sat_metadata_request_state)

    backfill_app.command("plan")(sat_backfill_plan)

    backfill_app.command("submit")(sat_backfill_submit)

    sat_app.command("verify-due")(sat_verify_due)

    sat_app.command("package-download-smoke")(sat_package_download_smoke)

    sat_app.command("metadata-verify-smoke")(sat_metadata_verify_smoke)

    sat_app.command("inspect-auth-contract")(sat_inspect_auth_contract)

    sat_app.command("lint-auth-envelope")(sat_lint_auth_envelope)

    sat_app.command("oracle-auth-fingerprint")(sat_oracle_auth_fingerprint)

    sat_app.command("diff-auth-oracle")(sat_diff_auth_oracle)

    sat_app.command("diagnose-live")(sat_diagnose_live)

    sat_app.command("probe-transport")(sat_probe_transport)

    sat_app.command("probe-auth-post")(sat_probe_auth_post)

    sat_app.command("probe-verify-post")(sat_probe_verify_post)

    sat_app.command("probe-auth-matrix")(sat_probe_auth_matrix)
