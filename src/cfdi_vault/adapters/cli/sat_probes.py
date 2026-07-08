"""SAT transport probe CLI commands."""

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

def _run_transport_probe() -> tuple[SatProbeResult, ...]:
    return run_sat_transport_probe()

def _run_auth_post_probe() -> SatAuthPostProbeResult:
    return run_sat_auth_post_probe()

def _run_verify_post_probe() -> SatVerifyPostProbeResult:
    return run_sat_verify_post_probe()

def _run_auth_matrix_probe() -> tuple[SatAuthMatrixProbeResult, ...]:
    return run_sat_auth_matrix_probe()

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
