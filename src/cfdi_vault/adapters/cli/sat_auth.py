"""SAT authentication CLI commands."""

from __future__ import annotations

from .common import *
from .sat_common import _join_lint_values


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
