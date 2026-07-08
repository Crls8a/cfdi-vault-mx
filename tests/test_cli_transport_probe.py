from __future__ import annotations

from types import SimpleNamespace
from typer.testing import CliRunner

from cfdi_vault.adapters.cli import sat_probes as cli_module
from cfdi_vault.cli import app
from cfdi_vault.sat_auth_matrix_probe import SatAuthMatrixProbeResult
from cfdi_vault.sat_auth_post_probe import SatAuthPostProbeResult
from cfdi_vault.sat_transport_probe import SatProbeResult
from cfdi_vault.sat_verify_post_probe import SatVerifyPostProbeResult


def test_sat_probe_transport_prints_redacted_results(monkeypatch) -> None:
    monkeypatch.setattr(cli_module, "_validate_live_transport_probe_guard", lambda **kwargs: None)
    monkeypatch.setattr(
        cli_module,
        "_run_transport_probe",
        lambda: (
            SatProbeResult(
                endpoint="auth_service",
                check="wsdl_get",
                host="sat.example",
                status="ok",
                error_kind="ok",
                safe_hint="public transport check passed",
                http_status=200,
                payload_size=42,
                duration_ms=3,
                correlation_id="probe-synthetic",
            ),
        ),
    )

    result = CliRunner().invoke(app, ["sat", "probe-transport", "--manual-real-sat"])

    assert result.exit_code == 0, result.output
    assert "mode=transport-probe" in result.output
    assert "probe_status=ok" in result.output
    assert "endpoint=auth_service" in result.output
    assert "host=sat.example" in result.output
    assert "http_status=200" in result.output
    assert "payload_size=42" in result.output
    assert "efirma_loaded=no" in result.output
    assert "credential_material_loaded=no" in result.output
    assert "metadata_requested=no" in result.output
    assert "https://" not in result.output
    assert "raw wsdl" not in result.output.lower()


def test_sat_probe_transport_keeps_package_endpoint_non_fatal(monkeypatch) -> None:
    monkeypatch.setattr(cli_module, "_validate_live_transport_probe_guard", lambda **kwargs: None)
    monkeypatch.setattr(
        cli_module,
        "_run_transport_probe",
        lambda: (
            SatProbeResult(
                endpoint="package_download",
                check="wsdl_get",
                host="sat.example",
                status="failed",
                error_kind="wsdl_unavailable",
                safe_hint="WSDL endpoint reached but did not return a successful WSDL response",
                correlation_id="probe-package",
            ),
        ),
    )

    result = CliRunner().invoke(app, ["sat", "probe-transport", "--manual-real-sat"])

    assert result.exit_code == 0, result.output
    assert "probe_status=ok" in result.output
    assert "required=no" in result.output
    assert "error_kind=wsdl_unavailable" in result.output


def test_sat_probe_transport_passes_permit_id_to_guard(monkeypatch) -> None:
    seen: dict[str, object] = {}
    monkeypatch.setattr(cli_module, "_validate_live_transport_probe_guard", lambda **kwargs: seen.update(kwargs))
    monkeypatch.setattr(cli_module, "_run_transport_probe", lambda: ())

    result = CliRunner().invoke(app, ["sat", "probe-transport", "--profile", "dummy-profile", "--permit", "permit-abc_123"])

    assert result.exit_code == 0, result.output
    assert seen["profile_id"] == "dummy-profile"
    assert seen["permit_ref"] == "permit-abc_123"
    assert seen["manual_real_sat"] is False


def test_sat_probe_auth_post_requires_permit_before_probe(monkeypatch) -> None:
    calls: list[str] = []
    monkeypatch.setattr(cli_module, "_run_auth_post_probe", lambda: calls.append("called"))

    result = CliRunner().invoke(app, ["sat", "probe-auth-post", "--profile", "dummy-profile"])

    assert result.exit_code == 1
    assert "error=live_permit_denied" in result.output
    assert "reason=permit-required" in result.output
    assert calls == []


def test_sat_probe_auth_post_prints_redacted_reached_server_result(monkeypatch) -> None:
    seen: dict[str, object] = {}
    monkeypatch.setattr(cli_module, "_validate_live_auth_post_probe_guard", lambda **kwargs: seen.update(kwargs))
    monkeypatch.setattr(
        cli_module,
        "_run_auth_post_probe",
        lambda: SatAuthPostProbeResult(
            endpoint="auth",
            check="post",
            host="auth.example",
            status="ok",
            error_kind="http_status_error",
            safe_hint="auth POST reached the server",
            http_status=415,
            payload_size=21,
            duration_ms=5,
            correlation_id="authpost-synthetic",
        ),
    )

    result = CliRunner().invoke(app, ["sat", "probe-auth-post", "--profile", "dummy-profile", "--permit", "permit-abc_123"])

    assert result.exit_code == 0, result.output
    assert seen["profile_id"] == "dummy-profile"
    assert seen["permit_ref"] == "permit-abc_123"
    assert "mode=auth-post-probe" in result.output
    assert "probe_status=ok" in result.output
    assert "endpoint=auth" in result.output
    assert "error_kind=http_status_error" in result.output
    assert "efirma_loaded=no" in result.output
    assert "credential_material_loaded=no" in result.output
    assert "metadata_requested=no" in result.output
    assert "raw_soap_printed=no" in result.output
    assert "https://" not in result.output


def test_sat_probe_verify_post_prints_redacted_reached_server_result(monkeypatch) -> None:
    seen: dict[str, object] = {}
    monkeypatch.setattr(cli_module, "_validate_live_verify_post_probe_guard", lambda **kwargs: seen.update(kwargs))
    monkeypatch.setattr(
        cli_module,
        "_run_verify_post_probe",
        lambda **kwargs: SatVerifyPostProbeResult(
            endpoint="verify",
            check="post",
            host="verify.example",
            status="ok",
            error_kind="soap_fault",
            safe_hint="verify POST reached SOAP handling",
            http_status=500,
            payload_size=21,
            duration_ms=5,
            correlation_id="verifypost-synthetic",
            request_body_bytes_len=345,
            has_authorization=True,
            variant=kwargs["variant"],
            post_attempted=True,
            response_received=True,
            soap_fault_detected=True,
            request_size_bytes=345,
            response_size_bytes=21,
            exception_stage="soap_fault",
        ),
    )

    result = CliRunner().invoke(
        app,
        [
            "sat",
            "probe-verify-post",
            "--profile",
            "dummy-profile",
            "--manual-real-sat",
            "--permit",
            "permit-abc_123",
            "--variant",
            "keep-alive",
        ],
    )

    assert result.exit_code == 0, result.output
    assert seen["profile_id"] == "dummy-profile"
    assert seen["permit_ref"] == "permit-abc_123"
    assert seen["manual_real_sat"] is True
    assert "mode=verify-post-probe" in result.output
    assert "probe_status=ok" in result.output
    assert "variant=keep-alive" in result.output
    assert "post_attempted=yes" in result.output
    assert "response_received=yes" in result.output
    assert "soap_fault_detected=yes" in result.output
    assert "timeout_stage=none" in result.output
    assert "endpoint=verify" in result.output
    assert "error_kind=soap_fault" in result.output
    assert "has_authorization=yes" in result.output
    assert "real_authorization_value_used=no" in result.output
    assert "real_request_id_used=no" in result.output
    assert "raw_soap_printed=no" in result.output
    assert "https://" not in result.output


def test_sat_probe_verify_post_dry_run_skips_live_guard(monkeypatch) -> None:
    calls: list[str] = []
    monkeypatch.setattr(cli_module, "_validate_live_verify_post_probe_guard", lambda **kwargs: calls.append("guard"))
    monkeypatch.setattr(
        cli_module,
        "_run_verify_post_probe",
        lambda **kwargs: SatVerifyPostProbeResult(
            endpoint="verify",
            check="post",
            host="verify.example",
            status="dry_run",
            error_kind="none",
            safe_hint="dry run",
            variant=kwargs["variant"],
            post_attempted=False,
            response_received=False,
            request_size_bytes=345,
            connect_timeout_seconds=kwargs["connect_timeout_seconds"],
            read_timeout_seconds=kwargs["read_timeout_seconds"],
        ),
    )

    result = CliRunner().invoke(app, ["sat", "probe-verify-post", "--profile", "dummy-profile", "--dry-run"])

    assert result.exit_code == 0, result.output
    assert calls == []
    assert "post_attempted=no" in result.output
    assert "response_received=no" in result.output


def test_sat_probe_verify_post_dry_run_reports_production_signed_shape_without_live_guard(monkeypatch) -> None:
    calls: list[str] = []
    monkeypatch.setattr(cli_module, "_validate_live_verify_post_probe_guard", lambda **kwargs: calls.append("guard"))

    result = CliRunner().invoke(
        app,
        [
            "sat",
            "probe-verify-post",
            "--profile",
            "dummy-profile",
            "--dry-run",
            "--variant",
            "connection-close",
            "--envelope-source",
            "production-signed",
        ],
    )

    assert result.exit_code == 0, result.output
    assert calls == []
    for marker in (
        "probe_status=dry_run",
        "variant=connection-close",
        "envelope_source=production-signed",
        "body_shape_verified=yes",
        "operation=VerificaSolicitudDescarga",
        "has_id_solicitud=yes",
        "has_rfc_solicitante=yes",
        "has_signature=yes",
        "has_signed_info=yes",
        "has_signature_value=yes",
        "has_key_info=yes",
        "has_x509_issuer_serial=yes",
        "has_x509_certificate=yes",
        "signature_placement=inside_solicitud",
        "signed_target=operation_wrapper",
        "canonicalization=exclusive_c14n",
        "transform=exclusive_c14n",
        "reference_uri=empty",
        "digest_method=sha1",
        "signature_method=rsa_sha1",
        "has_authorization_wrap=yes",
        "authorization_in_body=no",
        "content_type=text/xml; charset=utf-8",
        "soap_action_present=yes",
        "request_body_sha256_redacted=sha256:",
        "redaction_active=yes",
        "raw_soap_printed=no",
    ):
        assert marker in result.output
    for forbidden in ("WRAP", "access_token", "DUMMY-VERIFY-REQUEST", "XAXX010101000"):
        assert forbidden not in result.output


def test_sat_probe_verify_post_requires_manual_flag_before_live_probe(monkeypatch) -> None:
    calls: list[str] = []
    monkeypatch.setattr(cli_module, "_run_verify_post_probe", lambda **kwargs: calls.append("called"))

    result = CliRunner().invoke(app, ["sat", "probe-verify-post", "--profile", "dummy-profile", "--permit", "permit-abc_123"])

    assert result.exit_code == 1
    assert "error=live_sat_guard_denied" in result.output
    assert "reason=missing-manual-real-sat-flag" in result.output
    assert calls == []


def test_sat_probe_verify_post_requires_permit_for_live_probe(monkeypatch) -> None:
    calls: list[str] = []
    monkeypatch.setattr(cli_module, "_run_verify_post_probe", lambda **kwargs: calls.append("called"))

    result = CliRunner().invoke(app, ["sat", "probe-verify-post", "--profile", "dummy-profile", "--manual-real-sat"])

    assert result.exit_code == 1
    assert "error=live_permit_denied" in result.output
    assert "reason=permit-required" in result.output
    assert calls == []


def test_sat_probe_verify_post_rejects_dirty_worktree_before_probe(monkeypatch) -> None:
    calls: list[str] = []
    monkeypatch.setattr(
        cli_module,
        "_load_download_profile",
        lambda profile_id: SimpleNamespace(status=cli_module.setup_flow.LocalProfileStatus.READY),
    )
    monkeypatch.setattr(cli_module, "_live_smoke_doctor_ok", lambda profile: True)
    monkeypatch.setattr(cli_module, "_checkout_guard_status", lambda: (False, True))
    monkeypatch.setattr(
        cli_module,
        "load_live_execution_permit",
        lambda permit_ref, env: SimpleNamespace(direction="received", date_from="2024-01-01", date_to="2024-01-01"),
    )
    monkeypatch.setattr(cli_module, "validate_and_consume_live_permit", lambda *args, **kwargs: SimpleNamespace())
    monkeypatch.setattr(cli_module, "_run_verify_post_probe", lambda **kwargs: calls.append("called"))

    result = CliRunner().invoke(
        app,
        [
            "sat",
            "probe-verify-post",
            "--profile",
            "dummy-profile",
            "--manual-real-sat",
            "--permit",
            "permit-abc_123",
        ],
    )

    assert result.exit_code == 1
    assert "error=live_sat_guard_denied" in result.output
    assert "reason=repo-dirty" in result.output
    assert calls == []



def test_sat_probe_auth_matrix_requires_permit_before_probe(monkeypatch) -> None:
    calls: list[str] = []
    monkeypatch.setattr(cli_module, "_run_auth_matrix_probe", lambda: calls.append("called"))

    result = CliRunner().invoke(app, ["sat", "probe-auth-matrix", "--profile", "dummy-profile"])

    assert result.exit_code == 1
    assert "error=live_permit_denied" in result.output
    assert "reason=permit-required" in result.output
    assert calls == []


def test_sat_probe_auth_matrix_prints_redacted_results(monkeypatch) -> None:
    seen: dict[str, object] = {}
    monkeypatch.setattr(cli_module, "_validate_live_auth_matrix_probe_guard", lambda **kwargs: seen.update(kwargs))
    monkeypatch.setattr(
        cli_module,
        "_run_auth_matrix_probe",
        lambda: (
            SatAuthMatrixProbeResult(
                client_kind="python",
                method="POST",
                logical_endpoint="auth",
                check="dummy_envelope",
                scheme="https",
                host="auth.example",
                port=443,
                path="/Autenticacion/Autenticacion.svc",
                sni_host="auth.example",
                tls_result="ok",
                status="ok",
                error_kind="http_status_error",
                safe_hint="request reached HTTP",
                timeout_seconds=10,
                proxy_detected=False,
                ca_mode="default",
                http_status=415,
                soap_fault_present=False,
                duration_ms=5,
                correlation_id="authmatrix-synthetic",
            ),
        ),
    )

    result = CliRunner().invoke(app, ["sat", "probe-auth-matrix", "--profile", "dummy-profile", "--permit", "permit-abc_123"])

    assert result.exit_code == 0, result.output
    assert seen["profile_id"] == "dummy-profile"
    assert seen["permit_ref"] == "permit-abc_123"
    assert "mode=auth-matrix-probe" in result.output
    assert "probe_status=ok" in result.output
    assert "matrix_result=client_kind=python|method=POST|endpoint=auth" in result.output
    assert "tls_result=ok" in result.output
    assert "http_status=415" in result.output
    assert "credential_reference_resolved=no" in result.output
    assert "metadata_requested=no" in result.output
    assert "raw_soap_printed=no" in result.output
    assert "raw_headers_printed=no" in result.output
    assert "https://" not in result.output


def test_live_permit_create_writes_redacted_appdata_permit(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "appdata"))

    result = CliRunner().invoke(
        app,
        [
            "live",
            "permit",
            "create",
            "--scope",
            "transport_probe",
            "--profile",
            "dummy-profile",
            "--kind",
            "metadata",
            "--direction",
            "received",
            "--from",
            "2024-01-01",
            "--to",
            "2024-01-01",
            "--expires-minutes",
            "15",
            "--reason",
            "Carlos authorized post-86 transport probe",
        ],
    )

    assert result.exit_code == 0, result.output
    assert "mode=live-permit" in result.output
    assert "scope=transport_probe" in result.output
    assert "redaction_required=true" in result.output
    assert "permit_storage=appdata-local" in result.output
    assert "private-key" not in result.output.lower()
