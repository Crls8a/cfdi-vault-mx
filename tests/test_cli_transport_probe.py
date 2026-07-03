from __future__ import annotations

from typer.testing import CliRunner

from cfdi_vault import cli as cli_module
from cfdi_vault.cli import app
from cfdi_vault.sat_auth_matrix_probe import SatAuthMatrixProbeResult
from cfdi_vault.sat_auth_post_probe import SatAuthPostProbeResult
from cfdi_vault.sat_transport_probe import SatProbeResult


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
