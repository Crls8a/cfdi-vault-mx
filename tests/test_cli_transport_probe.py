from __future__ import annotations

from typer.testing import CliRunner

from cfdi_vault import cli as cli_module
from cfdi_vault.cli import app
from cfdi_vault.sat_transport_probe import SatProbeResult


def test_sat_probe_transport_prints_redacted_results(monkeypatch) -> None:
    monkeypatch.setattr(cli_module, "_validate_live_transport_probe_guard", lambda profile_id, manual_real_sat: None)
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
