from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

from typer.testing import CliRunner

from cfdi_vault.adapters.cli import sat_verify as cli_module
from cfdi_vault.cli import app
from cfdi_vault.domain import SatRequestState
from cfdi_vault.live_permit import LivePermitRequest, create_live_execution_permit
from cfdi_vault.sat_contract import SatDownloadResult, SatOutcomeAction, SatVerificationResult
from cfdi_vault.sat_download_live_gate import (
    DownloadOracleParityResult,
    DownloadWsdlCheckResult,
    check_download_wsdl_endpoint,
)
from cfdi_vault.sat_live_request_state import PACKAGE_READY, persist_live_metadata_request, redact_package_ref, upsert_live_metadata_request
from cfdi_vault.sat_package_download_offline import build_synthetic_package_zip
from tests.test_cli_download import (
    _assert_no_profile_secrets_or_paths,
    _key_value_lines,
    _live_smoke_env,
    _patch_live_smoke_dependencies,
    _weekly_metadata_query,
    _write_ready_setup_profile,
)


def test_cli_download_live_gate_blocks_without_required_preflight(tmp_path: Path, monkeypatch) -> None:
    appdata_root = tmp_path / "appdata"
    _write_ready_setup_profile(appdata_root)
    monkeypatch.setattr(
        cli_module,
        "check_download_wsdl_endpoint",
        lambda **_kwargs: (_ for _ in ()).throw(AssertionError("WSDL must not run")),
    )

    result = CliRunner().invoke(
        app,
        ["sat", "download-live-gate", "--profile", "dummy-profile"],
        env={"LOCALAPPDATA": str(appdata_root), "CI": ""},
    )

    assert result.exit_code == 1
    lines = _key_value_lines(result.output)
    assert lines["mode"] == "download-live-gate"
    assert lines["preflight_ready"] == "no"
    assert "missing-CFDI_VAULT_SAT_LIVE" in lines["preflight_missing"]
    assert "missing-CFDI_VAULT_SAT_PRODUCTION_SIGNED" in lines["preflight_missing"]
    assert "missing-manual-real-sat" in lines["preflight_missing"]
    assert "missing-live-permit" in lines["preflight_missing"]
    assert "missing-request-or-package-ref" in lines["preflight_missing"]
    assert lines["live_sat_executed"] == "no"
    assert lines["download_live_executed"] == "no"
    assert lines["raw_soap_persisted"] == "no"
    assert lines["raw_response_persisted"] == "no"
    _assert_no_profile_secrets_or_paths(result.output, appdata_root)


def test_cli_download_live_gate_blocks_when_verify_is_not_finished(tmp_path: Path, monkeypatch) -> None:
    appdata_root = tmp_path / "appdata"
    paths = _write_ready_setup_profile(appdata_root)
    record = _persist_request(paths.storage_root)
    permit = _permit(appdata_root)
    _patch_live_smoke_dependencies(monkeypatch, checkout=(True, True), interactive=False, doctor_ok=True)
    monkeypatch.setattr(cli_module, "check_download_wsdl_endpoint", lambda **_kwargs: DownloadWsdlCheckResult("passed", True, 200, 1))
    monkeypatch.setattr(
        cli_module,
        "_run_live_download_gate_verify",
        lambda *_args, **_kwargs: (
            SatVerificationResult(
                request_id="648a0000-1111-2222-3333-444444447b27",
                state=SatRequestState.IN_PROCESS,
                sat_code="5000",
                message="Working",
                action=SatOutcomeAction.IN_PROGRESS,
                package_ids=(),
            ),
            1,
        ),
    )
    monkeypatch.setattr(
        cli_module,
        "run_download_oracle_parity",
        lambda **_kwargs: (_ for _ in ()).throw(AssertionError("oracle must not run without packages")),
    )
    monkeypatch.setattr(
        cli_module,
        "_run_live_download_gate_download",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("download must not run")),
    )

    result = CliRunner().invoke(
        app,
        [
            "sat",
            "download-live-gate",
            "--profile",
            "dummy-profile",
            "--request-ref",
            record.request_ref,
            "--manual-real-sat",
            "--permit",
            permit,
            "--connect-timeout-seconds",
            "15",
            "--read-timeout-seconds",
            "180",
        ],
        env=_download_gate_env(appdata_root),
    )

    assert result.exit_code == 1
    lines = _key_value_lines(result.output)
    assert lines["verify_executed"] == "yes"
    assert lines["estado_solicitud"] == "in_process"
    assert lines["ids_paquetes_count"] == "0"
    assert lines["download_live_executed"] == "no"
    assert lines["error_kind"] == "estado-solicitud-not-finished"


def test_cli_download_live_gate_downloads_one_package_and_discards_zip(tmp_path: Path, monkeypatch) -> None:
    appdata_root = tmp_path / "appdata"
    paths = _write_ready_setup_profile(appdata_root)
    record = _persist_request(paths.storage_root)
    permit = _permit(appdata_root)
    package_ids = ("SYNTHETIC-PACKAGE-SECRET-0001", "SYNTHETIC-PACKAGE-SECRET-0002")
    seen: dict[str, object] = {}
    _patch_live_smoke_dependencies(monkeypatch, checkout=(True, True), interactive=False, doctor_ok=True)
    monkeypatch.setattr(cli_module, "check_download_wsdl_endpoint", lambda **_kwargs: DownloadWsdlCheckResult("passed", True, 200, 1))
    monkeypatch.setattr(
        cli_module,
        "_run_live_download_gate_verify",
        lambda *_args, **_kwargs: (
            SatVerificationResult(
                request_id="648a0000-1111-2222-3333-444444447b27",
                state=SatRequestState.FINISHED,
                sat_code="5000",
                message="Finished",
                action=SatOutcomeAction.FINISHED,
                package_ids=package_ids,
            ),
            1,
        ),
    )
    monkeypatch.setattr(
        cli_module,
        "run_download_oracle_parity",
        lambda **_kwargs: DownloadOracleParityResult(
            status="passed",
            operation="Descargar",
            namespace="http://DescargaMasivaTerceros.sat.gob.mx",
            signature_placement="inside_peticion_descarga",
            signed_target="operation_wrapper",
            canonicalization="http://www.w3.org/2001/10/xml-exc-c14n#",
            x509_issuer_serial=True,
            x509_certificate=True,
        ),
    )

    def fake_download(_profile_id: str, package_id: str, **_kwargs):
        seen["package_id"] = package_id
        return (
            SatDownloadResult(
                package_id=package_id,
                sat_code="5000",
                message="Downloaded",
                action=SatOutcomeAction.FINISHED,
                content=build_synthetic_package_zip(),
            ),
            1,
        )

    monkeypatch.setattr(cli_module, "_run_live_download_gate_download", fake_download)

    result = CliRunner().invoke(
        app,
        [
            "sat",
            "download-live-gate",
            "--profile",
            "dummy-profile",
            "--request-ref",
            record.request_ref,
            "--manual-real-sat",
            "--permit",
            permit,
            "--connect-timeout-seconds",
            "15",
            "--read-timeout-seconds",
            "180",
        ],
        env=_download_gate_env(appdata_root),
    )

    assert result.exit_code == 0, result.output
    assert seen == {"package_id": package_ids[0]}
    lines = _key_value_lines(result.output)
    assert lines["download_live_executed"] == "yes"
    assert lines["ids_paquetes_count"] == "2"
    assert lines["paquete_recibido"] == "yes"
    assert lines["base64_printed"] == "no"
    assert int(lines["bytes_decoded"]) > 0
    assert lines["zip_valid"] == "yes"
    assert lines["zip_entries_count"] == "2"
    assert lines["zip_persisted"] == "no"
    assert lines["xml_parsed"] == "no"
    assert lines["pdf_generated"] == "no"
    assert package_ids[0] not in result.output
    assert package_ids[1] not in result.output
    assert "648a0000-1111-2222-3333-444444447b27" not in result.output
    _assert_no_profile_secrets_or_paths(result.output, appdata_root)


def test_cli_download_live_gate_requires_oracle_before_download(tmp_path: Path, monkeypatch) -> None:
    appdata_root = tmp_path / "appdata"
    paths = _write_ready_setup_profile(appdata_root)
    package_id = "SYNTHETIC-PACKAGE-SECRET-0001"
    package_ref = redact_package_ref(package_id)
    record = replace(
        _persist_request(paths.storage_root),
        status=PACKAGE_READY,
        sat_estado_solicitud="finished",
        package_ids=(package_id,),
        package_refs_redacted=(package_ref,),
        numero_cfdis=1,
    )
    upsert_live_metadata_request(storage_root=paths.storage_root, record=record)
    permit = _permit(appdata_root)
    _patch_live_smoke_dependencies(monkeypatch, checkout=(True, True), interactive=False, doctor_ok=True)
    monkeypatch.setattr(cli_module, "check_download_wsdl_endpoint", lambda **_kwargs: DownloadWsdlCheckResult("passed", True, 200, 1))
    monkeypatch.setattr(
        cli_module,
        "run_download_oracle_parity",
        lambda **_kwargs: DownloadOracleParityResult(status="failed", reason="synthetic-oracle-failure"),
    )
    monkeypatch.setattr(
        cli_module,
        "_run_live_download_gate_download",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("download must not run after oracle failure")),
    )

    result = CliRunner().invoke(
        app,
        [
            "sat",
            "download-live-gate",
            "--profile",
            "dummy-profile",
            "--package-ref",
            package_ref,
            "--manual-real-sat",
            "--permit",
            permit,
            "--connect-timeout-seconds",
            "15",
            "--read-timeout-seconds",
            "180",
        ],
        env=_download_gate_env(appdata_root),
    )

    assert result.exit_code == 1
    lines = _key_value_lines(result.output)
    assert lines["oracle_parity"] == "failed"
    assert lines["download_live_executed"] == "no"
    assert lines["error_kind"] == "synthetic-oracle-failure"
    assert package_id not in result.output


def test_download_wsdl_check_does_not_read_or_persist_raw_wsdl() -> None:
    class FakeResponse:
        read_called = False

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

        def getcode(self) -> int:
            return 200

        def read(self) -> bytes:
            self.read_called = True
            return b"<definitions>raw wsdl must stay unread</definitions>"

    class FakeOpener:
        def __init__(self) -> None:
            self.response = FakeResponse()
            self.timeout = None
            self.url = ""

        def urlopen(self, request, timeout):  # noqa: ANN001
            self.timeout = timeout
            self.url = request.full_url
            return self.response

    opener = FakeOpener()

    result = check_download_wsdl_endpoint(connect_timeout_seconds=15, opener=opener)

    assert result.status == "passed"
    assert result.reachable is True
    assert result.status_code == 200
    assert opener.timeout == 15
    assert opener.url.endswith("?wsdl")
    assert opener.response.read_called is False


def _persist_request(storage_root: Path):
    return persist_live_metadata_request(
        storage_root=storage_root,
        profile_id="dummy-profile",
        query=_weekly_metadata_query(),
        operation="SolicitaDescargaRecibidos",
        id_solicitud="648a0000-1111-2222-3333-444444447b27",
        sat_code="5000",
        sat_message="Accepted",
        source_command="sat metadata-request-smoke",
        permit_ref=None,
        now=datetime.now(timezone.utc) - timedelta(minutes=10),
    )


def _permit(appdata_root: Path) -> str:
    return create_live_execution_permit(
        LivePermitRequest(
            scope="package_download_smoke",
            profile_id="dummy-profile",
            kind="metadata",
            direction="received",
            date_from="2024-01-01",
            date_to="2024-01-07",
            reason="Carlos authorized package download live gate test",
        ),
        env={"LOCALAPPDATA": str(appdata_root)},
    ).permit_id


def _download_gate_env(appdata_root: Path) -> dict[str, str]:
    return _live_smoke_env(
        appdata_root,
        {
            "CFDI_VAULT_ALLOW_REAL_SAT": None,
            "CFDI_VAULT_ALLOW_REAL_CREDENTIALS": None,
            "CFDI_VAULT_SAT_LIVE": "1",
            "CFDI_VAULT_SAT_PRODUCTION_SIGNED": "1",
        },
    )
