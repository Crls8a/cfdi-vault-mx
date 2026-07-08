from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from typer.testing import CliRunner

from cfdi_vault import setup as setup_flow
from cfdi_vault.cli import LiveSmokeCliResult, _print_verify_live_gate_result, app
from cfdi_vault.sat_live_request_state import LiveMetadataRequestRecord
from cfdi_vault.sat_verify_live_gate import (
    DEFAULT_VERIFY_CONNECT_TIMEOUT_SECONDS,
    DEFAULT_VERIFY_READ_TIMEOUT_SECONDS,
    LIVE_GATE_ENV,
    MAX_VERIFY_READ_TIMEOUT_SECONDS,
    PRODUCTION_SIGNED_ENV,
    VerifyOracleParityResult,
    VerifyWsdlCheckResult,
    build_verify_live_gate_preflight,
    check_verify_wsdl_endpoint,
    resolve_verify_gate_timeout_config,
    run_verify_oracle_parity,
)
from cfdi_vault.secrets import DummySecretProvider


SYNTHETIC_RFC = "XAXX010101000"
SYNTHETIC_REQUEST_ID = "SYNTHETIC-REQUEST-ID-00000001"
SYNTHETIC_REQUEST_REDACTED = "SYNT...0001"
SYNTHETIC_PHRASE = "synthetic phrase"


def test_verify_live_gate_preflight_blocks_without_opt_ins_and_redacts_values(tmp_path: Path) -> None:
    profile = _profile(tmp_path)
    record = _record()
    provider = DummySecretProvider({profile.phrase_ref: SYNTHETIC_PHRASE})

    preflight = build_verify_live_gate_preflight(
        profile=profile,
        record=record,
        provider=provider,
        env={},
        manual_real_sat=False,
        permit_ref=None,
        repo_root=Path.cwd(),
    )

    assert preflight.ready is False
    assert "missing-CFDI_VAULT_SAT_LIVE" in preflight.missing
    assert "missing-CFDI_VAULT_SAT_PRODUCTION_SIGNED" in preflight.missing
    assert "missing-manual-real-sat" in preflight.missing
    assert "missing-live-permit" in preflight.missing
    assert preflight.rfc_redacted == "XA*********00"
    assert preflight.id_solicitud_redacted == SYNTHETIC_REQUEST_REDACTED
    assert SYNTHETIC_RFC not in repr(preflight)
    assert SYNTHETIC_REQUEST_ID not in repr(preflight)


def test_verify_live_gate_preflight_requires_production_signed_opt_in(tmp_path: Path) -> None:
    profile = _profile(tmp_path)
    record = _record()
    provider = DummySecretProvider({profile.phrase_ref: SYNTHETIC_PHRASE})

    preflight = build_verify_live_gate_preflight(
        profile=profile,
        record=record,
        provider=provider,
        env={LIVE_GATE_ENV: "1"},
        manual_real_sat=True,
        permit_ref="permit-synthetic",
        repo_root=Path.cwd(),
    )

    assert preflight.ready is False
    assert preflight.missing == ("missing-CFDI_VAULT_SAT_PRODUCTION_SIGNED",)


def test_verify_live_gate_preflight_requires_positive_read_timeout(tmp_path: Path) -> None:
    profile = _profile(tmp_path)
    record = _record()
    provider = DummySecretProvider({profile.phrase_ref: SYNTHETIC_PHRASE})

    preflight = build_verify_live_gate_preflight(
        profile=profile,
        record=record,
        provider=provider,
        env={LIVE_GATE_ENV: "1", PRODUCTION_SIGNED_ENV: "1"},
        manual_real_sat=True,
        permit_ref="permit-synthetic",
        read_timeout_seconds=0,
        repo_root=Path.cwd(),
    )

    assert preflight.ready is False
    assert preflight.missing == ("invalid-read-timeout",)


def test_verify_live_gate_preflight_rejects_read_timeout_above_documented_max(tmp_path: Path) -> None:
    profile = _profile(tmp_path)
    record = _record()
    provider = DummySecretProvider({profile.phrase_ref: SYNTHETIC_PHRASE})

    preflight = build_verify_live_gate_preflight(
        profile=profile,
        record=record,
        provider=provider,
        env={LIVE_GATE_ENV: "1", PRODUCTION_SIGNED_ENV: "1"},
        manual_real_sat=True,
        permit_ref="permit-synthetic",
        read_timeout_seconds=MAX_VERIFY_READ_TIMEOUT_SECONDS + 1,
        repo_root=Path.cwd(),
    )

    assert preflight.ready is False
    assert preflight.missing == ("read-timeout-too-large",)


def test_verify_gate_timeout_config_defaults_and_allows_gate_only_override() -> None:
    defaults = resolve_verify_gate_timeout_config(connect_timeout_seconds=None, read_timeout_seconds=None, env={})

    assert defaults.connect_timeout_seconds == DEFAULT_VERIFY_CONNECT_TIMEOUT_SECONDS
    assert defaults.read_timeout_seconds == DEFAULT_VERIFY_READ_TIMEOUT_SECONDS
    assert defaults.invalid == ()

    overridden = resolve_verify_gate_timeout_config(
        connect_timeout_seconds=15,
        read_timeout_seconds=180,
        env={"CFDI_VAULT_VERIFY_GATE_READ_TIMEOUT_SECONDS": "30"},
    )

    assert overridden.connect_timeout_seconds == 15
    assert overridden.read_timeout_seconds == 180
    assert overridden.invalid == ()


def test_verify_live_gate_preflight_accepts_configurable_connect_timeout(tmp_path: Path) -> None:
    profile = _profile(tmp_path)
    record = _record()
    provider = DummySecretProvider({profile.phrase_ref: SYNTHETIC_PHRASE})

    preflight = build_verify_live_gate_preflight(
        profile=profile,
        record=record,
        provider=provider,
        env={LIVE_GATE_ENV: "1", PRODUCTION_SIGNED_ENV: "1"},
        manual_real_sat=True,
        permit_ref="permit-synthetic",
        connect_timeout_seconds=15,
        read_timeout_seconds=180,
        repo_root=Path.cwd(),
    )

    assert preflight.ready is True
    assert preflight.connect_timeout_seconds == 15
    assert preflight.read_timeout_seconds == 180


def test_verify_wsdl_check_does_not_read_or_persist_raw_wsdl() -> None:
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

    result = check_verify_wsdl_endpoint(connect_timeout_seconds=15, opener=opener)

    assert result.status == "passed"
    assert result.reachable is True
    assert result.status_code == 200
    assert opener.timeout == 15
    assert opener.url.endswith("?wsdl")
    assert opener.response.read_called is False


def test_verify_oracle_parity_passes_with_synthetic_production_signed_shape(tmp_path: Path) -> None:
    profile = _profile(tmp_path)
    record = _record()
    provider = DummySecretProvider({profile.phrase_ref: SYNTHETIC_PHRASE})

    oracle = run_verify_oracle_parity(profile=profile, record=record, provider=provider)

    assert oracle.status == "passed"
    assert oracle.operation == "VerificaSolicitudDescarga"
    assert oracle.signature_placement == "inside_solicitud"
    assert oracle.signed_target == "operation_wrapper"
    assert oracle.x509_issuer_serial is True
    assert oracle.x509_certificate is True
    assert SYNTHETIC_RFC not in repr(oracle)
    assert SYNTHETIC_REQUEST_ID not in repr(oracle)


def test_cli_verify_live_gate_does_not_run_without_preflight() -> None:
    result = CliRunner().invoke(
        app,
        ["sat", "verify-live-gate", "--profile", "missing-profile"],
        env={LIVE_GATE_ENV: "0", PRODUCTION_SIGNED_ENV: "0"},
    )

    assert result.exit_code == 1
    assert "mode=verify-live-gate" in result.output
    assert "preflight_ready=no" in result.output
    assert "live_sat_executed=no" in result.output
    assert "oracle_parity=not-run" in result.output
    assert "raw_soap_persisted=no" in result.output
    assert "raw_response_persisted=no" in result.output
    assert "full_rfc_visible=no" in result.output
    assert "full_id_solicitud_visible=no" in result.output
    assert "download_executed=no" in result.output


def test_cli_verify_live_gate_blocks_signed_live_when_wsdl_check_fails(monkeypatch, tmp_path: Path) -> None:
    profile = _profile(tmp_path)
    record = _record()
    provider = DummySecretProvider({profile.phrase_ref: SYNTHETIC_PHRASE})

    monkeypatch.setattr("cfdi_vault.cli._load_download_profile_or_none", lambda profile_id: profile)
    monkeypatch.setattr("cfdi_vault.cli._setup_provider", lambda profile_id: provider)
    monkeypatch.setattr("cfdi_vault.cli._load_request_record_or_none", lambda loaded_profile, request_ref: record)
    monkeypatch.setattr(
        "cfdi_vault.cli.run_verify_oracle_parity",
        lambda **kwargs: VerifyOracleParityResult(status="passed", operation="VerificaSolicitudDescarga"),
    )
    monkeypatch.setattr(
        "cfdi_vault.cli.check_verify_wsdl_endpoint",
        lambda **kwargs: VerifyWsdlCheckResult(status="failed", reachable=False, error_kind="wsdl_unreachable"),
    )
    monkeypatch.setattr(
        "cfdi_vault.cli._run_live_metadata_verify_smoke",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("signed live verify must not run")),
    )

    result = CliRunner().invoke(
        app,
        [
            "sat",
            "verify-live-gate",
            "--profile",
            "dummy-profile",
            "--request-ref",
            "req-synthetic",
            "--manual-real-sat",
            "--permit",
            "permit-synthetic",
            "--connect-timeout-seconds",
            "15",
            "--read-timeout-seconds",
            "180",
        ],
        env={LIVE_GATE_ENV: "1", PRODUCTION_SIGNED_ENV: "1"},
    )

    assert result.exit_code == 1
    assert "oracle_parity=passed" in result.output
    assert "wsdl_check=failed" in result.output
    assert "wsdl_error_kind=wsdl_unreachable" in result.output
    assert "live_sat_executed=no" in result.output
    assert "raw_wsdl_persisted=no" in result.output
    assert "raw_soap_persisted=no" in result.output


def test_cli_verify_live_gate_requires_oracle_before_any_network(monkeypatch, tmp_path: Path) -> None:
    profile = _profile(tmp_path)
    record = _record()
    provider = DummySecretProvider({profile.phrase_ref: SYNTHETIC_PHRASE})

    monkeypatch.setattr("cfdi_vault.cli._load_download_profile_or_none", lambda profile_id: profile)
    monkeypatch.setattr("cfdi_vault.cli._setup_provider", lambda profile_id: provider)
    monkeypatch.setattr("cfdi_vault.cli._load_request_record_or_none", lambda loaded_profile, request_ref: record)
    monkeypatch.setattr(
        "cfdi_vault.cli.run_verify_oracle_parity",
        lambda **kwargs: VerifyOracleParityResult(status="failed", reason="synthetic-oracle-failure"),
    )
    monkeypatch.setattr(
        "cfdi_vault.cli.check_verify_wsdl_endpoint",
        lambda **kwargs: (_ for _ in ()).throw(AssertionError("wsdl check must not run after oracle failure")),
    )
    monkeypatch.setattr(
        "cfdi_vault.cli._run_live_metadata_verify_smoke",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("signed live verify must not run")),
    )

    result = CliRunner().invoke(
        app,
        [
            "sat",
            "verify-live-gate",
            "--profile",
            "dummy-profile",
            "--request-ref",
            "req-synthetic",
            "--manual-real-sat",
            "--permit",
            "permit-synthetic",
        ],
        env={LIVE_GATE_ENV: "1", PRODUCTION_SIGNED_ENV: "1"},
    )

    assert result.exit_code == 1
    assert "oracle_parity=failed" in result.output
    assert "wsdl_check=not-run" in result.output
    assert "live_sat_executed=no" in result.output


def test_verify_live_gate_prints_package_count_without_download_or_ids(tmp_path: Path, capsys) -> None:
    preflight = build_verify_live_gate_preflight(
        profile=_profile(tmp_path),
        record=_record(),
        provider=DummySecretProvider({"local-dev-dummy://phrase": SYNTHETIC_PHRASE}),
        env={LIVE_GATE_ENV: "1", PRODUCTION_SIGNED_ENV: "1"},
        manual_real_sat=True,
        permit_ref="permit-synthetic",
        repo_root=None,
    )
    oracle = VerifyOracleParityResult(
        status="passed",
        operation="VerificaSolicitudDescarga",
        namespace="http://DescargaMasivaTerceros.sat.gob.mx",
        signature_placement="inside_solicitud",
        signed_target="operation_wrapper",
        canonicalization="http://www.w3.org/2001/10/xml-exc-c14n#",
        x509_issuer_serial=True,
        x509_certificate=True,
    )
    result = LiveSmokeCliResult(
        result="metadata-verify-ok",
        auth="authenticated",
        verification="finished",
        sat_state="finished",
        package_count=2,
    )

    _print_verify_live_gate_result(
        profile_id="dummy-profile",
        preflight=preflight,
        oracle=oracle,
        result=result,
        live_executed=True,
        error_kind="",
    )

    output = capsys.readouterr().out
    assert "completed=yes" in output
    assert "ids_paquetes=present_count=2" in output
    assert "download_executed=no" in output
    assert "raw_soap_persisted=no" in output
    assert SYNTHETIC_REQUEST_ID not in output


def _profile(tmp_path: Path) -> setup_flow.LocalProfile:
    credentials = tmp_path / "credentials"
    storage = tmp_path / "storage"
    credentials.mkdir(parents=True, exist_ok=True)
    storage.mkdir(parents=True, exist_ok=True)
    certificate_path, private_key_path = _write_synthetic_efirma(credentials)
    return setup_flow.LocalProfile(
        profile_id="dummy-profile",
        rfc=SYNTHETIC_RFC,
        storage_root=storage,
        credential_mode=setup_flow.CredentialMode.COPIED,
        certificate_path=certificate_path,
        private_key_path=private_key_path,
        phrase_ref="local-dev-dummy://phrase",
        status=setup_flow.LocalProfileStatus.READY,
        certificate_fingerprint="a" * 64,
    )


def _record() -> LiveMetadataRequestRecord:
    return LiveMetadataRequestRecord(
        request_ref="req-synthetic",
        profile_id="dummy-profile",
        direction="received",
        kind="metadata",
        operation="SolicitaDescargaRecibidos",
        fecha_inicial="2024-01-01T00:00:00Z",
        fecha_final="2024-01-01T23:59:59Z",
        criteria_hash="a" * 64,
        id_solicitud=SYNTHETIC_REQUEST_ID,
        id_solicitud_redacted=SYNTHETIC_REQUEST_REDACTED,
        sat_code="5000",
        sat_message="accepted",
        created_at="2024-01-01T00:00:00Z",
        live=True,
        source_command="sat metadata-request-smoke",
        permit_id_hash="permit-hash",
        status="accepted",
    )


def _write_synthetic_efirma(directory: Path) -> tuple[Path, Path]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Synthetic SAT Verify Gate")])
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(private_key.public_key())
        .serial_number(1000)
        .not_valid_before(datetime(2024, 1, 1, tzinfo=timezone.utc))
        .not_valid_after(datetime(2030, 1, 1, tzinfo=timezone.utc))
        .sign(private_key, hashes.SHA256())
    )
    certificate_path = directory / "certificate.cer"
    private_key_path = directory / "private-key.key"
    certificate_path.write_bytes(certificate.public_bytes(serialization.Encoding.DER))
    private_key_path.write_bytes(
        private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.BestAvailableEncryption(SYNTHETIC_PHRASE.encode()),
        )
    )
    return certificate_path, private_key_path
