from __future__ import annotations

import base64
from datetime import datetime, timezone
from pathlib import Path
import ssl
from urllib.error import URLError

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
import pytest

from cfdi_vault.domain import DateTimePeriod, DownloadDirection, DownloadQuery, RequestType
from cfdi_vault.sat_live_smoke import SatEfirmMaterial, SatLiveMetadataSmokeAdapter, SatLiveSmokeEndpoints, SatLiveSmokeError
from cfdi_vault.sat_transport import FakeSoapTransport, SoapTransportResponse
from cfdi_vault.secrets import DummySecretProvider
from cfdi_vault.setup_core import CredentialMode, LocalProfile, LocalProfileStatus


def test_metadata_smoke_uses_real_adapter_shape_without_package_download(tmp_path: Path) -> None:
    responses = [
        SoapTransportResponse(200, body=_soap("<sat:AutenticaResult>SYNTHETIC_TOKEN</sat:AutenticaResult>")),
        SoapTransportResponse(200, body=_soap('<sat:SolicitaDescargaResult IdSolicitud="SYN-REQ-001" CodEstatus="5000" Mensaje="Accepted" />')),
        SoapTransportResponse(200, body=_soap('<sat:VerificaSolicitudDescargaResult CodEstatus="5000" EstadoSolicitud="2" Mensaje="Working" />')),
    ]
    transport = FakeSoapTransport(responses)
    endpoints = SatLiveSmokeEndpoints("https://auth.example", "https://request.example", "https://verify.example")

    result = SatLiveMetadataSmokeAdapter(
        profile=_profile(tmp_path), provider=DummySecretProvider(), transport=transport, material=_material(), endpoints=endpoints
    ).metadata_smoke(_query())

    assert (result.result, result.auth, result.request, result.verification) == ("metadata-smoke-ok", "authenticated", "accepted", "in_progress")
    assert [request.endpoint for request in transport.requests] == [endpoints.auth, endpoints.request, endpoints.verify]
    assert b"SolicitaDescarga" in transport.requests[1].body
    assert b'TipoSolicitud="Metadata"' in transport.requests[1].body
    assert b"VerificaSolicitudDescarga" in transport.requests[2].body
    assert "SYNTHETIC_TOKEN" not in repr(transport.requests[1])
    assert "SYN-REQ-001" not in repr(transport.requests[2])


def test_efirma_material_stays_out_of_tls_client_transport(tmp_path: Path) -> None:
    transport = FakeSoapTransport([SoapTransportResponse(200, body=_soap("<sat:AutenticaResult>SYNTHETIC_TOKEN</sat:AutenticaResult>"))])
    material = _material()

    SatLiveMetadataSmokeAdapter(
        profile=_profile(tmp_path),
        provider=DummySecretProvider(),
        transport=transport,
        material=material,
    ).auth_smoke()

    request = transport.requests[0]
    assert request.tls_verify is True
    assert request.client_tls_certificate is None
    assert request.timeout_seconds == 60
    assert b"BinarySecurityToken" in request.body
    assert material.certificate_pem.decode("ascii") not in repr(request)


def test_transport_failure_is_redacted(tmp_path: Path) -> None:
    class BrokenTransport:
        def send(self, _request: object) -> object:
            raise RuntimeError("raw transport detail")
    adapter = SatLiveMetadataSmokeAdapter(profile=_profile(tmp_path), provider=DummySecretProvider(), transport=BrokenTransport(), material=_material())
    with pytest.raises(SatLiveSmokeError, match="SAT transport failed") as exc:
        adapter.auth_smoke()
    diagnostic = exc.value.diagnostic
    assert diagnostic.stage == "auth_transport"
    assert diagnostic.error_kind == "unknown_live_adapter_failure"
    assert diagnostic.endpoint == "auth"
    assert diagnostic.envelope_sha256 is not None
    assert "raw transport detail" not in str(exc.value)


def test_http_failure_reports_only_safe_diagnostic_fields(tmp_path: Path) -> None:
    transport = FakeSoapTransport([SoapTransportResponse(500, body=b"<synthetic>server unavailable</synthetic>")])
    adapter = SatLiveMetadataSmokeAdapter(profile=_profile(tmp_path), provider=DummySecretProvider(), transport=transport, material=_material())
    with pytest.raises(SatLiveSmokeError, match="SAT transport returned a non-success status") as exc:
        adapter.auth_smoke()
    diagnostic = exc.value.diagnostic
    assert diagnostic.stage == "auth_transport"
    assert diagnostic.error_kind == "transport_http_error"
    assert diagnostic.http_status == 500
    assert diagnostic.payload_size == len(b"<synthetic>server unavailable</synthetic>")
    assert diagnostic.endpoint == "auth"
    assert diagnostic.transport_layer is None


@pytest.mark.parametrize(
    ("failure", "error_kind", "transport_layer"),
    [
        (ssl.SSLError("synthetic TLS failure"), "tls_handshake_failed", "tls"),
        (ssl.SSLCertVerificationError("synthetic CA failure"), "certificate_verify_failed", "tls"),
        (ssl.SSLError("tlsv13 alert certificate required"), "client_cert_rejected", "tls"),
        (TimeoutError("synthetic timeout"), "timeout", "network"),
        (ConnectionResetError("synthetic reset"), "connection_reset", "network"),
        (URLError(OSError("synthetic proxy tunnel failure")), "proxy_connect_failed", "proxy"),
    ],
)
def test_transport_exception_classification_is_specific_and_redacted(
    tmp_path: Path,
    failure: BaseException,
    error_kind: str,
    transport_layer: str,
) -> None:
    class BrokenTransport:
        def send(self, _request: object) -> object:
            raise failure

    adapter = SatLiveMetadataSmokeAdapter(profile=_profile(tmp_path), provider=DummySecretProvider(), transport=BrokenTransport(), material=_material())

    with pytest.raises(SatLiveSmokeError) as exc:
        adapter.auth_smoke()

    diagnostic = exc.value.diagnostic
    assert diagnostic.stage == "auth_transport"
    assert diagnostic.error_kind == error_kind
    assert diagnostic.transport_layer == transport_layer
    assert diagnostic.exception_class
    assert "synthetic" not in str(exc.value)


def test_missing_auth_authorization_reports_token_extract_stage(tmp_path: Path) -> None:
    transport = FakeSoapTransport([SoapTransportResponse(200, body=_soap("<sat:AutenticaResult />"))])
    adapter = SatLiveMetadataSmokeAdapter(profile=_profile(tmp_path), provider=DummySecretProvider(), transport=transport, material=_material())
    with pytest.raises(SatLiveSmokeError, match="SAT authentication response could not be parsed") as exc:
        adapter.auth_smoke()
    diagnostic = exc.value.diagnostic
    assert diagnostic.stage == "token_extract"
    assert diagnostic.error_kind == "token_missing"
    assert diagnostic.payload_size == len(_soap("<sat:AutenticaResult />"))


def _material() -> SatEfirmMaterial:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Synthetic SAT Smoke")])
    cert = x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(1000).not_valid_before(datetime(2024, 1, 1, tzinfo=timezone.utc)).not_valid_after(datetime(2030, 1, 1, tzinfo=timezone.utc)).sign(key, hashes.SHA256())
    cert_der = cert.public_bytes(serialization.Encoding.DER)
    return SatEfirmMaterial(key, cert.public_bytes(serialization.Encoding.PEM), base64.b64encode(cert_der).decode("ascii"))


def _profile(tmp_path: Path) -> LocalProfile:
    return LocalProfile("dummy-profile", "XAXX010101000", tmp_path / "storage", CredentialMode.COPIED, tmp_path / "certificate.cer", tmp_path / "private-key.key", "local-dev-dummy://phrase", LocalProfileStatus.READY, "a" * 64)


def _query() -> DownloadQuery:
    return DownloadQuery("default", "XAXX010101000", DownloadDirection.RECEIVED, RequestType.METADATA, DateTimePeriod(datetime(2024, 1, 1, tzinfo=timezone.utc), datetime(2024, 1, 1, 23, 59, tzinfo=timezone.utc)))


def _soap(body: str) -> bytes:
    return f'<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:sat="http://DescargaMasivaTerceros.sat.gob.mx"><soap:Body>{body}</soap:Body></soap:Envelope>'.encode()
