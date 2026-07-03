from __future__ import annotations

import base64
from datetime import datetime, timezone
from pathlib import Path

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
