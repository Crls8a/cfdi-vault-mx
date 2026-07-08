from __future__ import annotations

import base64
from datetime import datetime, timezone
import hashlib
from pathlib import Path
import ssl
from urllib.error import URLError

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from lxml import etree
import pytest

from cfdi_vault.domain import DateTimePeriod, DownloadDirection, DownloadQuery, RequestType
from cfdi_vault.sat_auth_contract import AuthWsdlContract
from cfdi_vault.sat_auth_constants import (
    AUTH_ENVELOPE_VARIANT_ACTION_BEFORE_SECURITY,
    AUTH_ENVELOPE_VARIANT_SECURITY_BEFORE_ACTION,
)
from cfdi_vault.sat_auth_envelope_lint import lint_auth_envelope
from cfdi_vault.sat_auth_http import validate_auth_headers_for_contract
from cfdi_vault.sat_live_smoke import (
    AUTH_ACTION,
    DEFAULT_VERIFY_ENDPOINT,
    DS_NS,
    SAT_REQUEST_NS,
    SatEfirmMaterial,
    SatLiveMetadataSmokeAdapter,
    SatLiveSmokeEndpoints,
    SatLiveSmokeError,
    SatV15RequestOperation,
    VERIFY_ACTION,
    VERIFY_EXCLUSIVE_C14N,
    _build_request_envelope,
    resolve_v15_request_operation,
    v15_request_soap_action,
)
from cfdi_vault.sat_transport import FakeSoapTransport, SoapTransportResponse
from cfdi_vault.secrets import DummySecretProvider
from cfdi_vault.setup_core import CredentialMode, LocalProfile, LocalProfileStatus


def test_metadata_smoke_uses_real_adapter_shape_without_package_download(tmp_path: Path) -> None:
    responses = [
        SoapTransportResponse(200, body=_soap("<sat:AutenticaResult>SYNTHETIC_TOKEN</sat:AutenticaResult>")),
        SoapTransportResponse(200, body=_soap('<sat:SolicitaDescargaRecibidosResult IdSolicitud="SYN-REQ-001" CodEstatus="5000" Mensaje="Accepted" />')),
        SoapTransportResponse(200, body=_soap('<sat:VerificaSolicitudDescargaResult CodEstatus="5000" EstadoSolicitud="2" Mensaje="Working" />')),
    ]
    transport = FakeSoapTransport(responses)
    endpoints = SatLiveSmokeEndpoints("https://auth.example", "https://request.example", DEFAULT_VERIFY_ENDPOINT)

    result = SatLiveMetadataSmokeAdapter(
        profile=_profile(tmp_path), provider=DummySecretProvider(), transport=transport, material=_material(), endpoints=endpoints
    ).metadata_smoke(_query())

    assert (result.result, result.auth, result.request, result.verification) == ("metadata-smoke-ok", "authenticated", "accepted", "in_progress")
    assert result.operation == "SolicitaDescargaRecibidos"
    assert result.id_solicitud_redacted == "SYN-...-001"
    assert result.request_body_bytes_len is not None
    assert result.envelope_sha256 is not None
    assert result.signed_reference_count == 1
    assert [request.endpoint for request in transport.requests] == [endpoints.auth, endpoints.request, endpoints.verify]
    assert transport.requests[1].headers["SOAPAction"] == '"http://DescargaMasivaTerceros.sat.gob.mx/ISolicitaDescargaService/SolicitaDescargaRecibidos"'
    assert _body_operation_names(transport.requests[1].body) == ["SolicitaDescargaRecibidos"]
    assert "SolicitaDescarga" not in _body_operation_names(transport.requests[1].body)
    assert b'TipoSolicitud="Metadata"' in transport.requests[1].body
    assert b'RfcReceptor="XAXX010101000"' in transport.requests[1].body
    assert b"VerificaSolicitudDescarga" in transport.requests[2].body
    assert "SYNTHETIC_TOKEN" not in repr(transport.requests[1])
    assert "SYN-REQ-001" not in repr(transport.requests[2])


def test_metadata_request_smoke_does_not_verify_or_download(tmp_path: Path) -> None:
    responses = [
        SoapTransportResponse(200, body=_soap("<sat:AutenticaResult>SYNTHETIC_TOKEN</sat:AutenticaResult>")),
        SoapTransportResponse(200, body=_soap('<sat:SolicitaDescargaRecibidosResult IdSolicitud="SYN-REQ-002" CodEstatus="5000" Mensaje="Accepted" />')),
    ]
    transport = FakeSoapTransport(responses)

    result = SatLiveMetadataSmokeAdapter(
        profile=_profile(tmp_path), provider=DummySecretProvider(), transport=transport, material=_material()
    ).metadata_request_smoke(_query())

    assert (result.result, result.request, result.verification) == ("metadata-request-submitted", "accepted", "not_run")
    assert result.operation == "SolicitaDescargaRecibidos"
    assert result.id_solicitud_redacted == "SYN-...-002"
    assert result.id_solicitud == "SYN-REQ-002"
    assert "SYN-REQ-002" not in repr(result)
    assert len(transport.requests) == 2


def test_metadata_request_smoke_allows_explicit_weekly_backfill_range(tmp_path: Path) -> None:
    responses = [
        SoapTransportResponse(200, body=_soap("<sat:AutenticaResult>SYNTHETIC_TOKEN</sat:AutenticaResult>")),
        SoapTransportResponse(200, body=_soap('<sat:SolicitaDescargaRecibidosResult IdSolicitud="SYN-REQ-003" CodEstatus="5000" Mensaje="Accepted" />')),
    ]
    transport = FakeSoapTransport(responses)
    query = DownloadQuery(
        "default",
        "XAXX010101000",
        DownloadDirection.RECEIVED,
        RequestType.METADATA,
        DateTimePeriod(
            datetime(2026, 1, 1, tzinfo=timezone.utc),
            datetime(2026, 1, 7, 23, 59, 59, tzinfo=timezone.utc),
        ),
    )

    result = SatLiveMetadataSmokeAdapter(
        profile=_profile(tmp_path), provider=DummySecretProvider(), transport=transport, material=_material()
    ).metadata_request_smoke(query, max_range_days=7)

    assert (result.result, result.request, result.verification) == ("metadata-request-submitted", "accepted", "not_run")
    assert result.operation == "SolicitaDescargaRecibidos"
    assert len(transport.requests) == 2
    assert _body_operation_names(transport.requests[1].body) == ["SolicitaDescargaRecibidos"]


def test_package_download_uses_download_endpoint_without_request_or_verify(tmp_path: Path) -> None:
    payload = base64.b64encode(b"SYNTHETIC-ZIP-BYTES").decode("ascii")
    responses = [
        SoapTransportResponse(200, body=_soap("<sat:AutenticaResult>SYNTHETIC_TOKEN</sat:AutenticaResult>")),
        SoapTransportResponse(200, body=_soap(f'<sat:DescargaResult IdPaquete="SYN-PKG-001" CodEstatus="5000">{payload}</sat:DescargaResult>')),
    ]
    transport = FakeSoapTransport(responses)

    result = SatLiveMetadataSmokeAdapter(
        profile=_profile(tmp_path), provider=DummySecretProvider(), transport=transport, material=_material()
    ).download_package("SYN-PKG-001")

    assert result.package_id == "SYN-PKG-001"
    assert result.content == b"SYNTHETIC-ZIP-BYTES"
    assert [request.endpoint for request in transport.requests] == [
        "https://cfdidescargamasivasolicitud.clouda.sat.gob.mx/Autenticacion/Autenticacion.svc",
        "https://cfdidescargamasiva.clouda.sat.gob.mx/DescargaMasivaService.svc",
    ]
    assert transport.requests[1].headers["SOAPAction"] == '"http://DescargaMasivaTerceros.sat.gob.mx/IDescargaMasivaTercerosService/Descargar"'
    assert _body_operation_names(transport.requests[1].body) == ["Descargar"]
    assert "SYNTHETIC_TOKEN" not in repr(transport.requests[1])


def test_metadata_verify_smoke_uses_stored_request_id_without_new_request_or_download(tmp_path: Path) -> None:
    responses = [
        SoapTransportResponse(200, body=_soap("<sat:AutenticaResult>SYNTHETIC_TOKEN</sat:AutenticaResult>")),
        SoapTransportResponse(200, body=_soap('<sat:VerificaSolicitudDescargaResult CodEstatus="5000" EstadoSolicitud="2" Mensaje="Working" />')),
    ]
    transport = FakeSoapTransport(responses)

    result = SatLiveMetadataSmokeAdapter(
        profile=_profile(tmp_path), provider=DummySecretProvider(), transport=transport, material=_material()
    ).metadata_verify_smoke("648a0000-1111-2222-3333-444444447b27")

    assert (result.result, result.auth, result.request, result.verification) == ("metadata-verify-ok", "authenticated", "not_run", "in_progress")
    assert result.operation == "VerificaSolicitudDescarga"
    assert result.id_solicitud_redacted == "648a...7b27"
    assert result.sat_state == "in_process"
    assert result.package_count == 0
    assert len(transport.requests) == 2
    assert b"SolicitaDescarga" not in transport.requests[1].body
    assert b"VerificaSolicitudDescarga" in transport.requests[1].body
    assert "648a0000-1111-2222-3333-444444447b27" not in repr(result)
    assert "SYNTHETIC_TOKEN" not in repr(transport.requests[1])


def test_metadata_verify_smoke_reports_finished_packages_without_download(tmp_path: Path) -> None:
    responses = [
        SoapTransportResponse(200, body=_soap("<sat:AutenticaResult>SYNTHETIC_TOKEN</sat:AutenticaResult>")),
        SoapTransportResponse(
            200,
            body=_soap(
                """
                <sat:VerificaSolicitudDescargaResult IdSolicitud="SYN-REQ-003" CodEstatus="5000" EstadoSolicitud="3" Mensaje="Finished">
                  <sat:IdsPaquetes>
                    <sat:IdPaquete>SYN-PKG-001</sat:IdPaquete>
                    <sat:IdPaquete>SYN-PKG-002</sat:IdPaquete>
                  </sat:IdsPaquetes>
                </sat:VerificaSolicitudDescargaResult>
                """
            ),
        ),
    ]
    transport = FakeSoapTransport(responses)

    result = SatLiveMetadataSmokeAdapter(
        profile=_profile(tmp_path), provider=DummySecretProvider(), transport=transport, material=_material()
    ).metadata_verify_smoke("648a0000-1111-2222-3333-444444447b27")

    assert (result.result, result.auth, result.request, result.verification) == ("metadata-verify-ok", "authenticated", "not_run", "finished")
    assert result.sat_state == "finished"
    assert result.package_count == 2
    assert len(transport.requests) == 2
    assert transport.requests[1].endpoint == DEFAULT_VERIFY_ENDPOINT


def test_metadata_verify_smoke_sends_ready_verify_post_without_sensitive_repr(tmp_path: Path) -> None:
    responses = [
        SoapTransportResponse(200, body=_soap("<sat:AutenticaResult>SYNTHETIC_TOKEN</sat:AutenticaResult>")),
        SoapTransportResponse(200, body=_soap('<sat:VerificaSolicitudDescargaResult CodEstatus="5000" EstadoSolicitud="2" Mensaje="Working" />')),
    ]
    transport = FakeSoapTransport(responses)

    SatLiveMetadataSmokeAdapter(
        profile=_profile(tmp_path), provider=DummySecretProvider(), transport=transport, material=_material()
    ).metadata_verify_smoke("648a0000-1111-2222-3333-444444447b27")

    verify_request = transport.requests[1]
    assert verify_request.endpoint == DEFAULT_VERIFY_ENDPOINT
    assert verify_request.headers["SOAPAction"] == f'"{VERIFY_ACTION}"'
    assert verify_request.headers["Content-Type"] == "text/xml; charset=utf-8"
    assert verify_request.headers["Authorization"].startswith('WRAP access_token="')
    assert "SYNTHETIC_TOKEN" not in repr(verify_request)
    assert b"VerificaSolicitudDescarga" in verify_request.body
    assert b"IdSolicitud" in verify_request.body
    assert b"RfcSolicitante" in verify_request.body
    assert b"Signature" in verify_request.body
    assert b"None" not in verify_request.body
    assert b"TODO" not in verify_request.body

    root = etree.fromstring(verify_request.body)
    body = root.find("{http://schemas.xmlsoap.org/soap/envelope/}Body")
    assert body is not None
    operation = body.find(f"{{{SAT_REQUEST_NS}}}VerificaSolicitudDescarga")
    assert operation is not None
    solicitud = operation.find(f"{{{SAT_REQUEST_NS}}}solicitud")
    assert solicitud is not None
    signature = solicitud.find(f"{{{DS_NS}}}Signature")
    assert signature is not None
    signed_info = signature.find(f"{{{DS_NS}}}SignedInfo")
    assert signed_info is not None
    assert signed_info.find(f"{{{DS_NS}}}CanonicalizationMethod").get("Algorithm") == VERIFY_EXCLUSIVE_C14N
    reference = signed_info.find(f"{{{DS_NS}}}Reference")
    assert reference is not None
    assert reference.get("URI") == ""
    transforms = tuple(node.get("Algorithm") for node in reference.findall(f".//{{{DS_NS}}}Transform"))
    assert transforms == (VERIFY_EXCLUSIVE_C14N,)
    assert signature.find(f".//{{{DS_NS}}}X509IssuerSerial") is not None
    assert signature.find(f".//{{{DS_NS}}}X509Certificate") is not None


def test_metadata_verify_smoke_fails_before_verify_transport_when_endpoint_is_wrong(tmp_path: Path) -> None:
    transport = FakeSoapTransport(
        [SoapTransportResponse(200, body=_soap("<sat:AutenticaResult>SYNTHETIC_TOKEN</sat:AutenticaResult>"))]
    )
    endpoints = SatLiveSmokeEndpoints("https://auth.example", "https://request.example", "https://request.example")

    with pytest.raises(SatLiveSmokeError) as exc:
        SatLiveMetadataSmokeAdapter(
            profile=_profile(tmp_path), provider=DummySecretProvider(), transport=transport, material=_material(), endpoints=endpoints
        ).metadata_verify_smoke("648a0000-1111-2222-3333-444444447b27")

    diagnostic = exc.value.diagnostic
    assert diagnostic.stage == "verify_request_readiness"
    assert diagnostic.error_kind == "client_configuration_error"
    assert diagnostic.endpoint_url_ok is False
    assert diagnostic.has_authorization is True
    assert diagnostic.authorization_value_len == len("SYNTHETIC_TOKEN")
    assert diagnostic.has_id_solicitud is True
    assert diagnostic.id_solicitud_redacted == "648a...7b27"
    assert diagnostic.has_rfc_solicitante is True
    assert diagnostic.has_signature is True
    assert len(transport.requests) == 1


def test_metadata_verify_timeout_is_classified_with_redacted_readiness(tmp_path: Path) -> None:
    class TimeoutOnVerifyTransport(FakeSoapTransport):
        def send(self, request):
            self.requests.append(request)
            if len(self.requests) == 2:
                raise TimeoutError("synthetic timeout")
            return SoapTransportResponse(200, body=_soap("<sat:AutenticaResult>SYNTHETIC_TOKEN</sat:AutenticaResult>"))

    transport = TimeoutOnVerifyTransport()

    with pytest.raises(SatLiveSmokeError) as exc:
        SatLiveMetadataSmokeAdapter(
            profile=_profile(tmp_path), provider=DummySecretProvider(), transport=transport, material=_material()
        ).metadata_verify_smoke("648a0000-1111-2222-3333-444444447b27")

    diagnostic = exc.value.diagnostic
    assert diagnostic.stage == "verify_transport"
    assert diagnostic.error_kind == "verify_read_timeout"
    assert diagnostic.has_authorization is True
    assert diagnostic.authorization_value_len == len("SYNTHETIC_TOKEN")
    assert diagnostic.has_id_solicitud is True
    assert diagnostic.id_solicitud_redacted == "648a...7b27"
    assert diagnostic.has_signature is True
    assert "SYNTHETIC_TOKEN" not in repr(diagnostic)
    assert "648a0000-1111-2222-3333-444444447b27" not in repr(diagnostic)
    assert len(transport.requests) == 2


def test_v15_request_operation_routing_has_no_legacy_fallback() -> None:
    issued = DownloadQuery(
        "default",
        "XAXX010101000",
        DownloadDirection.ISSUED,
        RequestType.METADATA,
        DateTimePeriod(datetime(2024, 1, 1, tzinfo=timezone.utc), datetime(2024, 1, 1, 0, 0, 2, tzinfo=timezone.utc)),
    )
    folio = DownloadQuery("default", "XAXX010101000", DownloadDirection.FOLIO, RequestType.METADATA, uuid="SYNTHETIC-UUID")

    assert resolve_v15_request_operation(_query()) == SatV15RequestOperation.RECEIVED
    assert resolve_v15_request_operation(issued) == SatV15RequestOperation.ISSUED
    assert resolve_v15_request_operation(folio) == SatV15RequestOperation.FOLIO
    assert v15_request_soap_action(SatV15RequestOperation.RECEIVED).endswith("/SolicitaDescargaRecibidos")


def test_v15_request_builder_emits_operation_specific_payloads() -> None:
    material = _material()
    issued = DownloadQuery(
        "default",
        "XAXX010101000",
        DownloadDirection.ISSUED,
        RequestType.METADATA,
        DateTimePeriod(datetime(2024, 1, 1, tzinfo=timezone.utc), datetime(2024, 1, 1, 0, 0, 2, tzinfo=timezone.utc)),
    )
    folio = DownloadQuery("default", "XAXX010101000", DownloadDirection.FOLIO, RequestType.METADATA, uuid="SYNTHETIC-UUID")

    assert _body_operation_names(_build_request_envelope(_query(), material)) == ["SolicitaDescargaRecibidos"]
    assert _body_operation_names(_build_request_envelope(issued, material)) == ["SolicitaDescargaEmitidos"]
    assert _body_operation_names(_build_request_envelope(folio, material)) == ["SolicitaDescargaFolio"]


@pytest.mark.parametrize(
    ("start", "end", "safe_hint"),
    [
        (datetime(2024, 1, 1, tzinfo=timezone.utc), datetime(2024, 1, 1, tzinfo=timezone.utc), "fecha-inicial-must-be-before-fecha-final"),
        (datetime(2024, 1, 1, tzinfo=timezone.utc), datetime(2024, 1, 1, 0, 0, 1, tzinfo=timezone.utc), "minimum-two-second-range-required"),
        (datetime(2024, 1, 1, tzinfo=timezone.utc), datetime(2024, 1, 2, 0, 0, 1, tzinfo=timezone.utc), "range-too-wide"),
    ],
)
def test_v15_live_metadata_date_rules_fail_before_transport(
    tmp_path: Path,
    start: datetime,
    end: datetime,
    safe_hint: str,
) -> None:
    query = DownloadQuery("default", "XAXX010101000", DownloadDirection.RECEIVED, RequestType.METADATA, DateTimePeriod(start, end))
    transport = FakeSoapTransport([])
    adapter = SatLiveMetadataSmokeAdapter(profile=_profile(tmp_path), provider=DummySecretProvider(), transport=transport, material=_material())

    with pytest.raises(SatLiveSmokeError) as exc:
        adapter.metadata_request_smoke(query)

    assert exc.value.failed_stage == "preflight"
    assert exc.value.error_kind == "guard_failed"
    assert exc.value.diagnostic.safe_hint == safe_hint
    assert transport.requests == []


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
    assert request.connect_timeout_seconds is None
    assert request.read_timeout_seconds is None
    assert b"BinarySecurityToken" in request.body
    assert material.certificate_pem.decode("ascii") not in repr(request)


def test_gate_only_adapter_can_pass_separate_connect_and_read_timeouts(tmp_path: Path) -> None:
    transport = FakeSoapTransport([SoapTransportResponse(200, body=_soap("<sat:AutenticaResult>SYNTHETIC_TOKEN</sat:AutenticaResult>"))])

    SatLiveMetadataSmokeAdapter(
        profile=_profile(tmp_path),
        provider=DummySecretProvider(),
        transport=transport,
        material=_material(),
        timeout_seconds=180,
        connect_timeout_seconds=15,
        read_timeout_seconds=180,
    ).auth_smoke()

    request = transport.requests[0]
    assert request.timeout_seconds == 180
    assert request.connect_timeout_seconds == 15
    assert request.read_timeout_seconds == 180


def test_auth_smoke_headers_match_soap11_contract_without_sensitive_headers(tmp_path: Path) -> None:
    transport = FakeSoapTransport([SoapTransportResponse(200, body=_soap("<sat:AutenticaResult>SYNTHETIC_TOKEN</sat:AutenticaResult>"))])

    SatLiveMetadataSmokeAdapter(
        profile=_profile(tmp_path),
        provider=DummySecretProvider(),
        transport=transport,
        material=_material(),
    ).auth_smoke()

    request = transport.requests[0]
    result = validate_auth_headers_for_contract(request.headers, _auth_contract(), body=request.body)
    assert result.all_checks_passed is True
    assert request.headers["Content-Type"] == "text/xml; charset=utf-8"
    assert request.headers["SOAPAction"] == f'"{AUTH_ACTION}"'
    assert request.headers["Accept"] == "text/xml"
    assert "Authorization" not in request.headers


def test_auth_smoke_uses_explicit_security_before_action_variant(tmp_path: Path) -> None:
    transport = FakeSoapTransport([SoapTransportResponse(200, body=_soap("<sat:AutenticaResult>SYNTHETIC_TOKEN</sat:AutenticaResult>"))])

    SatLiveMetadataSmokeAdapter(
        profile=_profile(tmp_path),
        provider=DummySecretProvider(),
        transport=transport,
        material=_material(),
        auth_envelope_variant=AUTH_ENVELOPE_VARIANT_SECURITY_BEFORE_ACTION,
    ).auth_smoke()

    request = transport.requests[0]
    result = lint_auth_envelope(request.body, expected_header_action_order=AUTH_ENVELOPE_VARIANT_SECURITY_BEFORE_ACTION)
    assert result.all_checks_passed is True
    assert result.header_action_order == AUTH_ENVELOPE_VARIANT_SECURITY_BEFORE_ACTION
    assert result.action_header_before_security is False
    assert result.action_header_order_ok is True
    assert "<soap" not in repr(result)
    assert "SignatureValue" not in repr(result)


def test_auth_smoke_fails_before_transport_when_request_body_is_empty(tmp_path: Path) -> None:
    class EmptyAuthEnvelopeAdapter(SatLiveMetadataSmokeAdapter):
        def _load_material(self) -> SatEfirmMaterial:
            return _material()

    transport = FakeSoapTransport([])
    adapter = EmptyAuthEnvelopeAdapter(profile=_profile(tmp_path), provider=DummySecretProvider(), transport=transport, material=_material())

    with pytest.MonkeyPatch.context() as monkeypatch:
        monkeypatch.setattr("cfdi_vault.sat_live_smoke._build_auth_envelope", lambda *_args, **_kwargs: b"")
        with pytest.raises(SatLiveSmokeError, match="SAT auth request failed local readiness checks") as exc:
            adapter.auth_smoke()

    diagnostic = exc.value.diagnostic
    assert diagnostic.stage == "auth_request_readiness"
    assert diagnostic.error_kind == "client_configuration_error"
    assert diagnostic.request_body_bytes_len == 0
    assert diagnostic.payload_size == 0
    assert diagnostic.envelope_sha256 is not None
    assert diagnostic.soap_action == f'"{AUTH_ACTION}"'
    assert diagnostic.content_type == "text/xml; charset=utf-8"
    assert diagnostic.has_ws_security is False
    assert transport.requests == []


def test_auth_smoke_fails_before_transport_when_accept_header_is_missing(tmp_path: Path) -> None:
    transport = FakeSoapTransport([])
    adapter = SatLiveMetadataSmokeAdapter(
        profile=_profile(tmp_path),
        provider=DummySecretProvider(),
        transport=transport,
        material=_material(),
        auth_envelope_variant=AUTH_ENVELOPE_VARIANT_ACTION_BEFORE_SECURITY,
    )

    def headers_without_accept(action: str) -> dict[str, str]:
        return {"Content-Type": "text/xml; charset=utf-8", "SOAPAction": f'"{action}"'}

    with pytest.MonkeyPatch.context() as monkeypatch:
        monkeypatch.setattr("cfdi_vault.sat_live_smoke.build_soap11_headers", headers_without_accept)
        with pytest.raises(SatLiveSmokeError, match="SAT auth request failed local readiness checks") as exc:
            adapter.auth_smoke()

    diagnostic = exc.value.diagnostic
    assert diagnostic.stage == "auth_request_readiness"
    assert diagnostic.request_body_bytes_len is not None
    assert diagnostic.request_body_bytes_len > 500
    assert transport.requests == []


def test_auth_smoke_fails_before_transport_when_wcf_action_header_is_missing(tmp_path: Path) -> None:
    transport = FakeSoapTransport([])
    adapter = SatLiveMetadataSmokeAdapter(
        profile=_profile(tmp_path),
        provider=DummySecretProvider(),
        transport=transport,
        material=_material(),
        auth_envelope_variant=AUTH_ENVELOPE_VARIANT_ACTION_BEFORE_SECURITY,
    )
    from cfdi_vault import sat_live_smoke as live_smoke_module
    original_build_auth_envelope = live_smoke_module._build_auth_envelope

    def envelope_without_action(*args: object, **kwargs: object) -> bytes:
        envelope = original_build_auth_envelope(*args, **kwargs)
        root = etree.fromstring(envelope)
        action = root.find(".//{http://schemas.microsoft.com/ws/2005/05/addressing/none}Action")
        assert action is not None
        action.getparent().remove(action)
        return etree.tostring(root, encoding="UTF-8", xml_declaration=True)

    with pytest.MonkeyPatch.context() as monkeypatch:
        monkeypatch.setattr(live_smoke_module, "_build_auth_envelope", envelope_without_action)
        with pytest.raises(SatLiveSmokeError, match="SAT auth request failed local readiness checks") as exc:
            adapter.auth_smoke()

    diagnostic = exc.value.diagnostic
    assert diagnostic.stage == "auth_request_readiness"
    assert diagnostic.has_header_action is False
    assert diagnostic.header_action_order == "security_only"
    assert transport.requests == []


def test_auth_http_failure_reports_redacted_request_readiness(tmp_path: Path) -> None:
    transport = FakeSoapTransport([SoapTransportResponse(400, body=b"")])
    adapter = SatLiveMetadataSmokeAdapter(profile=_profile(tmp_path), provider=DummySecretProvider(), transport=transport, material=_material())

    with pytest.raises(SatLiveSmokeError, match="SAT transport returned a non-success status") as exc:
        adapter.auth_smoke()

    request = transport.requests[0]
    diagnostic = exc.value.diagnostic
    assert diagnostic.stage == "auth_transport"
    assert diagnostic.error_kind == "http_status_error"
    assert diagnostic.http_status == 400
    assert diagnostic.payload_size == 0
    assert diagnostic.request_body_bytes_len == len(request.body)
    assert diagnostic.request_body_bytes_len > 500
    assert diagnostic.envelope_sha256 == hashlib.sha256(request.body).hexdigest()
    assert diagnostic.soap_action == f'"{AUTH_ACTION}"'
    assert diagnostic.content_type == "text/xml; charset=utf-8"
    assert diagnostic.timestamp_window_seconds == 300
    assert diagnostic.has_ws_security is True
    assert diagnostic.has_bst is True
    assert diagnostic.cert_der_bytes_len is not None
    assert diagnostic.cert_der_bytes_len > 0
    assert diagnostic.signature_method == "http://www.w3.org/2000/09/xmldsig#rsa-sha1"
    assert diagnostic.digest_method == "http://www.w3.org/2000/09/xmldsig#sha1"
    assert diagnostic.signed_reference_count >= 1
    assert diagnostic.signed_reference_targets_exist is True
    assert diagnostic.has_header_action is False
    assert diagnostic.header_action_value_ok is False
    assert diagnostic.header_action_must_understand is False
    assert diagnostic.header_action_order == "security_only"
    assert diagnostic.security_must_understand is True


def test_transport_failure_is_redacted(tmp_path: Path) -> None:
    class BrokenTransport:
        def send(self, _request: object) -> object:
            raise RuntimeError("raw transport detail")
    adapter = SatLiveMetadataSmokeAdapter(profile=_profile(tmp_path), provider=DummySecretProvider(), transport=BrokenTransport(), material=_material())
    with pytest.raises(SatLiveSmokeError, match="SAT transport failed") as exc:
        adapter.auth_smoke()
    diagnostic = exc.value.diagnostic
    assert diagnostic.stage == "auth_transport"
    assert diagnostic.error_kind == "client_configuration_error"
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
    assert diagnostic.error_kind == "http_status_error"
    assert diagnostic.http_status == 500
    assert diagnostic.payload_size == len(b"<synthetic>server unavailable</synthetic>")
    assert diagnostic.endpoint == "auth"
    assert diagnostic.transport_layer is None


def test_http_fault_failure_is_not_classified_as_tls(tmp_path: Path) -> None:
    transport = FakeSoapTransport([SoapTransportResponse(500, body=_soap("<soap:Fault />"))])
    adapter = SatLiveMetadataSmokeAdapter(profile=_profile(tmp_path), provider=DummySecretProvider(), transport=transport, material=_material())

    with pytest.raises(SatLiveSmokeError, match="SAT transport returned a non-success status") as exc:
        adapter.auth_smoke()

    diagnostic = exc.value.diagnostic
    assert diagnostic.error_kind == "soap_fault"
    assert diagnostic.http_status == 500
    assert diagnostic.transport_layer is None


@pytest.mark.parametrize(
    ("failure", "error_kind", "transport_layer"),
    [
        (ssl.SSLError("synthetic TLS failure"), "tls_handshake_failed", "tls"),
        (ssl.SSLCertVerificationError("synthetic CA failure"), "certificate_verify_failed", "tls"),
        (ssl.SSLError("tlsv13 alert certificate required"), "client_cert_rejected", "tls"),
        (TimeoutError("synthetic timeout"), "timeout", "network"),
        (ConnectionResetError("synthetic reset"), "connection_reset_during_post", "network"),
        (URLError(OSError("synthetic remote end closed connection")), "remote_closed_connection", "network"),
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


def _auth_contract() -> AuthWsdlContract:
    return AuthWsdlContract(
        operation_name="Autentica",
        soap_action=AUTH_ACTION,
        soap_version="1.1",
        binding_transport="http://schemas.xmlsoap.org/soap/http",
        target_namespace="http://DescargaMasivaTerceros.gob.mx",
        endpoint_scheme="https",
        endpoint_host="auth.example.test",
        endpoint_port=443,
        endpoint_path="/Autenticacion/Autenticacion.svc",
        expected_action_uri=AUTH_ACTION,
        wsdl_size=123,
    )


def _body_operation_names(body: bytes) -> list[str]:
    root = etree.fromstring(body)
    soap_body = root.find("{http://schemas.xmlsoap.org/soap/envelope/}Body")
    assert soap_body is not None
    return [etree.QName(child).localname for child in soap_body]


def _soap(body: str) -> bytes:
    return f'<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:sat="http://DescargaMasivaTerceros.sat.gob.mx"><soap:Body>{body}</soap:Body></soap:Envelope>'.encode()
