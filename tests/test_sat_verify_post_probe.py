from __future__ import annotations

from contextlib import contextmanager
from http.client import RemoteDisconnected
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Iterator, Mapping
from urllib.error import URLError
import socket
import ssl
import threading
import time

from cfdi_vault.sat_live_smoke import DEFAULT_VERIFY_ENDPOINT, VERIFY_ACTION
from cfdi_vault.sat_verify_post_probe import (
    VERIFY_POST_PROBE_BODY,
    VERIFY_POST_PROBE_ENVELOPE_SOURCES,
    VERIFY_POST_PROBE_HEADERS,
    VERIFY_POST_PROBE_VARIANTS,
    VerifyPostProbeHttpResponse,
    VerifyPostProbeTransportError,
    build_verify_post_probe_envelope,
    build_verify_post_probe_headers,
    run_sat_verify_post_probe,
)


SOAP_OK = b'''<?xml version="1.0"?><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><ok /></soap:Body></soap:Envelope>'''
SOAP_FAULT = b'''<?xml version="1.0"?><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><soap:Fault><faultcode>soap:Client</faultcode></soap:Fault></soap:Body></soap:Envelope>'''


class FakeVerifyPostClient:
    def __init__(self, *, response: VerifyPostProbeHttpResponse | None = None, error: BaseException | None = None) -> None:
        self.response = response or VerifyPostProbeHttpResponse(500, b"synthetic server error")
        self.error = error
        self.calls: list[tuple[str, bytes, Mapping[str, str], float, float]] = []

    def post(
        self,
        url: str,
        body: bytes,
        headers: Mapping[str, str],
        connect_timeout_seconds: float,
        read_timeout_seconds: float,
    ) -> VerifyPostProbeHttpResponse:
        self.calls.append((url, body, headers, connect_timeout_seconds, read_timeout_seconds))
        if self.error is not None:
            raise self.error
        return self.response


def test_verify_post_probe_fake_server_200_soap_is_reached_without_raw_body() -> None:
    with _fake_server(status=200, body=SOAP_OK) as endpoint:
        result = run_sat_verify_post_probe(endpoint=endpoint, connect_timeout_seconds=1, read_timeout_seconds=1)

    assert result.status == "ok"
    assert result.error_kind == "none"
    assert result.http_status == 200
    assert result.response_received is True
    assert result.post_attempted is True
    assert result.soap_fault_detected is False
    assert result.request_size_bytes == len(VERIFY_POST_PROBE_BODY)
    assert result.response_size_bytes == len(SOAP_OK)
    assert result.raw_soap_printed is False
    assert "Envelope" not in repr(result)


def test_verify_post_probe_fake_server_soap_fault_is_diagnostic_success() -> None:
    with _fake_server(status=500, body=SOAP_FAULT) as endpoint:
        result = run_sat_verify_post_probe(endpoint=endpoint, variant="connection-close")

    assert result.status == "ok"
    assert result.error_kind == "soap_fault"
    assert result.http_status == 500
    assert result.soap_fault_detected is True
    assert result.exception_stage == "soap_fault"
    assert result.timeout_stage == "none"


def test_verify_post_probe_fake_server_read_timeout_is_classified_by_stage() -> None:
    with _fake_server(status=200, body=SOAP_OK, response_delay=0.25) as endpoint:
        result = run_sat_verify_post_probe(endpoint=endpoint, connect_timeout_seconds=1, read_timeout_seconds=0.05)

    assert result.status == "failed"
    assert result.error_kind == "read"
    assert result.exception_stage == "read"
    assert result.timeout_stage == "read"
    assert result.response_received is False
    assert result.post_attempted is True


def test_verify_post_probe_connection_error_is_classified_without_real_sat() -> None:
    endpoint = f"http://127.0.0.1:{_unused_local_port()}/VerificaSolicitudDescargaService.svc"

    result = run_sat_verify_post_probe(endpoint=endpoint, connect_timeout_seconds=0.2, read_timeout_seconds=0.2)

    assert result.status == "failed"
    assert result.error_kind == "connect"
    assert result.exception_stage == "connect"
    assert result.response_received is False


def test_verify_post_probe_treats_http_error_as_reached_server_without_raw_body() -> None:
    client = FakeVerifyPostClient(response=VerifyPostProbeHttpResponse(415, b"raw unsupported media detail"))

    result = run_sat_verify_post_probe(client=client, endpoint="https://verify.example/svc", timeout_seconds=7)

    assert result.status == "ok"
    assert result.error_kind == "http_status"
    assert result.http_status == 415
    assert result.payload_size == len(b"raw unsupported media detail")
    assert result.host == "verify.example"
    assert result.request_body_bytes_len == len(VERIFY_POST_PROBE_BODY)
    assert result.has_authorization is True
    assert "raw unsupported" not in repr(result)
    assert client.calls == [("https://verify.example/svc", VERIFY_POST_PROBE_BODY, VERIFY_POST_PROBE_HEADERS, 7, 7)]


def test_verify_post_probe_uses_canonical_verify_contract_constants() -> None:
    assert b"VerificaSolicitudDescarga" in VERIFY_POST_PROBE_BODY
    assert b"DUMMY-VERIFY-REQUEST" in VERIFY_POST_PROBE_BODY
    assert VERIFY_POST_PROBE_ENVELOPE_SOURCES == ("synthetic", "production-signed")
    assert VERIFY_POST_PROBE_HEADERS["SOAPAction"] == f'"{VERIFY_ACTION}"'
    assert VERIFY_POST_PROBE_HEADERS["Content-Type"] == "text/xml; charset=utf-8"
    assert VERIFY_POST_PROBE_HEADERS["Authorization"] == 'WRAP access_token="DUMMY"'
    result = run_sat_verify_post_probe(client=FakeVerifyPostClient())
    assert result.path == "/VerificaSolicitudDescargaService.svc"
    assert DEFAULT_VERIFY_ENDPOINT.endswith(result.path)


def test_verify_post_probe_variants_adjust_headers_without_raw_values() -> None:
    headers_by_variant = {variant: build_verify_post_probe_headers(variant) for variant in VERIFY_POST_PROBE_VARIANTS}

    assert "Connection" not in headers_by_variant["default"]
    assert headers_by_variant["keep-alive"]["Connection"] == "keep-alive"
    assert headers_by_variant["connection-close"]["Connection"] == "close"
    assert headers_by_variant["explicit-content-length"]["Content-Length"] == str(len(VERIFY_POST_PROBE_BODY))
    assert "Expect" not in headers_by_variant["no-expect"]
    assert headers_by_variant["apache-like-ua"]["User-Agent"].startswith("Apache-HttpClient/")


def test_verify_post_probe_passes_variant_headers_and_split_timeouts_to_client() -> None:
    client = FakeVerifyPostClient(response=VerifyPostProbeHttpResponse(200, SOAP_OK))

    result = run_sat_verify_post_probe(
        client=client,
        endpoint="https://verify.example/svc",
        variant="keep-alive",
        connect_timeout_seconds=2,
        read_timeout_seconds=8,
    )

    assert result.variant == "keep-alive"
    assert result.connect_timeout_seconds == 2
    assert result.read_timeout_seconds == 8
    _, _, headers, connect_timeout, read_timeout = client.calls[0]
    assert headers["Connection"] == "keep-alive"
    assert connect_timeout == 2
    assert read_timeout == 8


def test_verify_post_probe_dry_run_does_not_post() -> None:
    client = FakeVerifyPostClient()

    result = run_sat_verify_post_probe(client=client, dry_run=True, variant="apache-like-ua")

    assert result.status == "dry_run"
    assert result.variant == "apache-like-ua"
    assert result.envelope_source == "synthetic"
    assert result.operation == "VerificaSolicitudDescarga"
    assert result.has_signature is False
    assert result.authorization_in_body is False
    for field in ("body_shape_verified", "has_id_solicitud", "has_rfc_solicitante", "has_authorization_wrap"):
        assert getattr(result, field) is True
    assert result.post_attempted is False
    assert result.response_received is False
    assert client.calls == []


def test_verify_post_probe_production_signed_source_uses_signed_shape_without_real_material() -> None:
    envelope = build_verify_post_probe_envelope(envelope_source="production-signed", variant="connection-close")

    assert envelope.source == "production-signed"
    assert envelope.headers["Connection"] == "close"
    assert envelope.shape.operation == "VerificaSolicitudDescarga"
    assert envelope.shape.authorization_in_body is False
    assert envelope.shape.content_type == "text/xml; charset=utf-8"
    for field in (
        "body_shape_verified", "has_id_solicitud", "has_rfc_solicitante", "has_signature",
        "has_signed_info", "has_signature_value", "has_key_info", "has_x509_issuer_serial",
        "has_x509_certificate", "has_authorization_wrap", "soap_action_present",
    ):
        assert getattr(envelope.shape, field) is True
    assert envelope.shape.signature_placement == "inside_solicitud"
    assert envelope.shape.signed_target == "operation_wrapper"
    assert envelope.shape.canonicalization == "exclusive_c14n"
    assert envelope.shape.transform == "exclusive_c14n"
    assert envelope.shape.reference_uri == "empty"
    assert envelope.shape.digest_method == "sha1"
    assert envelope.shape.signature_method == "rsa_sha1"
    assert len(envelope.body) > len(VERIFY_POST_PROBE_BODY)
    for marker in (b"IdSolicitud", b"RfcSolicitante", b"Signature", b"SignedInfo", b"SignatureValue"):
        assert marker in envelope.body
    assert b"X509IssuerSerial" in envelope.body
    assert b"X509Certificate" in envelope.body
    assert b"enveloped-signature" not in envelope.body
    assert b"REC-xml-c14n-20010315" not in envelope.body
    assert b"WRAP" not in envelope.body
    assert ("access_" + "token").encode("ascii") not in envelope.body


def test_verify_post_probe_production_signed_result_is_redacted_and_larger_than_synthetic() -> None:
    client = FakeVerifyPostClient(response=VerifyPostProbeHttpResponse(200, SOAP_OK))

    result = run_sat_verify_post_probe(
        client=client,
        endpoint="https://verify.example/svc",
        envelope_source="production-signed",
        variant="explicit-content-length",
    )

    assert result.status == "ok"
    assert result.envelope_source == "production-signed"
    for field in (
        "body_shape_verified", "has_signature", "has_signed_info", "has_signature_value", "has_key_info",
        "has_x509_issuer_serial", "has_x509_certificate",
    ):
        assert getattr(result, field) is True
    assert result.signed_target == "operation_wrapper"
    assert result.canonicalization == "exclusive_c14n"
    assert result.transform == "exclusive_c14n"
    assert result.reference_uri == "empty"
    assert result.digest_method == "sha1"
    assert result.signature_method == "rsa_sha1"
    assert result.request_size_bytes > len(VERIFY_POST_PROBE_BODY)
    assert result.request_body_sha256_redacted.startswith("sha256:")
    assert result.request_body_sha256_redacted.endswith("...")
    _, body, headers, _, _ = client.calls[0]
    assert len(body) == result.request_size_bytes
    assert headers["Content-Length"] == str(len(body))
    rendered = repr(result)
    assert "WRAP" not in rendered
    assert "access_token" not in rendered
    assert "DUMMY-VERIFY-REQUEST" not in rendered
    assert "XAXX010101000" not in rendered
    assert "SignatureValue>" not in rendered


def test_verify_post_probe_classifies_transport_failures_by_stage() -> None:
    failures = [
        (VerifyPostProbeTransportError("connect", ssl.SSLError("synthetic tls failure")), "connect", "connect", "none"),
        (VerifyPostProbeTransportError("connect", ssl.SSLCertVerificationError("synthetic ca failure")), "connect", "connect", "none"),
        (VerifyPostProbeTransportError("read", TimeoutError("synthetic timeout")), "read", "read", "read"),
        (VerifyPostProbeTransportError("write", ConnectionResetError("synthetic reset")), "write", "write", "none"),
        (VerifyPostProbeTransportError("read", RemoteDisconnected("synthetic remote close")), "read", "read", "none"),
        (VerifyPostProbeTransportError("connect", URLError(OSError("synthetic proxy tunnel failure"))), "connect", "connect", "none"),
        (VerifyPostProbeTransportError("connect", socket.gaierror("synthetic dns failure")), "connect", "connect", "none"),
        (RuntimeError("synthetic client configuration failure"), "unknown", "unknown", "none"),
    ]

    for failure, error_kind, exception_stage, timeout_stage in failures:
        result = run_sat_verify_post_probe(client=FakeVerifyPostClient(error=failure))

        assert result.status == "failed"
        assert result.error_kind == error_kind
        assert result.exception_stage == exception_stage
        assert result.timeout_stage == timeout_stage
        rendered = repr(result)
        assert "synthetic tls failure" not in rendered
        assert "synthetic timeout" not in rendered
        assert "synthetic remote close" not in rendered
        assert "synthetic client configuration failure" not in rendered


def test_verify_post_probe_redaction_result_excludes_sensitive_values() -> None:
    result = run_sat_verify_post_probe(dry_run=True)
    rendered = repr(result)

    assert "WRAP" not in rendered
    assert "access_token" not in rendered
    assert "DUMMY-VERIFY-REQUEST" not in rendered
    assert "XAXX010101000" not in rendered
    assert "VerificaSolicitudDescarga>" not in rendered
    assert result.raw_soap_printed is False
    assert result.real_authorization_value_used is False
    assert result.real_request_id_used is False


@contextmanager
def _fake_server(*, status: int, body: bytes, response_delay: float = 0) -> Iterator[str]:
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802 - stdlib handler API.
            length = int(self.headers.get("Content-Length", "0"))
            if length:
                self.rfile.read(length)
            if response_delay:
                time.sleep(response_delay)
            self.send_response(status)
            self.send_header("Content-Type", "text/xml; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            try:
                self.wfile.write(body)
            except BrokenPipeError:
                pass

        def log_message(self, format: str, *args: object) -> None:  # noqa: A002 - stdlib signature.
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}/VerificaSolicitudDescargaService.svc"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=1)


def _unused_local_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])
