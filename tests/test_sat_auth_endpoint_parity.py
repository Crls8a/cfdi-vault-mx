from urllib.parse import urlsplit

from cfdi_vault.sat_auth_endpoints import (
    DEFAULT_AUTH_ENDPOINT,
    auth_wsdl_endpoint,
    describe_endpoint,
    resolve_auth_endpoint,
)
from cfdi_vault.sat_auth_post_probe import run_sat_auth_post_probe
from cfdi_vault.sat_live_smoke import SatLiveSmokeEndpoints
from cfdi_vault.sat_transport_probe import DEFAULT_PROBE_ENDPOINTS


def test_default_auth_probe_post_and_live_adapter_share_host_path() -> None:
    transport_auth_url = dict(DEFAULT_PROBE_ENDPOINTS)["auth_service"]
    post_endpoint = describe_endpoint("auth", resolve_auth_endpoint({}))
    wsdl_endpoint = describe_endpoint("auth_service", transport_auth_url)
    live_endpoint = describe_endpoint("auth", SatLiveSmokeEndpoints().auth)

    assert transport_auth_url == DEFAULT_AUTH_ENDPOINT
    assert (post_endpoint.scheme, post_endpoint.host, post_endpoint.port, post_endpoint.path) == (
        wsdl_endpoint.scheme,
        wsdl_endpoint.host,
        wsdl_endpoint.port,
        wsdl_endpoint.path,
    )
    assert (post_endpoint.scheme, post_endpoint.host, post_endpoint.port, post_endpoint.path) == (
        live_endpoint.scheme,
        live_endpoint.host,
        live_endpoint.port,
        live_endpoint.path,
    )


def test_auth_wsdl_url_keeps_auth_endpoint_host_path_without_sensitive_query() -> None:
    endpoint = "https://auth.example.test/Autenticacion/Autenticacion.svc?tenant=redacted"
    wsdl = auth_wsdl_endpoint(endpoint)

    endpoint_parts = urlsplit(endpoint)
    wsdl_parts = urlsplit(wsdl)
    assert (wsdl_parts.scheme, wsdl_parts.hostname, wsdl_parts.port, wsdl_parts.path) == (
        endpoint_parts.scheme,
        endpoint_parts.hostname,
        endpoint_parts.port,
        endpoint_parts.path,
    )
    assert "singleWsdl" in wsdl_parts.query


def test_auth_post_probe_reports_redacted_endpoint_shape() -> None:
    result = run_sat_auth_post_probe(
        client=_ReachedServerClient(),
        endpoint="https://auth.example.test/Autenticacion/Autenticacion.svc?marker=not-printed",
    )

    assert result.status == "ok"
    assert result.scheme == "https"
    assert result.host == "auth.example.test"
    assert result.port == 443
    assert result.path == "/Autenticacion/Autenticacion.svc"
    assert result.query_present is True
    assert "marker" not in repr(result)
    assert "not-printed" not in repr(result)


class _ReachedServerClient:
    def post(self, url, body, headers, timeout_seconds):  # noqa: ANN001, ANN201
        from cfdi_vault.sat_auth_post_probe import AuthPostProbeHttpResponse

        return AuthPostProbeHttpResponse(415, b"unsupported media")
