"""Focused tests for the internal SAT v1.5 wire contract."""

from dataclasses import fields

from cfdi_vault.sat_auth_constants import AUTH_SOAP_ACTION
from cfdi_vault.sat_auth_endpoints import DEFAULT_AUTH_ENDPOINT
from cfdi_vault.sat_v15_contract import (
    AUTH_ACTION,
    DEFAULT_DOWNLOAD_ENDPOINT,
    DEFAULT_REQUEST_ENDPOINT,
    DEFAULT_VERIFY_ENDPOINT,
    DOWNLOAD_ACTION,
    REQUEST_ACTION_BASE,
    SAT_REQUEST_NS,
    VERIFY_ACTION,
    SatV15Endpoints,
    SatV15RequestOperation,
    v15_request_soap_action,
)


def test_v15_contract_exposes_canonical_wire_values() -> None:
    assert SAT_REQUEST_NS == "http://DescargaMasivaTerceros.sat.gob.mx"
    assert AUTH_ACTION == AUTH_SOAP_ACTION
    assert REQUEST_ACTION_BASE.endswith("/ISolicitaDescargaService")
    assert VERIFY_ACTION.endswith("/VerificaSolicitudDescarga")
    assert DOWNLOAD_ACTION.endswith("/Descargar")
    assert DEFAULT_REQUEST_ENDPOINT.endswith("/SolicitaDescargaService.svc")
    assert DEFAULT_VERIFY_ENDPOINT.endswith("/VerificaSolicitudDescargaService.svc")
    assert DEFAULT_DOWNLOAD_ENDPOINT.endswith("/DescargaMasivaService.svc")


def test_v15_endpoints_preserve_transport_field_order_and_defaults() -> None:
    assert [item.name for item in fields(SatV15Endpoints)] == ["auth", "request", "verify", "download"]
    assert SatV15Endpoints() == SatV15Endpoints(
        auth=DEFAULT_AUTH_ENDPOINT,
        request=DEFAULT_REQUEST_ENDPOINT,
        verify=DEFAULT_VERIFY_ENDPOINT,
        download=DEFAULT_DOWNLOAD_ENDPOINT,
    )


def test_v15_request_actions_are_derived_from_specialized_operations() -> None:
    expected = {
        SatV15RequestOperation.ISSUED: "SolicitaDescargaEmitidos",
        SatV15RequestOperation.RECEIVED: "SolicitaDescargaRecibidos",
        SatV15RequestOperation.FOLIO: "SolicitaDescargaFolio",
    }

    for operation, suffix in expected.items():
        assert operation.value == suffix
        assert v15_request_soap_action(operation) == f"{REQUEST_ACTION_BASE}/{suffix}"
