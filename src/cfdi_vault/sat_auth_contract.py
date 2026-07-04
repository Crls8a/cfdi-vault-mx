"""Safe SAT auth WSDL contract inspection without raw WSDL output."""

from __future__ import annotations

from dataclasses import dataclass
from urllib import request as urllib_request
from urllib.error import HTTPError

from lxml import etree

from cfdi_vault.sat_auth_constants import AUTH_OPERATION
from cfdi_vault.sat_auth_endpoints import auth_wsdl_endpoint, describe_endpoint, resolve_auth_endpoint

WSDL_NS = "http://schemas.xmlsoap.org/wsdl/"
SOAP11_BINDING_NS = "http://schemas.xmlsoap.org/wsdl/soap/"
SOAP12_BINDING_NS = "http://schemas.xmlsoap.org/wsdl/soap12/"


@dataclass(frozen=True)
class AuthWsdlContract:
    operation_name: str
    soap_action: str
    soap_version: str
    binding_transport: str
    target_namespace: str
    endpoint_scheme: str
    endpoint_host: str
    endpoint_port: int
    endpoint_path: str
    expected_action_uri: str
    wsdl_size: int
    raw_wsdl_printed: bool = False


def fetch_auth_wsdl_contract(*, endpoint: str | None = None, timeout_seconds: float = 10) -> AuthWsdlContract:
    """Fetch the public auth WSDL and return only a redacted contract summary."""

    auth_endpoint = endpoint or resolve_auth_endpoint()
    request = urllib_request.Request(auth_wsdl_endpoint(auth_endpoint), method="GET", headers={"User-Agent": "cfdi-vault-auth-contract"})
    try:
        with urllib_request.urlopen(request, timeout=timeout_seconds) as response:  # noqa: S310 - explicit public WSDL fetch
            body = response.read(1024 * 1024)
    except HTTPError as exc:
        body = exc.read(1024 * 1024)
        if not 200 <= exc.code < 300:
            raise ValueError("auth-wsdl-unavailable") from None
    return parse_auth_wsdl_contract(body)


def parse_auth_wsdl_contract(wsdl: bytes) -> AuthWsdlContract:
    root = etree.fromstring(wsdl)
    target_namespace = root.get("targetNamespace") or ""
    operation = _first(root.xpath(".//wsdl:binding/wsdl:operation[@name=$name]", name=AUTH_OPERATION, namespaces={"wsdl": WSDL_NS}))
    if operation is None:
        raise ValueError("auth-operation-not-found")
    soap_operation = _first(operation.xpath("./soap:operation", namespaces={"soap": SOAP11_BINDING_NS}))
    soap_version = "1.1"
    if soap_operation is None:
        soap_operation = _first(operation.xpath("./soap12:operation", namespaces={"soap12": SOAP12_BINDING_NS}))
        soap_version = "1.2"
    if soap_operation is None:
        raise ValueError("auth-soap-operation-not-found")
    soap_action = soap_operation.get("soapAction") or ""
    binding = operation.getparent()
    assert binding is not None
    binding_node = _first(binding.xpath("./soap:binding|./soap12:binding", namespaces={"soap": SOAP11_BINDING_NS, "soap12": SOAP12_BINDING_NS}))
    binding_transport = binding_node.get("transport") if binding_node is not None else ""
    address = _first(root.xpath(".//wsdl:service/wsdl:port/soap:address|.//wsdl:service/wsdl:port/soap12:address", namespaces={"wsdl": WSDL_NS, "soap": SOAP11_BINDING_NS, "soap12": SOAP12_BINDING_NS}))
    endpoint = describe_endpoint("auth", address.get("location") if address is not None else resolve_auth_endpoint())
    return AuthWsdlContract(
        operation_name=operation.get("name") or AUTH_OPERATION,
        soap_action=soap_action,
        soap_version=soap_version,
        binding_transport=binding_transport,
        target_namespace=target_namespace,
        endpoint_scheme=endpoint.scheme,
        endpoint_host=endpoint.host,
        endpoint_port=endpoint.port,
        endpoint_path=endpoint.path,
        expected_action_uri=soap_action,
        wsdl_size=len(wsdl),
    )


def _first(items: list[object]) -> object | None:
    return items[0] if items else None
