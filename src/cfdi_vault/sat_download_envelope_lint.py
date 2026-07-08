"""Redacted offline SAT package-download envelope linter."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib

from lxml import etree
from signxml.algorithms import CanonicalizationMethod, DigestAlgorithm, SignatureMethod

from cfdi_vault.sat_auth_constants import AUTH_ACCEPT, AUTH_CONTENT_TYPE
from cfdi_vault.sat_live_smoke import (
    DEFAULT_DOWNLOAD_ENDPOINT,
    DOWNLOAD_ACTION,
    DS_NS,
    SAT_REQUEST_NS,
    SOAP11_NS,
)
from cfdi_vault.sat_verify_envelope_lint import (
    _child,
    _digest_matches,
    _element_paths,
    _first_path,
    _has_key_info_child,
    _key_info_shape,
    _method_algorithm,
    _reference_method_algorithm,
    _reference_uri_shape,
    _transform_algorithms,
)

EXPECTED_PACKAGE_DOWNLOAD_OPERATION = "Descargar"
EXPECTED_PACKAGE_DOWNLOAD_XMLSIG_PROFILE = "sat_download_signed_operation_wrapper"
EXPECTED_PACKAGE_DOWNLOAD_C14N_METHOD = CanonicalizationMethod.EXCLUSIVE_XML_CANONICALIZATION_1_0.value
EXPECTED_PACKAGE_DOWNLOAD_SIGNATURE_METHOD = SignatureMethod.RSA_SHA1.value
EXPECTED_PACKAGE_DOWNLOAD_DIGEST_METHOD = DigestAlgorithm.SHA1.value
EXPECTED_PACKAGE_DOWNLOAD_TRANSFORMS = (CanonicalizationMethod.EXCLUSIVE_XML_CANONICALIZATION_1_0.value,)


@dataclass(frozen=True)
class PackageDownloadEnvelopeLintResult:
    envelope_sha256: str
    envelope_size: int
    endpoint: str
    soap_action: str
    content_type: str
    accept: str
    authorization_header_shape: str
    authorization_value_len: int
    operation_name: str
    operation_namespace: str
    peticion_attribute_names: tuple[str, ...]
    peticion_attribute_order: str
    package_id_redacted: str
    signature_location: str
    signature_placement: str
    signed_target: str
    key_info_shape: str
    reference_uri_shape: str
    reference_transform_algorithms: tuple[str, ...]
    c14n_algorithm: str
    signature_algorithm: str
    digest_algorithms: tuple[str, ...]
    signed_node_path: str
    soap_envelope: bool
    soap_header: bool
    soap_body: bool
    endpoint_download: bool
    soap_action_ok: bool
    content_type_ok: bool
    accept_ok: bool
    authorization_header: bool
    operation_download: bool
    peticion_present: bool
    peticion_has_id_paquete: bool
    peticion_has_rfc: bool
    signature_inside_peticion: bool
    signed_info: bool
    reference_count: int
    reference_uri: bool
    reference_transforms: bool
    c14n_method: bool
    signature_method: bool
    digest_method: bool
    digest_value: bool
    signature_value: bool
    key_info: bool
    x509_data: bool
    x509_issuer_serial: bool
    x509_certificate: bool
    no_ws_security: bool
    no_authorization_in_xml: bool
    no_placeholders: bool
    all_checks_passed: bool


def lint_package_download_envelope(
    envelope: bytes,
    *,
    headers: dict[str, str] | None = None,
    endpoint: str = DEFAULT_DOWNLOAD_ENDPOINT,
) -> PackageDownloadEnvelopeLintResult:
    """Lint one offline package-download envelope without exposing ids or tokens."""

    safe_headers = headers or {}
    root = etree.fromstring(envelope)
    header = _child(root, SOAP11_NS, "Header")
    body = _child(root, SOAP11_NS, "Body")
    operation = _child(body, SAT_REQUEST_NS, EXPECTED_PACKAGE_DOWNLOAD_OPERATION)
    peticion = _child(operation, SAT_REQUEST_NS, "peticionDescarga")
    signature = _child(peticion, DS_NS, "Signature")
    signed_info = _child(signature, DS_NS, "SignedInfo")
    key_info = _child(signature, DS_NS, "KeyInfo")
    reference_nodes = tuple(signed_info.findall(f".//{{{DS_NS}}}Reference")) if signed_info is not None else ()
    reference = reference_nodes[0] if reference_nodes else None
    paths = _element_paths(root)
    signed_target = _signed_target(operation, peticion, signature, reference)
    soap_action = _header_value(safe_headers, "SOAPAction") or ""
    content_type = _header_value(safe_headers, "Content-Type") or ""
    accept = _header_value(safe_headers, "Accept") or ""
    authorization = _header_value(safe_headers, "Authorization") or ""
    result = PackageDownloadEnvelopeLintResult(
        envelope_sha256=hashlib.sha256(envelope).hexdigest(),
        envelope_size=len(envelope),
        endpoint=endpoint,
        soap_action=soap_action,
        content_type=content_type,
        accept=accept,
        authorization_header_shape=_authorization_header_shape(authorization),
        authorization_value_len=_authorization_token_len(authorization),
        operation_name=etree.QName(operation).localname if operation is not None else "",
        operation_namespace=etree.QName(operation).namespace if operation is not None else "",
        peticion_attribute_names=tuple(peticion.attrib) if peticion is not None else (),
        peticion_attribute_order=",".join(peticion.attrib) if peticion is not None else "missing",
        package_id_redacted=_redact_identifier(peticion.get("IdPaquete", "")) if peticion is not None else "",
        signature_location=_first_path(paths, "/des:peticionDescarga/ds:Signature"),
        signature_placement="inside_peticion_descarga" if signature is not None else "missing",
        signed_target=signed_target,
        key_info_shape=_key_info_shape(key_info),
        reference_uri_shape=_reference_uri_shape(reference),
        reference_transform_algorithms=_transform_algorithms(reference),
        c14n_algorithm=_method_algorithm(signed_info, "CanonicalizationMethod"),
        signature_algorithm=_method_algorithm(signed_info, "SignatureMethod"),
        digest_algorithms=tuple(_reference_method_algorithm(node, "DigestMethod") for node in reference_nodes),
        signed_node_path=_reference_target_path(reference, signed_target),
        soap_envelope=root.tag == f"{{{SOAP11_NS}}}Envelope",
        soap_header=header is not None,
        soap_body=body is not None,
        endpoint_download=endpoint == DEFAULT_DOWNLOAD_ENDPOINT,
        soap_action_ok=soap_action == f'"{DOWNLOAD_ACTION}"',
        content_type_ok=content_type == AUTH_CONTENT_TYPE,
        accept_ok=accept == AUTH_ACCEPT,
        authorization_header=_authorization_header_shape(authorization) == "wrap-access-token",
        operation_download=operation is not None and etree.QName(operation).namespace == SAT_REQUEST_NS,
        peticion_present=peticion is not None,
        peticion_has_id_paquete=bool(peticion.get("IdPaquete")) if peticion is not None else False,
        peticion_has_rfc=bool(peticion.get("RfcSolicitante")) if peticion is not None else False,
        signature_inside_peticion=signature is not None,
        signed_info=signed_info is not None,
        reference_count=len(reference_nodes),
        reference_uri=reference is not None and _reference_uri_shape(reference) in {"empty", "redacted-id"},
        reference_transforms=_transform_algorithms(reference) == EXPECTED_PACKAGE_DOWNLOAD_TRANSFORMS,
        c14n_method=_method_algorithm(signed_info, "CanonicalizationMethod") == EXPECTED_PACKAGE_DOWNLOAD_C14N_METHOD,
        signature_method=_method_algorithm(signed_info, "SignatureMethod") == EXPECTED_PACKAGE_DOWNLOAD_SIGNATURE_METHOD,
        digest_method=bool(reference_nodes)
        and all(
            _reference_method_algorithm(node, "DigestMethod") == EXPECTED_PACKAGE_DOWNLOAD_DIGEST_METHOD
            for node in reference_nodes
        ),
        digest_value=signature.find(f".//{{{DS_NS}}}DigestValue") is not None if signature is not None else False,
        signature_value=signature.find(f".//{{{DS_NS}}}SignatureValue") is not None if signature is not None else False,
        key_info=key_info is not None,
        x509_data=key_info.find(f".//{{{DS_NS}}}X509Data") is not None if key_info is not None else False,
        x509_issuer_serial=_has_key_info_child(key_info, "X509IssuerSerial"),
        x509_certificate=_has_key_info_child(key_info, "X509Certificate"),
        no_ws_security=root.find(f".//{{http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd}}Security")
        is None,
        no_authorization_in_xml=b"WRAP access_" + b"token" not in envelope,
        no_placeholders=not any(marker in envelope for marker in (b"None", b"null", b"undefined", b"TODO", b"MISSING")),
        all_checks_passed=False,
    )
    checks = [value for key, value in result.__dict__.items() if isinstance(value, bool) and key != "all_checks_passed"]
    return PackageDownloadEnvelopeLintResult(
        **{
            **result.__dict__,
            "all_checks_passed": all(checks)
            and result.reference_count == 1
            and result.signature_placement == "inside_peticion_descarga"
            and result.signed_target == "operation_wrapper",
        }
    )


def _header_value(headers: dict[str, str], name: str) -> str | None:
    lowered = name.lower()
    for key, value in headers.items():
        if key.lower() == lowered:
            return value
    return None


def _authorization_header_shape(value: str) -> str:
    if not value:
        return "missing"
    return "wrap-access-token" if _authorization_token_len(value) > 0 else "unexpected"


def _authorization_token_len(value: str) -> int:
    prefix = 'WRAP access_token="'
    stripped = value.strip()
    if not stripped.startswith(prefix) or not stripped.endswith('"'):
        return 0
    return len(stripped[len(prefix) : -1])


def _signed_target(
    operation: etree._Element | None,
    peticion: etree._Element | None,
    signature: etree._Element | None,
    reference: etree._Element | None,
) -> str:
    digest_value = signature.findtext(f".//{{{DS_NS}}}DigestValue") if signature is not None else ""
    if not digest_value:
        return "missing"
    if operation is not None and _digest_matches(operation, digest_value, exclusive=True):
        return "operation_wrapper"
    if peticion is not None and (
        _digest_matches(peticion, digest_value, exclusive=True)
        or _digest_matches(peticion, digest_value, exclusive=False)
    ):
        return "peticion_descarga"
    if reference is not None and "http://www.w3.org/2000/09/xmldsig#enveloped-signature" in _transform_algorithms(reference):
        return "peticion_descarga"
    if reference is not None and (reference.get("URI") or "").startswith("#"):
        return "redacted-id"
    return "unknown"


def _reference_target_path(reference: etree._Element | None, signed_target: str) -> str:
    if reference is None:
        return "missing"
    uri = reference.get("URI")
    if uri == "":
        if signed_target == "peticion_descarga":
            return "/soapenv:Envelope/soapenv:Body/des:Descargar/des:peticionDescarga"
        return "/soapenv:Envelope/soapenv:Body/des:Descargar"
    return "redacted-id" if uri else "missing"


def _redact_identifier(value: str) -> str:
    if not value:
        return ""
    if len(value) <= 8:
        return "<redacted>"
    return f"{value[:4]}...{value[-4:]}"
