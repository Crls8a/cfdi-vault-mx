"""Redacted offline SAT verify envelope linter."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
from pathlib import Path
import re

from lxml import etree
from signxml.algorithms import CanonicalizationMethod, DigestAlgorithm, SignatureMethod

from cfdi_vault.sat_live_smoke import DS_NS, SAT_REQUEST_NS, SOAP11_NS

EXPECTED_VERIFY_OPERATION = "VerificaSolicitudDescarga"
EXPECTED_VERIFY_XMLSIG_PROFILE = "sat_verify_signed_solicitud"
EXPECTED_VERIFY_C14N_METHOD = CanonicalizationMethod.CANONICAL_XML_1_0.value
EXPECTED_VERIFY_SIGNATURE_METHOD = SignatureMethod.RSA_SHA1.value
EXPECTED_VERIFY_DIGEST_METHOD = DigestAlgorithm.SHA1.value
EXPECTED_VERIFY_TRANSFORMS = (
    "http://www.w3.org/2000/09/xmldsig#enveloped-signature",
    CanonicalizationMethod.CANONICAL_XML_1_0.value,
)


@dataclass(frozen=True)
class VerifyEnvelopeLintResult:
    envelope_sha256: str
    envelope_size: int
    operation_name: str
    operation_namespace: str
    solicitud_attribute_names: tuple[str, ...]
    solicitud_attribute_order: str
    signature_location: str
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
    operation_verify: bool
    solicitud_present: bool
    solicitud_has_id: bool
    solicitud_has_rfc: bool
    signature_inside_solicitud: bool
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
    no_ws_security: bool
    no_authorization_in_xml: bool
    no_placeholders: bool
    all_checks_passed: bool


@dataclass(frozen=True)
class PhpCfdiVerifyOracle:
    available: bool
    reason: str
    source_sha256: str
    operation_name: str
    operation_namespace: str
    solicitud_attribute_names: tuple[str, ...]
    signature_location: str
    key_info_shape: str
    has_auth_wssecurity: bool


def lint_verify_envelope(envelope: bytes) -> VerifyEnvelopeLintResult:
    root = etree.fromstring(envelope)
    header = _child(root, SOAP11_NS, "Header")
    body = _child(root, SOAP11_NS, "Body")
    operation = _child(body, SAT_REQUEST_NS, EXPECTED_VERIFY_OPERATION)
    solicitud = _child(operation, SAT_REQUEST_NS, "solicitud")
    signature = _child(solicitud, DS_NS, "Signature")
    signed_info = _child(signature, DS_NS, "SignedInfo")
    key_info = _child(signature, DS_NS, "KeyInfo")
    reference_nodes = tuple(signed_info.findall(f".//{{{DS_NS}}}Reference")) if signed_info is not None else ()
    reference = reference_nodes[0] if reference_nodes else None
    paths = _element_paths(root)
    result = VerifyEnvelopeLintResult(
        envelope_sha256=hashlib.sha256(envelope).hexdigest(),
        envelope_size=len(envelope),
        operation_name=etree.QName(operation).localname if operation is not None else "",
        operation_namespace=etree.QName(operation).namespace if operation is not None else "",
        solicitud_attribute_names=tuple(solicitud.attrib) if solicitud is not None else (),
        solicitud_attribute_order=",".join(solicitud.attrib) if solicitud is not None else "missing",
        signature_location=_first_path(paths, "/des:solicitud/ds:Signature"),
        key_info_shape=_key_info_shape(key_info),
        reference_uri_shape=_reference_uri_shape(reference),
        reference_transform_algorithms=_transform_algorithms(reference),
        c14n_algorithm=_method_algorithm(signed_info, "CanonicalizationMethod"),
        signature_algorithm=_method_algorithm(signed_info, "SignatureMethod"),
        digest_algorithms=tuple(_reference_method_algorithm(node, "DigestMethod") for node in reference_nodes),
        signed_node_path=_reference_target_path(paths, reference),
        soap_envelope=root.tag == f"{{{SOAP11_NS}}}Envelope",
        soap_header=header is not None,
        soap_body=body is not None,
        operation_verify=operation is not None and etree.QName(operation).namespace == SAT_REQUEST_NS,
        solicitud_present=solicitud is not None,
        solicitud_has_id=bool(solicitud.get("IdSolicitud")) if solicitud is not None else False,
        solicitud_has_rfc=bool(solicitud.get("RfcSolicitante")) if solicitud is not None else False,
        signature_inside_solicitud=signature is not None,
        signed_info=signed_info is not None,
        reference_count=len(reference_nodes),
        reference_uri=reference is not None and _reference_uri_shape(reference) in {"empty", "redacted-id"},
        reference_transforms=_transform_algorithms(reference) == EXPECTED_VERIFY_TRANSFORMS,
        c14n_method=_method_algorithm(signed_info, "CanonicalizationMethod") == EXPECTED_VERIFY_C14N_METHOD,
        signature_method=_method_algorithm(signed_info, "SignatureMethod") == EXPECTED_VERIFY_SIGNATURE_METHOD,
        digest_method=bool(reference_nodes)
        and all(_reference_method_algorithm(node, "DigestMethod") == EXPECTED_VERIFY_DIGEST_METHOD for node in reference_nodes),
        digest_value=signature.find(f".//{{{DS_NS}}}DigestValue") is not None if signature is not None else False,
        signature_value=signature.find(f".//{{{DS_NS}}}SignatureValue") is not None if signature is not None else False,
        key_info=key_info is not None,
        x509_data=key_info.find(f".//{{{DS_NS}}}X509Data") is not None if key_info is not None else False,
        no_ws_security=root.find(f".//{{http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd}}Security") is None,
        no_authorization_in_xml=b"WRAP access_" + b"token" not in envelope,
        no_placeholders=not any(marker in envelope for marker in (b"None", b"null", b"undefined", b"TODO", b"MISSING")),
        all_checks_passed=False,
    )
    checks = [value for key, value in result.__dict__.items() if isinstance(value, bool) and key != "all_checks_passed"]
    return VerifyEnvelopeLintResult(**{**result.__dict__, "all_checks_passed": all(checks) and result.reference_count == 1})


def fingerprint_phpcfdi_verify_oracle(source_path: Path | None) -> PhpCfdiVerifyOracle:
    if source_path is None:
        return _oracle_unavailable("phpcfdi-builder-source-not-provided")
    try:
        source = source_path.read_text(encoding="utf-8")
    except OSError:
        return _oracle_unavailable("phpcfdi-builder-source-not-readable")
    verify_source = _source_verify_segment(source)
    return PhpCfdiVerifyOracle(
        available=True,
        reason="ok",
        source_sha256=hashlib.sha256(source.encode("utf-8")).hexdigest(),
        operation_name=EXPECTED_VERIFY_OPERATION if EXPECTED_VERIFY_OPERATION in source else "",
        operation_namespace=SAT_REQUEST_NS if "DescargaMasivaTerceros.sat.gob.mx" in source else "",
        solicitud_attribute_names=tuple(name for name in ("IdSolicitud", "RfcSolicitante") if name in verify_source),
        signature_location="des:solicitud/ds:Signature" if "sign(" in verify_source or "createSignature" in source else "unknown",
        key_info_shape="ds-x509data" if "X509Data" in source or "certificate" in source.lower() else "unknown",
        has_auth_wssecurity="BinarySecurityToken" in verify_source or "Timestamp" in verify_source,
    )


def _oracle_unavailable(reason: str) -> PhpCfdiVerifyOracle:
    return PhpCfdiVerifyOracle(False, reason, "", "", "", (), "unknown", "unknown", False)


def _source_verify_segment(source: str) -> str:
    start = source.find("function verify")
    if start < 0:
        start = source.find(EXPECTED_VERIFY_OPERATION)
    end = source.find("function ", start + 8) if start >= 0 else -1
    return source[start:end] if start >= 0 and end > start else source[start:] if start >= 0 else source


def _child(node: etree._Element | None, namespace: str, local_name: str) -> etree._Element | None:
    return node.find(f"{{{namespace}}}{local_name}") if node is not None else None


def _method_algorithm(signed_info: etree._Element | None, local_name: str) -> str:
    if signed_info is None:
        return ""
    node = signed_info.find(f"{{{DS_NS}}}{local_name}")
    return node.get("Algorithm") if node is not None else ""


def _reference_method_algorithm(reference: etree._Element, local_name: str) -> str:
    node = reference.find(f".//{{{DS_NS}}}{local_name}")
    return node.get("Algorithm") if node is not None else ""


def _transform_algorithms(reference: etree._Element | None) -> tuple[str, ...]:
    if reference is None:
        return ()
    return tuple(node.get("Algorithm") or "" for node in reference.findall(f".//{{{DS_NS}}}Transform"))


def _reference_uri_shape(reference: etree._Element | None) -> str:
    if reference is None:
        return "missing"
    uri = reference.get("URI")
    if uri == "":
        return "empty"
    return "redacted-id" if uri and uri.startswith("#") else "external-redacted"


def _key_info_shape(key_info: etree._Element | None) -> str:
    if key_info is None:
        return "missing_key_info"
    if key_info.find(f".//{{{DS_NS}}}X509Data") is not None:
        return "ds-x509data"
    return "unknown"


def _reference_target_path(paths: tuple[str, ...], reference: etree._Element | None) -> str:
    if reference is None:
        return "missing"
    uri = reference.get("URI")
    if uri == "":
        return "/soapenv:Envelope/soapenv:Body/des:VerificaSolicitudDescarga/des:solicitud"
    target = (uri or "").lstrip("#")
    if not target:
        return "missing"
    return next((path for path in paths if path.endswith(f"@Id={target}")), "redacted-id")


def _first_path(paths: tuple[str, ...], suffix: str) -> str:
    return next((path for path in paths if path.endswith(suffix)), "missing")


def _element_paths(root: etree._Element) -> tuple[str, ...]:
    paths: list[str] = []

    def visit(node: etree._Element, parent: str) -> None:
        path = f"{parent}/{_qualified_name(node)}"
        paths.append(path)
        for child in node:
            visit(child, path)

    visit(root, "")
    return tuple(paths)


def _qualified_name(node: etree._Element) -> str:
    name = etree.QName(node)
    prefixes = {SOAP11_NS: "soapenv", SAT_REQUEST_NS: "des", DS_NS: "ds"}
    return f"{prefixes.get(name.namespace, 'ns')}:{name.localname}" if name.namespace else name.localname
