"""Redacted offline SAT auth envelope linter."""

from __future__ import annotations

import base64
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from lxml import etree
from signxml import XMLVerifier
from signxml.algorithms import CanonicalizationMethod, DigestAlgorithm, SignatureMethod
from signxml.verifier import SignatureConfiguration

from cfdi_vault.sat_auth_constants import AUTH_OPERATION, AUTH_SOAP_ACTION
from cfdi_vault.sat_auth_constants import (
    AUTH_ENVELOPE_VARIANT_ACTION_BEFORE_SECURITY,
    AUTH_ENVELOPE_VARIANT_SECURITY_ONLY,
    DEFAULT_AUTH_ENVELOPE_VARIANT,
)
from cfdi_vault.sat_live_smoke import (
    ADDR_NS,
    BASE64_ENCODING_TYPE,
    DS_NS,
    SAT_AUTH_NS,
    SOAP11_NS,
    WSSE_NS,
    WSU_NS,
    X509_VALUE_TYPE,
    SatEfirmMaterial,
    _build_auth_envelope,
)

EXPECTED_C14N_METHOD = CanonicalizationMethod.EXCLUSIVE_XML_CANONICALIZATION_1_0.value
EXPECTED_SIGNATURE_METHOD = SignatureMethod.RSA_SHA1.value
EXPECTED_DIGEST_METHOD = DigestAlgorithm.SHA1.value
EXPECTED_XMLSIG_PROFILE = "sat_legacy_wssecurity"
EXPECTED_HEADER_ACTION_ORDER = DEFAULT_AUTH_ENVELOPE_VARIANT


@dataclass(frozen=True)
class AuthEnvelopeLintResult:
    envelope_sha256: str
    envelope_size: int
    xmlsig_profile: str
    c14n_algorithm: str
    signature_algorithm: str
    digest_algorithms: tuple[str, ...]
    reference_uris_redacted: tuple[str, ...]
    reference_transform_algorithms: tuple[str, ...]
    key_info_reference_uri_redacted: str
    header_action_order: str
    expected_header_action_order: str
    timestamp_window_seconds: int | None
    soap_envelope: bool
    soap_header: bool
    soap_body: bool
    operation_auth: bool
    ws_security: bool
    timestamp: bool
    timestamp_id_present: bool
    timestamp_created_utc_z: bool
    timestamp_expires_utc_z: bool
    timestamp_window_ok: bool
    bst_present: bool
    bst_id_present: bool
    bst_der: bool
    bst_no_pem: bool
    bst_value_type: bool
    bst_encoding_type: bool
    bst_size: int
    signature: bool
    signed_info: bool
    c14n_method: bool
    signature_method: bool
    digest_method: bool
    reference_transforms: bool
    reference_count: int
    reference_uris: bool
    references_resolve: bool
    references_use_wsu_id: bool
    signed_nodes_exist: bool
    digest_value: bool
    signature_value: bool
    key_info: bool
    sec_ref: bool
    sec_ref_uri: bool
    sec_ref_value_type: bool
    sec_ref_resolves_bst: bool
    timestamp_signed: bool
    to_header_present: bool
    action_header_present: bool
    action_header_value: bool
    action_header_namespace: bool
    action_header_must_understand: bool
    action_header_before_security: bool
    action_header_order_ok: bool
    security_must_understand: bool
    local_signature_verify: bool
    all_checks_passed: bool


def build_dummy_auth_envelope(endpoint: str, *, auth_envelope_variant: str = DEFAULT_AUTH_ENVELOPE_VARIANT) -> bytes:
    return _build_auth_envelope(_dummy_material(), endpoint, auth_envelope_variant=auth_envelope_variant)


def lint_auth_envelope(
    envelope: bytes,
    *,
    now: datetime | None = None,
    expected_header_action_order: str = EXPECTED_HEADER_ACTION_ORDER,
) -> AuthEnvelopeLintResult:
    root = etree.fromstring(envelope)
    header = root.find(f"{{{SOAP11_NS}}}Header")
    body = root.find(f"{{{SOAP11_NS}}}Body")
    security = header.find(f"{{{WSSE_NS}}}Security") if header is not None else None
    timestamp = security.find(f"{{{WSU_NS}}}Timestamp") if security is not None else None
    bst = security.find(f"{{{WSSE_NS}}}BinarySecurityToken") if security is not None else None
    signature = security.find(f"{{{DS_NS}}}Signature") if security is not None else None
    signed_info = signature.find(f"{{{DS_NS}}}SignedInfo") if signature is not None else None
    action = header.find(f"{{{ADDR_NS}}}Action") if header is not None else None
    sec_ref_reference = _sec_ref_reference(signature)
    references = signed_info.findall(f".//{{{DS_NS}}}Reference") if signed_info is not None else []
    existing_ids = _collect_ids(root)
    wsu_ids = _collect_wsu_ids(root)
    header_action_order = _header_action_order(header)
    result = AuthEnvelopeLintResult(
        envelope_sha256=hashlib.sha256(envelope).hexdigest(),
        envelope_size=len(envelope),
        xmlsig_profile=EXPECTED_XMLSIG_PROFILE,
        c14n_algorithm=_method_algorithm(signed_info, "CanonicalizationMethod"),
        signature_algorithm=_method_algorithm(signed_info, "SignatureMethod"),
        digest_algorithms=tuple(_reference_method_algorithm(ref, "DigestMethod") for ref in references),
        reference_uris_redacted=tuple(_redact_reference_uri(ref.get("URI") or "") for ref in references),
        reference_transform_algorithms=tuple(algorithm for ref in references for algorithm in _reference_transform_algorithms(ref)),
        key_info_reference_uri_redacted=_key_info_reference_uri_redacted(signature),
        header_action_order=header_action_order,
        expected_header_action_order=expected_header_action_order,
        timestamp_window_seconds=_timestamp_window_seconds(timestamp),
        soap_envelope=root.tag == f"{{{SOAP11_NS}}}Envelope",
        soap_header=header is not None,
        soap_body=body is not None,
        operation_auth=body.find(f"{{{SAT_AUTH_NS}}}{AUTH_OPERATION}") is not None if body is not None else False,
        ws_security=security is not None,
        timestamp=timestamp is not None,
        timestamp_id_present=bool(_wsu_id(timestamp)),
        timestamp_created_utc_z=_is_utc_z(timestamp.findtext(f"{{{WSU_NS}}}Created") if timestamp is not None else None),
        timestamp_expires_utc_z=_is_utc_z(timestamp.findtext(f"{{{WSU_NS}}}Expires") if timestamp is not None else None),
        timestamp_window_ok=_timestamp_window_ok(timestamp, now=now or datetime.now(timezone.utc)),
        bst_present=bst is not None,
        bst_id_present=bool(_wsu_id(bst)),
        bst_der=_bst_is_der_base64(bst.text if bst is not None else ""),
        bst_no_pem=_bst_has_no_pem_marker(bst.text if bst is not None else ""),
        bst_value_type=bst.get("ValueType") == X509_VALUE_TYPE if bst is not None else False,
        bst_encoding_type=bst.get("EncodingType") == BASE64_ENCODING_TYPE if bst is not None else False,
        bst_size=len((bst.text or "")) if bst is not None else 0,
        signature=signature is not None,
        signed_info=signed_info is not None,
        c14n_method=_method_algorithm(signed_info, "CanonicalizationMethod") == EXPECTED_C14N_METHOD,
        signature_method=_method_algorithm(signed_info, "SignatureMethod") == EXPECTED_SIGNATURE_METHOD,
        digest_method=bool(references) and all(_reference_method_algorithm(ref, "DigestMethod") == EXPECTED_DIGEST_METHOD for ref in references),
        reference_transforms=bool(references) and all(_reference_transform_ok(ref) for ref in references),
        reference_count=len(references),
        reference_uris=bool(references) and all(_reference_uri(ref) for ref in references),
        references_resolve=bool(references) and all((ref.get("URI") or "").lstrip("#") in existing_ids for ref in references),
        references_use_wsu_id=bool(references) and all(_reference_uri(ref) in wsu_ids for ref in references),
        signed_nodes_exist=bool(references) and all(_reference_uri(ref) in existing_ids for ref in references),
        digest_value=signature.find(f".//{{{DS_NS}}}DigestValue") is not None if signature is not None else False,
        signature_value=signature.find(f".//{{{DS_NS}}}SignatureValue") is not None if signature is not None else False,
        key_info=signature.find(f"{{{DS_NS}}}KeyInfo") is not None if signature is not None else False,
        sec_ref=signature.find(f".//{{{WSSE_NS}}}SecurityTokenReference") is not None if signature is not None else False,
        sec_ref_uri=bool(_uri_target(sec_ref_reference)),
        sec_ref_value_type=sec_ref_reference.get("ValueType") == X509_VALUE_TYPE if sec_ref_reference is not None else False,
        sec_ref_resolves_bst=_uri_target(sec_ref_reference) == _wsu_id(bst),
        timestamp_signed=any((ref.get("URI") or "").lstrip("#") == (timestamp.get(f"{{{WSU_NS}}}Id") if timestamp is not None else "") for ref in references),
        to_header_present=header.find(f"{{{ADDR_NS}}}To") is not None if header is not None else False,
        action_header_present=action is not None,
        action_header_value=(action.text or "").strip() == AUTH_SOAP_ACTION if action is not None else False,
        action_header_namespace=action.tag == f"{{{ADDR_NS}}}Action" if action is not None else False,
        action_header_must_understand=_must_understand(action),
        action_header_before_security=header_action_order == AUTH_ENVELOPE_VARIANT_ACTION_BEFORE_SECURITY,
        action_header_order_ok=header_action_order == expected_header_action_order,
        security_must_understand=_must_understand(security),
        local_signature_verify=_verify_signature_with_bst(root, bst),
        all_checks_passed=False,
    )
    expects_action = expected_header_action_order != AUTH_ENVELOPE_VARIANT_SECURITY_ONLY
    action_checks = {"to_header_present", "action_header_present", "action_header_value", "action_header_namespace", "action_header_must_understand"}
    checks = [
        value
        for key, value in result.__dict__.items()
        if isinstance(value, bool) and key not in {"all_checks_passed", "action_header_before_security"}
        and (expects_action or key not in action_checks)
    ]
    return AuthEnvelopeLintResult(**{**result.__dict__, "all_checks_passed": all(checks)})


def _collect_ids(root: etree._Element) -> set[str]:
    ids: set[str] = set()
    for node in root.iter():
        for value in (node.get("Id"), node.get(f"{{{WSU_NS}}}Id")):
            if value:
                ids.add(value)
    return ids


def _collect_wsu_ids(root: etree._Element) -> set[str]:
    ids: set[str] = set()
    for node in root.iter():
        value = node.get(f"{{{WSU_NS}}}Id")
        if value:
            ids.add(value)
    return ids


def _timestamp_window_ok(timestamp: etree._Element | None, *, now: datetime) -> bool:
    if timestamp is None:
        return False
    created = _parse_time(timestamp.findtext(f"{{{WSU_NS}}}Created"))
    expires = _parse_time(timestamp.findtext(f"{{{WSU_NS}}}Expires"))
    if created is None or expires is None:
        return False
    return created <= now <= expires and 0 < (expires - created).total_seconds() <= 600


def _timestamp_window_seconds(timestamp: etree._Element | None) -> int | None:
    if timestamp is None:
        return None
    created = _parse_time(timestamp.findtext(f"{{{WSU_NS}}}Created"))
    expires = _parse_time(timestamp.findtext(f"{{{WSU_NS}}}Expires"))
    if created is None or expires is None:
        return None
    return round((expires - created).total_seconds())


def _is_utc_z(value: str | None) -> bool:
    return bool(value and value.endswith("Z") and _parse_time(value) is not None)


def _must_understand(node: etree._Element | None) -> bool:
    return node is not None and node.get(f"{{{SOAP11_NS}}}mustUnderstand") == "1"


def _header_action_order(header: etree._Element | None) -> str:
    if header is None:
        return "missing_header"
    action_index: int | None = None
    security_index: int | None = None
    for index, child in enumerate(header):
        name = etree.QName(child)
        if name.namespace == ADDR_NS and name.localname == "Action":
            action_index = index
        if name.namespace == WSSE_NS and name.localname == "Security":
            security_index = index
    if action_index is None and security_index is not None:
        return AUTH_ENVELOPE_VARIANT_SECURITY_ONLY
    if action_index is None or security_index is None:
        return "missing_action_or_security"
    return AUTH_ENVELOPE_VARIANT_ACTION_BEFORE_SECURITY if action_index < security_index else "security_before_action"


def _parse_time(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _bst_is_der_base64(value: str | None) -> bool:
    if not value or "-----BEGIN" in value:
        return False
    try:
        x509.load_der_x509_certificate(base64.b64decode(value, validate=True))
        return True
    except ValueError:
        return False


def _bst_has_no_pem_marker(value: str | None) -> bool:
    return bool(value) and "-----BEGIN" not in value and "-----END" not in value


def _method_algorithm(signed_info: etree._Element | None, local_name: str) -> str:
    if signed_info is None:
        return ""
    node = signed_info.find(f"{{{DS_NS}}}{local_name}")
    return node.get("Algorithm") if node is not None else ""


def _reference_method_algorithm(reference: etree._Element, local_name: str) -> str:
    node = reference.find(f".//{{{DS_NS}}}{local_name}")
    return node.get("Algorithm") if node is not None else ""


def _reference_transform_algorithms(reference: etree._Element) -> tuple[str, ...]:
    return tuple(transform.get("Algorithm") or "" for transform in reference.findall(f".//{{{DS_NS}}}Transform"))


def _reference_transform_ok(reference: etree._Element) -> bool:
    transforms = _reference_transform_algorithms(reference)
    return bool(transforms) and all(transform == EXPECTED_C14N_METHOD for transform in transforms)


def _redact_reference_uri(uri: str) -> str:
    if not uri:
        return ""
    return "#<id>" if uri.startswith("#") else "<external-redacted>"


def _key_info_reference_uri_redacted(signature: etree._Element | None) -> str:
    reference = _sec_ref_reference(signature)
    if reference is None:
        return ""
    return _redact_reference_uri(reference.get("URI") or "")


def _sec_ref_reference(signature: etree._Element | None) -> etree._Element | None:
    return signature.find(f".//{{{WSSE_NS}}}SecurityTokenReference/{{{WSSE_NS}}}Reference") if signature is not None else None


def _uri_target(reference: etree._Element | None) -> str:
    uri = reference.get("URI") if reference is not None else ""
    return uri[1:] if uri and uri.startswith("#") else ""


def _reference_uri(reference: etree._Element) -> str:
    uri = reference.get("URI") or ""
    return uri[1:] if uri.startswith("#") else ""


def _wsu_id(node: etree._Element | None) -> str:
    if node is None:
        return ""
    return node.get(f"{{{WSU_NS}}}Id") or ""


def _verify_signature_with_bst(root: etree._Element, bst: etree._Element | None) -> bool:
    certificate = _load_bst_certificate(bst)
    if certificate is None:
        return False
    config = SignatureConfiguration(
        require_x509=True,
        expect_references=1,
        signature_methods=frozenset({SignatureMethod.RSA_SHA1}),
        digest_algorithms=frozenset({DigestAlgorithm.SHA1}),
        default_reference_c14n_method=CanonicalizationMethod.EXCLUSIVE_XML_CANONICALIZATION_1_0,
    )
    try:
        XMLVerifier().verify(
            root,
            x509_cert=certificate.public_bytes(serialization.Encoding.PEM),
            id_attribute="Id",
            expect_config=config,
            validate_schema=False,
        )
        return True
    except Exception:
        return False


def _load_bst_certificate(bst: etree._Element | None) -> x509.Certificate | None:
    if bst is None:
        return None
    value = bst.text or ""
    if not _bst_has_no_pem_marker(value):
        return None
    try:
        return x509.load_der_x509_certificate(base64.b64decode(value, validate=True))
    except ValueError:
        return None


def _dummy_material() -> SatEfirmMaterial:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Synthetic SAT Auth Lint")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1000)
        .not_valid_before(datetime(2024, 1, 1, tzinfo=timezone.utc))
        .not_valid_after(datetime(2030, 1, 1, tzinfo=timezone.utc))
        .sign(key, hashes.SHA256())
    )
    cert_der = cert.public_bytes(serialization.Encoding.DER)
    return SatEfirmMaterial(key, cert.public_bytes(serialization.Encoding.PEM), base64.b64encode(cert_der).decode("ascii"))
