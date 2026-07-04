"""Redacted SAT auth envelope fingerprints for local/oracle comparison."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
from pathlib import Path
import re
import shutil

from lxml import etree

from cfdi_vault.sat_live_smoke import ADDR_NS, DS_NS, SAT_AUTH_NS, SOAP11_NS, WSSE_NS, WSU_NS

_PREFIXES = {
    SOAP11_NS: "s",
    ADDR_NS: "addr",
    WSSE_NS: "o",
    WSU_NS: "u",
    DS_NS: "ds",
    SAT_AUTH_NS: "sat",
}


@dataclass(frozen=True)
class AuthEnvelopeFingerprint:
    envelope_sha256: str
    envelope_size: int
    ordered_element_paths: tuple[str, ...]
    namespaces: tuple[str, ...]
    attributes: tuple[str, ...]
    c14n_algorithm: str
    signature_algorithm: str
    digest_algorithms: tuple[str, ...]
    reference_uris_redacted: tuple[str, ...]
    bst_length: int
    signature_value_length: int
    digest_value_lengths: tuple[int, ...]
    has_header_action: bool
    header_action_order: str
    sec_ref_shape: str


@dataclass(frozen=True)
class PhpCfdiOracleFingerprint:
    available: bool
    php_available: bool
    composer_available: bool
    reason: str
    source_sha256: str
    has_header_action: bool
    header_action_order: str
    c14n_algorithm: str
    signature_algorithm: str
    digest_algorithm: str
    reference_uri_redacted: str
    sec_ref_shape: str
    request_operations: tuple[str, ...]
    setup_steps: tuple[str, ...]


def fingerprint_auth_envelope(envelope: bytes) -> AuthEnvelopeFingerprint:
    root = etree.fromstring(envelope)
    header = _child(root, SOAP11_NS, "Header")
    signed_info = root.find(f".//{{{DS_NS}}}SignedInfo")
    signature = root.find(f".//{{{DS_NS}}}Signature")
    bst = root.find(f".//{{{WSSE_NS}}}BinarySecurityToken")
    signature_value = root.find(f".//{{{DS_NS}}}SignatureValue")
    digest_values = tuple(root.findall(f".//{{{DS_NS}}}DigestValue"))
    references = tuple(root.findall(f".//{{{DS_NS}}}Reference"))
    paths = tuple(_element_paths(root))
    return AuthEnvelopeFingerprint(
        envelope_sha256=hashlib.sha256(envelope).hexdigest(),
        envelope_size=len(envelope),
        ordered_element_paths=paths,
        namespaces=tuple(sorted(ns for ns in {etree.QName(node).namespace for node in root.iter()} if ns)),
        attributes=tuple(_redacted_attributes(root)),
        c14n_algorithm=_method_algorithm(signed_info, "CanonicalizationMethod"),
        signature_algorithm=_method_algorithm(signed_info, "SignatureMethod"),
        digest_algorithms=tuple(_reference_method_algorithm(reference, "DigestMethod") for reference in references),
        reference_uris_redacted=tuple(_redact_uri(reference.get("URI") or "") for reference in references),
        bst_length=len((bst.text or "")) if bst is not None else 0,
        signature_value_length=len((signature_value.text or "")) if signature_value is not None else 0,
        digest_value_lengths=tuple(len(value.text or "") for value in digest_values),
        has_header_action=_child(header, ADDR_NS, "Action") is not None,
        header_action_order=_header_action_order(header),
        sec_ref_shape=_sec_ref_shape(signature),
    )


def fingerprint_phpcfdi_oracle(source_path: Path | None = None) -> PhpCfdiOracleFingerprint:
    php_available = shutil.which("php") is not None
    composer_available = shutil.which("composer") is not None
    setup_steps = ("Install PHP and Composer outside this repository.", "Create an external composer project with phpcfdi/sat-ws-descarga-masiva.", "Pass FielRequestBuilder.php with --phpcfdi-builder-source.")
    if source_path is None:
        return _phpcfdi_unavailable(php_available, composer_available, "phpcfdi-builder-source-not-provided", setup_steps)
    try:
        source = source_path.read_text(encoding="utf-8")
    except OSError:
        return _phpcfdi_unavailable(php_available, composer_available, "phpcfdi-builder-source-not-readable", setup_steps)

    action_index = _source_tag_index(source, "Action")
    security_index = _source_tag_index(source, "Security")
    has_action = action_index >= 0
    has_security = security_index >= 0
    if has_action and has_security:
        header_order = "action_before_security" if action_index < security_index else "security_before_action"
    elif has_security:
        header_order = "security_only"
    else:
        header_order = "unknown"
    return PhpCfdiOracleFingerprint(
        available=True,
        php_available=php_available,
        composer_available=composer_available,
        reason="ok",
        source_sha256=hashlib.sha256(source.encode("utf-8")).hexdigest(),
        has_header_action=has_action,
        header_action_order=header_order,
        c14n_algorithm=_source_algorithm(source, "CanonicalizationMethod"),
        signature_algorithm=_source_algorithm(source, "SignatureMethod"),
        digest_algorithm=_source_algorithm(source, "DigestMethod"),
        reference_uri_redacted="#<id>" if re.search(r"\bURI\s*=\s*['\"]", source) else "",
        sec_ref_shape="wsse-reference-to-bst" if "SecurityTokenReference" in source and "BinarySecurityToken" in source else "unknown",
        request_operations=tuple(operation for operation in ("SolicitaDescargaEmitidos", "SolicitaDescargaRecibidos", "SolicitaDescargaFolio") if operation in source),
        setup_steps=(),
    )


def _phpcfdi_unavailable(
    php_available: bool,
    composer_available: bool,
    reason: str,
    setup_steps: tuple[str, ...],
) -> PhpCfdiOracleFingerprint:
    return PhpCfdiOracleFingerprint(
        available=False,
        php_available=php_available,
        composer_available=composer_available,
        reason=reason,
        source_sha256="",
        has_header_action=False,
        header_action_order="unknown",
        c14n_algorithm="",
        signature_algorithm="",
        digest_algorithm="",
        reference_uri_redacted="",
        sec_ref_shape="unknown",
        request_operations=(),
        setup_steps=setup_steps,
    )


def _element_paths(root: etree._Element) -> tuple[str, ...]:
    paths: list[str] = []

    def visit(node: etree._Element, parent: str) -> None:
        path = f"{parent}/{_qualified_name(node)}"
        paths.append(path)
        for child in node:
            visit(child, path)

    visit(root, "")
    return tuple(paths)


def _redacted_attributes(root: etree._Element) -> tuple[str, ...]:
    values: list[str] = []
    for path, node in zip(_element_paths(root), root.iter(), strict=True):
        for raw_name, raw_value in sorted(node.attrib.items()):
            name = etree.QName(raw_name)
            values.append(f"{path}@{_qualified_name(name)}={_redact_attribute(name.localname, raw_value)}")
    return tuple(values)


def _qualified_name(value: etree._Element | etree.QName) -> str:
    name = etree.QName(value)
    return f"{_PREFIXES.get(name.namespace, 'ns')}:{name.localname}" if name.namespace else name.localname


def _redact_attribute(name: str, value: str) -> str:
    if name in {"Id"}:
        return "<id>"
    if name == "URI":
        return _redact_uri(value)
    if name in {"Algorithm", "EncodingType", "ValueType", "mustUnderstand"}:
        return value
    return "<redacted>"


def _redact_uri(uri: str) -> str:
    if not uri:
        return ""
    return "#<id>" if uri.startswith("#") else "<external-redacted>"


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


def _header_action_order(header: etree._Element | None) -> str:
    if header is None:
        return "missing_header"
    seen = [_qualified_name(child) for child in header]
    if "addr:Action" not in seen and "o:Security" in seen:
        return "security_only"
    if "addr:Action" not in seen or "o:Security" not in seen:
        return "missing_action_or_security"
    return "action_before_security" if seen.index("addr:Action") < seen.index("o:Security") else "security_before_action"


def _sec_ref_shape(signature: etree._Element | None) -> str:
    if signature is None:
        return "missing_signature"
    reference = signature.find(f".//{{{WSSE_NS}}}SecurityTokenReference/{{{WSSE_NS}}}Reference")
    if reference is not None:
        return "wsse-reference-to-bst"
    if signature.find(f".//{{{DS_NS}}}X509Data") is not None:
        return "ds-x509data"
    return "unknown"


def _source_algorithm(source: str, tag_name: str) -> str:
    match = re.search(
        rf"<(?:[A-Za-z_][\w.-]*:)?{re.escape(tag_name)}\b[^>]*\bAlgorithm\s*=\s*['\"]([^'\"]+)['\"]",
        source,
    )
    return match.group(1) if match else ""


def _source_tag_index(source: str, tag_name: str) -> int:
    match = re.search(rf"<(?:[A-Za-z_][\w.-]*:)?{re.escape(tag_name)}\b", source)
    return match.start() if match else -1
