"""Redacted SAT auth envelope fingerprints for local/oracle comparison."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import os
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
_CI_ENV_VARS = ("CI", "GITHUB_ACTIONS", "TF_BUILD")
PHP_CFDI_BUILDER_SOURCE_DISABLED_IN_CI = "phpcfdi-builder-source-disabled-in-ci"


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
    comparable_fields: tuple[tuple[str, str], ...]


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
    comparable_fields: tuple[tuple[str, str], ...]
    setup_steps: tuple[str, ...]


@dataclass(frozen=True)
class AuthOracleDiffItem:
    field: str
    status: str
    ours: str
    oracle: str
    likely_breaking: bool
    safe_hint: str


@dataclass(frozen=True)
class AuthOracleDiffResult:
    oracle: str
    oracle_available: bool
    local_envelope_sha256: str
    local_envelope_size: int
    oracle_source_sha256: str
    items: tuple[AuthOracleDiffItem, ...]
    likely_breaking: bool
    recommended_fix: str


def fingerprint_auth_envelope(envelope: bytes) -> AuthEnvelopeFingerprint:
    root = etree.fromstring(envelope)
    header = _child(root, SOAP11_NS, "Header")
    body = _child(root, SOAP11_NS, "Body")
    action = _child(header, ADDR_NS, "Action")
    security = _child(header, WSSE_NS, "Security")
    timestamp = _child(security, WSU_NS, "Timestamp")
    signed_info = root.find(f".//{{{DS_NS}}}SignedInfo")
    signature = root.find(f".//{{{DS_NS}}}Signature")
    key_info = _child(signature, DS_NS, "KeyInfo")
    bst = root.find(f".//{{{WSSE_NS}}}BinarySecurityToken")
    signature_value = root.find(f".//{{{DS_NS}}}SignatureValue")
    digest_values = tuple(root.findall(f".//{{{DS_NS}}}DigestValue"))
    references = tuple(root.findall(f".//{{{DS_NS}}}Reference"))
    paths = tuple(_element_paths(root))
    operation = next(iter(body), None) if body is not None and len(body) else None
    comparable = _local_comparable_fields(root, header, action, security, timestamp, bst, signature, signed_info, key_info, operation, references, paths)
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
        has_header_action=action is not None,
        header_action_order=_header_action_order(header),
        sec_ref_shape=_sec_ref_shape(signature),
        comparable_fields=comparable,
    )


def fingerprint_phpcfdi_oracle(source_path: Path | None = None) -> PhpCfdiOracleFingerprint:
    php_available = shutil.which("php") is not None
    composer_available = shutil.which("composer") is not None
    setup_steps = ("Install PHP and Composer outside this repository.", "Create an external composer project with phpcfdi/sat-ws-descarga-masiva.", "Pass FielRequestBuilder.php with --phpcfdi-builder-source.")
    if source_path is None:
        return _phpcfdi_unavailable(php_available, composer_available, "phpcfdi-builder-source-not-provided", setup_steps)
    if _ci_detected():
        return _phpcfdi_unavailable(
            php_available,
            composer_available,
            PHP_CFDI_BUILDER_SOURCE_DISABLED_IN_CI,
            ("Run external phpcfdi oracle source checks only from a local developer machine.",),
        )
    try:
        source = source_path.read_text(encoding="utf-8")
    except OSError:
        return _phpcfdi_unavailable(php_available, composer_available, "phpcfdi-builder-source-not-readable", setup_steps)

    auth_source = _source_auth_segment(source)
    action_index = _source_tag_index(auth_source, "Action")
    security_index = _source_tag_index(auth_source, "Security")
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
        sec_ref_shape="wsse-reference-to-bst" if "SecurityTokenReference" in auth_source and "BinarySecurityToken" in auth_source else "unknown",
        request_operations=tuple(operation for operation in ("SolicitaDescargaEmitidos", "SolicitaDescargaRecibidos", "SolicitaDescargaFolio") if operation in source),
        comparable_fields=_phpcfdi_comparable_fields(source, auth_source, header_order, has_action),
        setup_steps=(),
    )


def diff_auth_oracle(local: AuthEnvelopeFingerprint, oracle: PhpCfdiOracleFingerprint) -> AuthOracleDiffResult:
    local_fields = dict(local.comparable_fields)
    oracle_fields = dict(oracle.comparable_fields)
    items = tuple(
        _diff_item(field, local_fields.get(field, ""), oracle_fields.get(field, ""))
        for field in sorted(set(local_fields) | set(oracle_fields))
    )
    likely_breaking = any(item.likely_breaking for item in items)
    return AuthOracleDiffResult(
        oracle="phpcfdi",
        oracle_available=oracle.available,
        local_envelope_sha256=local.envelope_sha256,
        local_envelope_size=local.envelope_size,
        oracle_source_sha256=oracle.source_sha256,
        items=items,
        likely_breaking=likely_breaking,
        recommended_fix=_recommended_fix(items, oracle.available),
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
        comparable_fields=(),
        setup_steps=setup_steps,
    )


def _ci_detected() -> bool:
    return any(os.getenv(name) for name in _CI_ENV_VARS)


def _local_comparable_fields(
    root: etree._Element,
    header: etree._Element | None,
    action: etree._Element | None,
    security: etree._Element | None,
    timestamp: etree._Element | None,
    bst: etree._Element | None,
    signature: etree._Element | None,
    signed_info: etree._Element | None,
    key_info: etree._Element | None,
    operation: etree._Element | None,
    references: tuple[etree._Element, ...],
    paths: tuple[str, ...],
) -> tuple[tuple[str, str], ...]:
    reference = references[0] if references else None
    return (
        ("soap_envelope_namespace", etree.QName(root).namespace or ""),
        ("header_children_order", _children_order(header)),
        ("header_action_present", _yes_no(action is not None)),
        ("header_action_namespace", etree.QName(action).namespace if action is not None else "none"),
        ("security_namespace", etree.QName(security).namespace if security is not None else "none"),
        ("security_must_understand", _must_understand(security)),
        ("timestamp_path", _first_path(paths, "/o:Security/u:Timestamp")),
        ("timestamp_id_pattern", _id_pattern(_wsu_id(timestamp))),
        ("bst_path", _first_path(paths, "/o:Security/o:BinarySecurityToken")),
        ("bst_id_pattern", _id_pattern(_wsu_id(bst))),
        ("bst_value_type", bst.get("ValueType") if bst is not None else ""),
        ("bst_encoding_type", bst.get("EncodingType") if bst is not None else ""),
        ("signature_location", _first_path(paths, "/o:Security/ds:Signature")),
        ("signed_info_structure", _children_order(signed_info)),
        ("canonicalization_method", _method_algorithm(signed_info, "CanonicalizationMethod")),
        ("signature_method", _method_algorithm(signed_info, "SignatureMethod")),
        ("digest_method", _reference_method_algorithm(reference, "DigestMethod") if reference is not None else ""),
        ("reference_uri", _redact_uri(reference.get("URI") if reference is not None else "")),
        ("reference_target_path", _reference_target_path(root, paths, reference)),
        ("transforms", _transform_algorithms(reference)),
        ("sec_ref_shape", _sec_ref_shape(signature)),
        ("key_info_shape", _key_info_shape(key_info)),
        ("body_operation", etree.QName(operation).localname if operation is not None else ""),
        ("body_namespace", etree.QName(operation).namespace if operation is not None else ""),
        ("envelope_length", str(len(etree.tostring(root, encoding="UTF-8", xml_declaration=True)))),
        ("structural_hash", _structural_hash(paths, _redacted_attributes(root))),
    )


def _phpcfdi_comparable_fields(source: str, auth_source: str, header_order: str, has_action: bool) -> tuple[tuple[str, str], ...]:
    security_prefix, security_attrs = _source_tag(auth_source, "Security")
    envelope_prefix, envelope_attrs = _source_tag(auth_source, "Envelope")
    operation_prefix, operation_attrs = _source_tag(auth_source, "Autentica")
    signed_info = _source_children(source, "SignedInfo", ("CanonicalizationMethod", "SignatureMethod", "Reference"))
    return (
        ("soap_envelope_namespace", _source_xmlns(envelope_attrs, envelope_prefix)),
        ("header_children_order", "o:Security" if header_order == "security_only" else header_order),
        ("header_action_present", _yes_no(has_action)),
        ("header_action_namespace", "none" if not has_action else "unknown"),
        ("security_namespace", _source_xmlns(security_attrs, security_prefix)),
        ("security_must_understand", _source_attr(security_attrs, "mustUnderstand")),
        ("timestamp_path", "/s:Envelope/s:Header/o:Security/u:Timestamp"),
        ("timestamp_id_pattern", _id_pattern(_source_attr(_source_tag(auth_source, "Timestamp")[1], "Id"))),
        ("bst_path", "/s:Envelope/s:Header/o:Security/o:BinarySecurityToken"),
        ("bst_id_pattern", "uuid-*-1" if "createXmlSecurityTokenId" in source else "<id>"),
        ("bst_value_type", _source_attr(_source_tag(auth_source, "BinarySecurityToken")[1], "ValueType")),
        ("bst_encoding_type", _source_attr(_source_tag(auth_source, "BinarySecurityToken")[1], "EncodingType")),
        ("signature_location", "/s:Envelope/s:Header/o:Security/ds:Signature"),
        ("signed_info_structure", signed_info),
        ("canonicalization_method", _source_algorithm(source, "CanonicalizationMethod")),
        ("signature_method", _source_algorithm(source, "SignatureMethod")),
        ("digest_method", _source_algorithm(source, "DigestMethod")),
        ("reference_uri", "#<id>" if "createSignature($toDigestXml, '#_0'" in source else ""),
        ("reference_target_path", "/s:Envelope/s:Header/o:Security/u:Timestamp"),
        ("transforms", _source_algorithm(source, "Transform")),
        ("sec_ref_shape", "wsse-reference-to-bst" if "SecurityTokenReference" in auth_source else "unknown"),
        ("key_info_shape", "wsse-reference-to-bst" if "SecurityTokenReference" in auth_source else "unknown"),
        ("body_operation", _source_local_name(operation_prefix, "Autentica")),
        ("body_namespace", _source_attr(operation_attrs, "xmlns")),
        ("envelope_length", "source-template"),
        ("structural_hash", hashlib.sha256("|".join(_source_structural_markers(auth_source)).encode("utf-8")).hexdigest()),
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


def _children_order(node: etree._Element | None) -> str:
    return ",".join(_qualified_name(child) for child in node) if node is not None and len(node) else "none"


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


def _transform_algorithms(reference: etree._Element | None) -> str:
    if reference is None:
        return ""
    return ",".join(node.get("Algorithm") or "" for node in reference.findall(f".//{{{DS_NS}}}Transform")) or "none"


def _header_action_order(header: etree._Element | None) -> str:
    if header is None:
        return "missing_header"
    seen = [_qualified_name(child) for child in header]
    if "addr:Action" not in seen and "o:Security" in seen:
        return "security_only"
    if "addr:Action" not in seen or "o:Security" not in seen:
        return "missing_action_or_security"
    return "action_before_security" if seen.index("addr:Action") < seen.index("o:Security") else "security_before_action"


def _first_path(paths: tuple[str, ...], suffix: str) -> str:
    return next((path for path in paths if path.endswith(suffix)), "missing")


def _sec_ref_shape(signature: etree._Element | None) -> str:
    if signature is None:
        return "missing_signature"
    reference = signature.find(f".//{{{WSSE_NS}}}SecurityTokenReference/{{{WSSE_NS}}}Reference")
    if reference is not None:
        return "wsse-reference-to-bst"
    if signature.find(f".//{{{DS_NS}}}X509Data") is not None:
        return "ds-x509data"
    return "unknown"


def _key_info_shape(key_info: etree._Element | None) -> str:
    if key_info is None:
        return "missing_key_info"
    if key_info.find(f".//{{{WSSE_NS}}}SecurityTokenReference") is not None:
        return "wsse-reference-to-bst"
    if key_info.find(f".//{{{DS_NS}}}X509Data") is not None:
        return "ds-x509data"
    return "unknown"


def _reference_target_path(root: etree._Element, paths: tuple[str, ...], reference: etree._Element | None) -> str:
    target = (reference.get("URI") if reference is not None else "").lstrip("#")
    if not target:
        return ""
    for path, node in zip(paths, root.iter(), strict=True):
        if target in {node.get("Id"), node.get(f"{{{WSU_NS}}}Id")}:
            return path
    return "missing"


def _wsu_id(node: etree._Element | None) -> str:
    return node.get(f"{{{WSU_NS}}}Id") if node is not None else ""


def _id_pattern(value: str) -> str:
    if not value:
        return "missing"
    if value == "_0":
        return "_0"
    if re.fullmatch(r"uuid-[0-9a-fA-F-]+-1", value):
        return "uuid-*-1"
    return "<id>"


def _must_understand(node: etree._Element | None) -> str:
    return node.get(f"{{{SOAP11_NS}}}mustUnderstand") if node is not None else ""


def _yes_no(value: bool) -> str:
    return "yes" if value else "no"


def _structural_hash(paths: tuple[str, ...], attributes: tuple[str, ...]) -> str:
    return hashlib.sha256("|".join((*paths, *attributes)).encode("utf-8")).hexdigest()


def _source_algorithm(source: str, tag_name: str) -> str:
    match = re.search(
        rf"<(?:[A-Za-z_][\w.-]*:)?{re.escape(tag_name)}\b[^>]*\bAlgorithm\s*=\s*['\"]([^'\"]+)['\"]",
        source,
    )
    return match.group(1) if match else ""


def _source_tag_index(source: str, tag_name: str) -> int:
    match = re.search(rf"<(?:[A-Za-z_][\w.-]*:)?{re.escape(tag_name)}\b", source)
    return match.start() if match else -1


def _source_auth_segment(source: str) -> str:
    start = source.find("public function authorization")
    end = source.find("public function query", start)
    return source[start:end] if start >= 0 and end > start else source


def _source_tag(source: str, tag_name: str) -> tuple[str, str]:
    match = re.search(rf"<(?:(?P<prefix>[A-Za-z_][\w.-]*):)?{re.escape(tag_name)}\b(?P<attrs>[^>]*)>", source)
    return ((match.group("prefix") or ""), match.group("attrs")) if match else ("", "")


def _source_xmlns(attrs: str, prefix: str) -> str:
    name = f"xmlns:{prefix}" if prefix else "xmlns"
    return _source_attr(attrs, name)


def _source_attr(attrs: str, name: str) -> str:
    pattern = re.escape(name) if name == "xmlns" or ":" in name else rf"(?:[A-Za-z_][\w.-]*:)?{re.escape(name)}"
    match = re.search(rf"\b{pattern}\s*=\s*['\"]([^'\"]+)['\"]", attrs)
    return match.group(1) if match else ""


def _source_children(source: str, parent: str, children: tuple[str, ...]) -> str:
    parent_index = _source_tag_index(source, parent)
    if parent_index < 0:
        return "none"
    positions = [(child, _source_tag_index(source[parent_index:], child)) for child in children]
    return ",".join(f"ds:{child}" for child, index in positions if index >= 0) or "none"


def _source_local_name(prefix: str, fallback: str) -> str:
    return f"{prefix}:{fallback}" if prefix else fallback


def _source_structural_markers(source: str) -> tuple[str, ...]:
    return tuple(match.group(1) for match in re.finditer(r"</?([A-Za-z_][\w.-]*(?::[A-Za-z_][\w.-]*)?)\b", source))


def _diff_item(field: str, ours: str, oracle: str) -> AuthOracleDiffItem:
    if not ours and oracle:
        status = "missing_in_ours"
    elif ours and not oracle:
        status = "extra_in_ours"
    elif ours == oracle:
        status = "same"
    else:
        status = "different"
    likely_breaking = status != "same" and field in _LIKELY_BREAKING_FIELDS
    return AuthOracleDiffItem(field, status, ours or "none", oracle or "none", likely_breaking, _safe_hint(field, status))


_LIKELY_BREAKING_FIELDS = frozenset(
    {
        "header_action_present",
        "header_children_order",
        "security_namespace",
        "security_must_understand",
        "bst_value_type",
        "bst_encoding_type",
        "signature_location",
        "canonicalization_method",
        "signature_method",
        "digest_method",
        "reference_target_path",
        "sec_ref_shape",
        "key_info_shape",
        "body_operation",
        "body_namespace",
    }
)


def _safe_hint(field: str, status: str) -> str:
    if status == "same":
        return "aligned"
    if field == "header_action_present":
        return "align SOAP Header Action presence with oracle before another auth-smoke"
    if field == "header_children_order":
        return "align SOAP Header child order with oracle"
    if field in {"sec_ref_shape", "key_info_shape"}:
        return "align WS-Security KeyInfo reference shape"
    return "inspect redacted structural diff; do not print raw SOAP"


def _recommended_fix(items: tuple[AuthOracleDiffItem, ...], available: bool) -> str:
    if not available:
        return "provide external phpcfdi FielRequestBuilder.php"
    by_field = {item.field: item for item in items}
    action = by_field.get("header_action_present")
    if action and action.status != "same" and action.ours == "yes" and action.oracle == "no":
        return "add no-header-action auth envelope variant"
    if any(item.likely_breaking for item in items):
        return "align likely_breaking auth envelope fields"
    return "no high-confidence fix"
