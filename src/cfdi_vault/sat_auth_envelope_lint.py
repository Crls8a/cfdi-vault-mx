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

from cfdi_vault.sat_live_smoke import (
    ADDR_NS,
    DS_NS,
    SAT_AUTH_NS,
    SOAP11_NS,
    WSSE_NS,
    WSU_NS,
    SatEfirmMaterial,
    _build_auth_envelope,
)


@dataclass(frozen=True)
class AuthEnvelopeLintResult:
    envelope_sha256: str
    envelope_size: int
    soap_envelope: bool
    soap_header: bool
    soap_body: bool
    operation_auth: bool
    ws_security: bool
    timestamp: bool
    timestamp_window_ok: bool
    bst_present: bool
    bst_der: bool
    bst_size: int
    signature: bool
    signed_info: bool
    reference_count: int
    references_resolve: bool
    digest_value: bool
    signature_value: bool
    key_info: bool
    sec_ref: bool
    timestamp_signed: bool
    to_header_present: bool
    action_header_present: bool
    all_checks_passed: bool


def build_dummy_auth_envelope(endpoint: str) -> bytes:
    return _build_auth_envelope(_dummy_material(), endpoint)


def lint_auth_envelope(envelope: bytes, *, now: datetime | None = None) -> AuthEnvelopeLintResult:
    root = etree.fromstring(envelope)
    header = root.find(f"{{{SOAP11_NS}}}Header")
    body = root.find(f"{{{SOAP11_NS}}}Body")
    security = header.find(f"{{{WSSE_NS}}}Security") if header is not None else None
    timestamp = security.find(f"{{{WSU_NS}}}Timestamp") if security is not None else None
    bst = security.find(f"{{{WSSE_NS}}}BinarySecurityToken") if security is not None else None
    signature = security.find(f"{{{DS_NS}}}Signature") if security is not None else None
    signed_info = signature.find(f"{{{DS_NS}}}SignedInfo") if signature is not None else None
    references = signed_info.findall(f".//{{{DS_NS}}}Reference") if signed_info is not None else []
    existing_ids = _collect_ids(root)
    result = AuthEnvelopeLintResult(
        envelope_sha256=hashlib.sha256(envelope).hexdigest(),
        envelope_size=len(envelope),
        soap_envelope=root.tag == f"{{{SOAP11_NS}}}Envelope",
        soap_header=header is not None,
        soap_body=body is not None,
        operation_auth=body.find(f"{{{SAT_AUTH_NS}}}Autentica") is not None if body is not None else False,
        ws_security=security is not None,
        timestamp=timestamp is not None,
        timestamp_window_ok=_timestamp_window_ok(timestamp, now=now or datetime.now(timezone.utc)),
        bst_present=bst is not None,
        bst_der=_bst_is_der_base64(bst.text if bst is not None else ""),
        bst_size=len((bst.text or "")) if bst is not None else 0,
        signature=signature is not None,
        signed_info=signed_info is not None,
        reference_count=len(references),
        references_resolve=bool(references) and all((ref.get("URI") or "").lstrip("#") in existing_ids for ref in references),
        digest_value=signature.find(f".//{{{DS_NS}}}DigestValue") is not None if signature is not None else False,
        signature_value=signature.find(f".//{{{DS_NS}}}SignatureValue") is not None if signature is not None else False,
        key_info=signature.find(f"{{{DS_NS}}}KeyInfo") is not None if signature is not None else False,
        sec_ref=signature.find(f".//{{{WSSE_NS}}}SecurityTokenReference") is not None if signature is not None else False,
        timestamp_signed=any((ref.get("URI") or "").lstrip("#") == (timestamp.get(f"{{{WSU_NS}}}Id") if timestamp is not None else "") for ref in references),
        to_header_present=header.find(f"{{{ADDR_NS}}}To") is not None if header is not None else False,
        action_header_present=header.find(f"{{{ADDR_NS}}}Action") is not None if header is not None else False,
        all_checks_passed=False,
    )
    checks = [value for key, value in result.__dict__.items() if isinstance(value, bool) and key != "all_checks_passed"]
    return AuthEnvelopeLintResult(**{**result.__dict__, "all_checks_passed": all(checks)})


def _collect_ids(root: etree._Element) -> set[str]:
    ids: set[str] = set()
    for node in root.iter():
        for value in (node.get("Id"), node.get(f"{{{WSU_NS}}}Id")):
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
        return bool(base64.b64decode(value, validate=True))
    except ValueError:
        return False


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
