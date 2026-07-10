"""Safety validators for reference-only queue contracts."""

from __future__ import annotations

import json
import re


_REASON_CODE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
_RFC_SHAPE = re.compile(r"^[A-ZÑ&]{3,4}\d{6}[A-Z0-9]{3}$")
_BASE64ISH = re.compile(r"^[A-Za-z0-9+/=\s]{80,}$")
_CREDENTIAL_MARKERS = (
    "api_key",
    "apikey",
    "authorization:",
    "bearer ",
    "client_secret",
    "password",
    "private_key",
    "secret",
    "token",
    "-----begin",
)
_SERIALIZED_MARKERS = (
    "criteria",
    "payload",
    "requester_rfc",
    "issuer_rfc",
    "receiver_rfc",
    "rfc",
    "soap",
    "xml",
    "zip",
)


def validate_reason_code(reason_code: str) -> str:
    """Return a safe machine reason code or raise ``ValueError``."""

    if not isinstance(reason_code, str) or not _REASON_CODE.fullmatch(reason_code):
        raise ValueError("queue reason_code must be a safe machine identifier")
    return reason_code


def validate_reference_string(name: str, value: str, *, allow_rfc: bool = False) -> str:
    """Reject sensitive-looking content from queue reference fields."""

    if not isinstance(value, str):
        raise TypeError(f"worker {name} must be a string")
    stripped = value.strip()
    if not stripped:
        raise ValueError(f"worker {name} cannot be empty")
    lowered = stripped.lower()
    uppered = stripped.upper()
    compact = "".join(stripped.split())

    if stripped.startswith("<") or "<?xml" in lowered or "<soap" in lowered or "</" in stripped:
        raise ValueError(f"worker {name} must be a reference, not raw XML/SOAP content")
    if uppered.startswith("PK") or compact.startswith(("UEsDB", "UEsDBBQ")) or _BASE64ISH.fullmatch(stripped):
        raise ValueError(f"worker {name} must be a reference, not raw ZIP/base64 content")
    if not allow_rfc and _RFC_SHAPE.fullmatch(uppered):
        raise ValueError(f"worker {name} must not contain RFC-shaped values")
    if any(marker in lowered for marker in _CREDENTIAL_MARKERS):
        raise ValueError(f"worker {name} must not contain token, secret, or password content")
    if _looks_like_serialized_payload(stripped, lowered):
        raise ValueError(f"worker {name} must be a reference, not serialized criteria or payload content")
    return value


def _looks_like_serialized_payload(stripped: str, lowered: str) -> bool:
    if stripped[:1] in {"{", "["}:
        try:
            decoded = json.loads(stripped)
        except json.JSONDecodeError:
            return True
        return isinstance(decoded, (dict, list))
    return any(f"{marker}=" in lowered or f'"{marker}"' in lowered for marker in _SERIALIZED_MARKERS)
