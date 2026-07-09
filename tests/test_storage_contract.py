from __future__ import annotations

from datetime import datetime, timezone
import hashlib

import pytest

from cfdi_vault.storage_contract import (
    EvidenceReference,
    StorageCollisionError,
    StorageIOError,
    StorageKey,
    StorageNotFoundError,
)


def test_storage_keys_are_deterministic_normalized_and_hash_aware() -> None:
    period = datetime(2024, 1, 15, 12, 0, tzinfo=timezone.utc)
    digest = hashlib.sha256(b"synthetic evidence").hexdigest()

    package = StorageKey.package(" xaxx010101000 ", period, " PKG / 001 ", digest.upper())
    xml = StorageKey.xml("xaxx010101000", period, " abc-def ", digest)
    metadata = StorageKey.metadata("xaxx010101000", period, " request 001 ", digest, extension=".CSV")

    assert str(package) == f"XAXX010101000/packages/2024/01/PKG-001-{digest[:12]}.zip"
    assert str(xml) == f"XAXX010101000/xml/2024/01/ABC-DEF-{digest[:12]}.xml"
    assert str(metadata) == f"XAXX010101000/metadata/2024/01/request-001-{digest[:12]}.CSV"
    assert package == StorageKey.parse(str(package))


@pytest.mark.parametrize(
    "raw_key",
    [
        "",
        "/absolute/evidence.xml",
        "../outside.xml",
        "tenant/../outside.xml",
        "tenant//evidence.xml",
        "tenant\\evidence.xml",
        "C:/outside.xml",
        "tenant/evidence.xml ",
    ],
)
def test_storage_key_rejects_non_canonical_or_traversal_input(raw_key: str) -> None:
    with pytest.raises(ValueError, match="storage key"):
        StorageKey.parse(raw_key)


@pytest.mark.parametrize("digest", ["", "abc", "g" * 64])
def test_evidence_key_builders_reject_invalid_sha256(digest: str) -> None:
    period = datetime(2024, 1, 15, tzinfo=timezone.utc)

    with pytest.raises(ValueError, match="SHA-256"):
        StorageKey.package("XAXX010101000", period, "PKG-001", digest)


@pytest.mark.parametrize(
    ("sha256", "size_bytes", "message"),
    [("invalid", 1, "SHA-256"), ("0" * 64, -1, "size_bytes")],
)
def test_evidence_reference_rejects_invalid_hash_or_size(
    sha256: str,
    size_bytes: int,
    message: str,
) -> None:
    key = StorageKey.parse("XAXX010101000/xml/2024/01/SYNTHETIC.xml")

    with pytest.raises(ValueError, match=message):
        EvidenceReference(key=key, sha256=sha256, size_bytes=size_bytes)


def test_evidence_reference_normalizes_a_valid_string_key() -> None:
    raw_key = "XAXX010101000/xml/2024/01/SYNTHETIC.xml"

    reference = EvidenceReference(key=raw_key, sha256="0" * 64, size_bytes=0)

    assert reference.key == StorageKey.parse(raw_key)


@pytest.mark.parametrize("key", [None, 1.5, True, "../outside.xml"])
def test_evidence_reference_rejects_invalid_key_boundaries(key: object) -> None:
    with pytest.raises((TypeError, ValueError)):
        EvidenceReference(key=key, sha256="0" * 64, size_bytes=0)


@pytest.mark.parametrize("size_bytes", [None, "1", 1.5, True, False])
def test_evidence_reference_requires_a_non_boolean_integer_size(size_bytes: object) -> None:
    key = StorageKey.parse("XAXX010101000/xml/2024/01/SYNTHETIC.xml")

    with pytest.raises(TypeError, match="integer"):
        EvidenceReference(key=key, sha256="0" * 64, size_bytes=size_bytes)


def test_storage_error_messages_never_expose_evidence_identifiers() -> None:
    key = StorageKey.parse(
        "SYNTHETIC-RFC/packages/2024/01/ID-SOLICITUD-ID-PAQUETE-SYNTHETIC-UUID.zip"
    )

    errors = (
        StorageCollisionError(key),
        StorageNotFoundError(key),
        StorageIOError(key, "stat"),
    )

    for error in errors:
        assert error.key == key
        assert str(key) not in str(error)
        for identifier in ("SYNTHETIC-RFC", "ID-SOLICITUD", "ID-PAQUETE", "SYNTHETIC-UUID"):
            assert identifier not in str(error)
