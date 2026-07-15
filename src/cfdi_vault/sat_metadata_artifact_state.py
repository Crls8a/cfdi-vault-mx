"""Private, redacted-safe artifact evidence for SAT metadata packages."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Mapping

from cfdi_vault.sat_metadata_package import (
    MetadataTextInspection,
    ProcessedMetadataPackage,
    StoredMetadataText,
)

_SCHEMA_VERSION = 1
_HASH_RE = re.compile(r"[0-9a-f]{64}")
_PACKAGE_REF_RE = re.compile(r"pkg-[0-9a-f]{12}")
_PACKAGE_KEY_RE = re.compile(
    r"sat-metadata/(?P<run>run-[0-9a-f]{12})/packages/"
    r"(?P<ordinal>[1-9][0-9]*)-(?P<digest>[0-9a-f]{12})\.zip"
)
_TEXT_KEY_RE = re.compile(
    r"sat-metadata/(?P<run>run-[0-9a-f]{12})/txt/"
    r"(?P<ordinal>[1-9][0-9]*)(?:-(?P<entry>[1-9][0-9]*))?-(?P<digest>[0-9a-f]{12})\.txt"
)
_DELIMITERS = {None, "~", "\t", "|", ","}
_STATE_KEYS = {
    "schemaVersion", "packageRef", "packageSha256", "packageStorageKey", "packageWritten", "texts",
}
_TEXT_KEYS = {"sha256", "storageKey", "written", "inspection"}
_INSPECTION_KEYS = {"encoding", "delimiter", "headers", "columnCount", "recordsPresent"}

class MetadataArtifactStateError(ValueError):
    """Raised with a safe code when private artifact state is invalid."""

@dataclass(frozen=True, repr=False)
class MetadataTextArtifact:
    """Bind one TXT digest and opaque key to structural evidence."""

    sha256: str
    storage_key: str
    written: bool
    inspection: MetadataTextInspection

@dataclass(frozen=True, repr=False)
class MetadataPackageArtifactState:
    """Immutable private evidence for exactly one opaque package reference."""

    package_ref: str
    package_sha256: str
    package_storage_key: str
    package_written: bool
    texts: tuple[MetadataTextArtifact, ...]
    def __post_init__(self) -> None:
        _validate_state(self)
    def __repr__(self) -> str:
        return (
            "MetadataPackageArtifactState("
            f"package_ref={self.package_ref!r}, zip_valid=True, "
            f"package_written={self.package_written!r}, txt_count={len(self.texts)})"
        )
    @classmethod
    def from_processed(cls, package_ref: str, processed: ProcessedMetadataPackage) -> MetadataPackageArtifactState:
        """Create validated evidence from the safe ZIP-to-TXT processor result."""
        failed = False
        try:
            if not isinstance(processed, ProcessedMetadataPackage):
                raise MetadataArtifactStateError("artifact-state-invalid")
            state = cls(
                package_ref=package_ref,
                package_sha256=processed.package_sha256,
                package_storage_key=processed.package_storage_key,
                package_written=processed.package_written,
                texts=tuple(_from_stored_text(item) for item in processed.texts),
            )
        except Exception:
            failed = True
        if failed:
            raise MetadataArtifactStateError("artifact-state-invalid") from None
        return state
    @classmethod
    def from_private_document(cls, value: object) -> MetadataPackageArtifactState:
        """Deserialize one strict versioned private document without leaking it."""
        failed = False
        try:
            document = _mapping(value, _STATE_KEYS)
            version = document["schemaVersion"]
            if type(version) is not int or version != _SCHEMA_VERSION:
                raise MetadataArtifactStateError("artifact-state-invalid")
            texts_value = document["texts"]
            if not isinstance(texts_value, list):
                raise MetadataArtifactStateError("artifact-state-invalid")
            state = cls(
                package_ref=_string(document, "packageRef"),
                package_sha256=_string(document, "packageSha256"),
                package_storage_key=_string(document, "packageStorageKey"),
                package_written=_boolean(document, "packageWritten"),
                texts=tuple(_text_from_document(item) for item in texts_value),
            )
        except Exception:
            failed = True
        if failed:
            raise MetadataArtifactStateError("artifact-state-invalid") from None
        return state
    @classmethod
    def from_private_json(cls, payload: str) -> MetadataPackageArtifactState:
        """Parse strict JSON, rejecting duplicate keys and private parse errors."""
        failed = False
        try:
            if type(payload) is not str:
                raise MetadataArtifactStateError("artifact-state-invalid")
            document = json.loads(payload, object_pairs_hook=_unique_object)
            state = cls.from_private_document(document)
        except Exception:
            failed = True
        if failed:
            raise MetadataArtifactStateError("artifact-state-invalid") from None
        return state
    def to_private_document(self) -> dict[str, object]:
        """Serialize hashes and opaque keys only for private external storage."""
        return {
            "schemaVersion": _SCHEMA_VERSION,
            "packageRef": self.package_ref,
            "packageSha256": self.package_sha256,
            "packageStorageKey": self.package_storage_key,
            "packageWritten": self.package_written,
            "texts": [_text_document(item, private=True) for item in self.texts],
        }
    def to_private_json(self) -> str:
        """Return deterministic private JSON suitable for external local state."""
        return json.dumps(self.to_private_document(), sort_keys=True, separators=(",", ":"))
    def to_redacted_document(self) -> dict[str, object]:
        """Expose only the safe reference and structural processing evidence."""
        return {
            "packageRef": self.package_ref,
            "zipValid": True,
            "packageWritten": self.package_written,
            "txtCount": len(self.texts),
            "texts": [_text_document(item, private=False) for item in self.texts],
        }

def _from_stored_text(value: StoredMetadataText) -> MetadataTextArtifact:
    if not isinstance(value, StoredMetadataText):
        raise MetadataArtifactStateError("artifact-state-invalid")
    return MetadataTextArtifact(value.sha256, value.storage_key, value.written, value.inspection)

def _validate_state(state: MetadataPackageArtifactState) -> None:
    package_match = _PACKAGE_KEY_RE.fullmatch(state.package_storage_key) if type(state.package_storage_key) is str else None
    if (
        type(state.package_ref) is not str or not _PACKAGE_REF_RE.fullmatch(state.package_ref)
        or not _valid_hash(state.package_sha256) or package_match is None
        or package_match["digest"] != state.package_sha256[:12]
        or type(state.package_written) is not bool or not isinstance(state.texts, tuple) or not state.texts
    ):
        raise MetadataArtifactStateError("artifact-state-invalid")
    keys: set[str] = set()
    for index, text in enumerate(state.texts, start=1):
        if not isinstance(text, MetadataTextArtifact) or not _valid_inspection(text.inspection):
            raise MetadataArtifactStateError("artifact-state-invalid")
        match = _TEXT_KEY_RE.fullmatch(text.storage_key) if type(text.storage_key) is str else None
        expected_entry = None if len(state.texts) == 1 else str(index)
        if (
            not _valid_hash(text.sha256) or type(text.written) is not bool or match is None
            or match["run"] != package_match["run"] or match["ordinal"] != package_match["ordinal"]
            or match["entry"] != expected_entry or match["digest"] != text.sha256[:12]
            or text.storage_key in keys
        ):
            raise MetadataArtifactStateError("artifact-state-invalid")
        keys.add(text.storage_key)

def _valid_inspection(value: object) -> bool:
    if not isinstance(value, MetadataTextInspection):
        return False
    headers = value.headers
    return (
        value.encoding == "utf-8-sig" and value.delimiter in _DELIMITERS
        and isinstance(headers, tuple) and all(type(item) is str and "\n" not in item and "\r" not in item for item in headers)
        and type(value.column_count) is int and value.column_count == len(headers)
        and (value.delimiter is None or value.column_count >= 2)
        and type(value.records_present) is bool
    )

def _valid_hash(value: object) -> bool:
    return type(value) is str and _HASH_RE.fullmatch(value) is not None

def _text_document(value: MetadataTextArtifact, *, private: bool) -> dict[str, object]:
    inspection = value.inspection
    structural = {
        "written": value.written,
        "encoding": inspection.encoding,
        "delimiter": inspection.delimiter,
        "headers": list(inspection.headers),
        "columnCount": inspection.column_count,
        "recordsPresent": inspection.records_present,
    }
    if not private:
        return structural
    return {
        "sha256": value.sha256,
        "storageKey": value.storage_key,
        "written": value.written,
        "inspection": {key: structural[key] for key in structural if key != "written"},
    }

def _text_from_document(value: object) -> MetadataTextArtifact:
    document = _mapping(value, _TEXT_KEYS)
    inspection = _mapping(document["inspection"], _INSPECTION_KEYS)
    headers = inspection["headers"]
    if not isinstance(headers, list) or not all(type(item) is str for item in headers):
        raise MetadataArtifactStateError("artifact-state-invalid")
    column_count = inspection["columnCount"]
    records_present = inspection["recordsPresent"]
    if type(column_count) is not int or type(records_present) is not bool:
        raise MetadataArtifactStateError("artifact-state-invalid")
    delimiter = inspection["delimiter"]
    if delimiter is not None and type(delimiter) is not str:
        raise MetadataArtifactStateError("artifact-state-invalid")
    return MetadataTextArtifact(
        _string(document, "sha256"), _string(document, "storageKey"), _boolean(document, "written"),
        MetadataTextInspection(_string(inspection, "encoding"), delimiter, tuple(headers), column_count, records_present),
    )

def _mapping(value: object, keys: set[str]) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or set(value) != keys:
        raise MetadataArtifactStateError("artifact-state-invalid")
    return value

def _string(document: Mapping[str, object], key: str) -> str:
    value = document[key]
    if type(value) is not str:
        raise MetadataArtifactStateError("artifact-state-invalid")
    return value

def _boolean(document: Mapping[str, object], key: str) -> bool:
    value = document[key]
    if type(value) is not bool:
        raise MetadataArtifactStateError("artifact-state-invalid")
    return value

def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    document: dict[str, object] = {}
    for key, value in pairs:
        if key in document:
            raise MetadataArtifactStateError("artifact-state-invalid")
        document[key] = value
    return document
