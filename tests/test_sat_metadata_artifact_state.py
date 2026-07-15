from __future__ import annotations

import copy
import json
from collections import UserDict
from dataclasses import FrozenInstanceError

import pytest

from cfdi_vault.sat_metadata_artifact_state import (
    MetadataArtifactStateError,
    MetadataPackageArtifactState,
)
from cfdi_vault.sat_metadata_package import (
    MetadataTextInspection,
    ProcessedMetadataPackage,
    StoredMetadataText,
)

RUN_REF = "run-0123456789ab"
PACKAGE_REF = "pkg-abcdef012345"
PACKAGE_SHA = "1" * 64
TEXT_SHA = "2" * 64

def _processed(*, package_key: str | None = None, text_key: str | None = None) -> ProcessedMetadataPackage:
    return ProcessedMetadataPackage(
        package_sha256=PACKAGE_SHA,
        package_storage_key=package_key or f"sat-metadata/{RUN_REF}/packages/3-{PACKAGE_SHA[:12]}.zip",
        package_written=True,
        texts=(
            StoredMetadataText(
                sha256=TEXT_SHA,
                storage_key=text_key or f"sat-metadata/{RUN_REF}/txt/3-{TEXT_SHA[:12]}.txt",
                written=True,
                inspection=MetadataTextInspection("utf-8-sig", "~", ("Header", "Status"), 2, True),
            ),
        ),
    )

def _document() -> dict[str, object]:
    return MetadataPackageArtifactState.from_processed(PACKAGE_REF, _processed()).to_private_document()


def _unsupported_encoding_processed() -> ProcessedMetadataPackage:
    processed = _processed()
    text = processed.texts[0]
    return ProcessedMetadataPackage(
        processed.package_sha256,
        processed.package_storage_key,
        processed.package_written,
        (
            StoredMetadataText(
                text.sha256,
                text.storage_key,
                text.written,
                MetadataTextInspection("unsupported_encoding", None, (), 0, False),
            ),
        ),
    )

def test_from_processed_round_trips_private_state_and_redacts_repr_and_output() -> None:
    state = MetadataPackageArtifactState.from_processed(PACKAGE_REF, _processed())

    restored = MetadataPackageArtifactState.from_private_json(state.to_private_json())

    assert restored == state
    assert state.to_redacted_document() == {
        "packageRef": PACKAGE_REF,
        "zipValid": True,
        "packageWritten": True,
        "txtCount": 1,
        "texts": [{
            "written": True,
            "encoding": "utf-8-sig",
            "delimiter": "~",
            "headers": ["Header", "Status"],
            "columnCount": 2,
            "recordsPresent": True,
        }],
    }
    private_values = (PACKAGE_SHA, TEXT_SHA, "sat-metadata/", RUN_REF, "Header")
    assert all(value not in output for value in private_values for output in (repr(state), repr(state.texts[0])))
    with pytest.raises(FrozenInstanceError):
        state.package_ref = "pkg-000000000000"  # type: ignore[misc]


def test_unsupported_encoding_round_trips_losslessly_and_redacts_as_category_only() -> None:
    state = MetadataPackageArtifactState.from_processed(PACKAGE_REF, _unsupported_encoding_processed())

    restored = MetadataPackageArtifactState.from_private_json(state.to_private_json())

    assert restored == state
    assert restored.texts[0].inspection == MetadataTextInspection(
        "unsupported_encoding", None, (), 0, False
    )
    assert state.to_redacted_document()["texts"] == [
        {"written": True, "encoding": "unsupported_encoding"}
    ]


@pytest.mark.parametrize(
    "inspection",
    [
        MetadataTextInspection("unsupported_encoding", "~", (), 0, False),
        MetadataTextInspection("unsupported_encoding", None, ("Header",), 0, False),
        MetadataTextInspection("unsupported_encoding", None, (), 1, False),
        MetadataTextInspection("unsupported_encoding", None, (), 0, True),
    ],
)
def test_unsupported_encoding_rejects_non_sentinel_field_combinations(
    inspection: MetadataTextInspection,
) -> None:
    processed = _unsupported_encoding_processed()
    text = processed.texts[0]
    invalid = ProcessedMetadataPackage(
        processed.package_sha256,
        processed.package_storage_key,
        processed.package_written,
        (StoredMetadataText(text.sha256, text.storage_key, text.written, inspection),),
    )

    with pytest.raises(MetadataArtifactStateError, match="artifact-state-invalid"):
        MetadataPackageArtifactState.from_processed(PACKAGE_REF, invalid)

def test_multiple_texts_require_deterministic_keys_but_allow_identical_content_hashes() -> None:
    text = _processed().texts[0]
    processed = ProcessedMetadataPackage(
        PACKAGE_SHA,
        f"sat-metadata/{RUN_REF}/packages/3-{PACKAGE_SHA[:12]}.zip",
        False,
        (
            StoredMetadataText(TEXT_SHA, f"sat-metadata/{RUN_REF}/txt/3-1-{TEXT_SHA[:12]}.txt", False, text.inspection),
            StoredMetadataText(TEXT_SHA, f"sat-metadata/{RUN_REF}/txt/3-2-{TEXT_SHA[:12]}.txt", False, text.inspection),
        ),
    )

    state = MetadataPackageArtifactState.from_processed(PACKAGE_REF, processed)

    assert [item.storage_key for item in state.texts] == [item.storage_key for item in processed.texts]

@pytest.mark.parametrize(
    ("path", "value"),
    [
        (("schemaVersion",), 2),
        (("packageRef",), "raw-sat-id"),
        (("packageSha256",), "A" * 64),
        (("packageStorageKey",), f"sat-metadata/{RUN_REF}/packages/3-{'9' * 12}.zip"),
        (("packageStorageKey",), f"sat-metadata/{RUN_REF}/packages/../private.zip"),
        (("packageWritten",), 1),
        (("texts", 0, "sha256"), "3" * 64),
        (("texts", 0, "storageKey"), f"sat-metadata/run-ffffffffffff/txt/3-{TEXT_SHA[:12]}.txt"),
        (("texts", 0, "written"), 1),
        (("texts", 0, "inspection", "encoding"), "latin-1"),
        (("texts", 0, "inspection", "delimiter"), ";"),
        (("texts", 0, "inspection", "headers"), ["OnlyOne"]),
        (("texts", 0, "inspection", "columnCount"), True),
        (("texts", 0, "inspection", "recordsPresent"), 1),
    ],
)
def test_private_document_fails_closed_on_invalid_native_values(path: tuple[object, ...], value: object) -> None:
    document = copy.deepcopy(_document())
    target: object = document
    for part in path[:-1]:
        target = target[part]  # type: ignore[index]
    target[path[-1]] = value  # type: ignore[index]

    with pytest.raises(MetadataArtifactStateError, match="artifact-state-invalid"):
        MetadataPackageArtifactState.from_private_document(document)

def test_private_document_rejects_unexpected_and_duplicate_text_keys() -> None:
    unexpected = _document()
    unexpected["privatePath"] = "C:/private"
    duplicate = _document()
    duplicate["texts"] = [duplicate["texts"][0], duplicate["texts"][0]]  # type: ignore[index]

    for document in (unexpected, duplicate):
        with pytest.raises(MetadataArtifactStateError, match="artifact-state-invalid"):
            MetadataPackageArtifactState.from_private_document(document)


class _DictSubclass(dict[str, object]):
    pass


class _ListSubclass(list[object]):
    pass


class _StringSubclass(str):
    pass


class _IntegerSubclass(int):
    pass


def _replace_top_level_key_with_subclass(document: dict[str, object]) -> object:
    value = document.pop("packageRef")
    document[_StringSubclass("packageRef")] = value
    return document


@pytest.mark.parametrize(
    "mutate",
    [
        lambda document: UserDict(document),
        lambda document: _DictSubclass(document),
        lambda document: {**document, "texts": _ListSubclass(document["texts"])},
        lambda document: {
            **document,
            "texts": [UserDict(document["texts"][0])],  # type: ignore[index]
        },
        lambda document: {
            **document,
            "texts": [{
                **document["texts"][0],  # type: ignore[index]
                "inspection": UserDict(document["texts"][0]["inspection"]),  # type: ignore[index]
            }],
        },
        lambda document: {
            **document,
            "texts": [{
                **document["texts"][0],  # type: ignore[index]
                "inspection": {
                    **document["texts"][0]["inspection"],  # type: ignore[index]
                    "headers": _ListSubclass(
                        document["texts"][0]["inspection"]["headers"]  # type: ignore[index]
                    ),
                },
            }],
        },
        _replace_top_level_key_with_subclass,
        lambda document: {**document, "schemaVersion": _IntegerSubclass(1)},
        lambda document: {**document, "packageRef": _StringSubclass(PACKAGE_REF)},
    ],
)
def test_private_document_requires_exact_native_json_types(mutate: object) -> None:
    document = _document()

    with pytest.raises(MetadataArtifactStateError, match="artifact-state-invalid"):
        MetadataPackageArtifactState.from_private_document(mutate(document))  # type: ignore[operator]

def test_private_json_rejects_duplicate_keys_without_retaining_private_input() -> None:
    private = "private-member-name"
    payload = json.dumps(_document()).replace('"packageRef":', f'"private": "{private}", "private": 1, "packageRef":')

    with pytest.raises(MetadataArtifactStateError) as captured:
        MetadataPackageArtifactState.from_private_json(payload)

    assert captured.value.__cause__ is None
    assert captured.value.__context__ is None
    assert private not in repr(captured.value)

@pytest.mark.parametrize(
    ("package_key", "text_key"),
    [
        (f"sat-metadata/{RUN_REF}/packages/3-{PACKAGE_SHA[:12]}.zip", "C:/private.txt"),
        (f"sat-metadata/{RUN_REF}/packages/3-{PACKAGE_SHA[:12]}.zip", f"sat-metadata/{RUN_REF}/txt/4-{TEXT_SHA[:12]}.txt"),
        (f"sat-metadata/{RUN_REF}/packages/3-{PACKAGE_SHA[:12]}.zip", f"sat-metadata/{RUN_REF}/txt/3\\{TEXT_SHA[:12]}.txt"),
    ],
)
def test_from_processed_rejects_unsafe_or_incoherent_storage_keys(package_key: str, text_key: str) -> None:
    with pytest.raises(MetadataArtifactStateError, match="artifact-state-invalid"):
        MetadataPackageArtifactState.from_processed(
            PACKAGE_REF,
            _processed(package_key=package_key, text_key=text_key),
        )
