from __future__ import annotations

from datetime import datetime, timezone
from io import BytesIO
from typing import Any

import pytest

from cfdi_vault.object_storage import S3CompatibleStorage
from cfdi_vault.storage import LocalStorage, sha256_bytes
from cfdi_vault.storage_contract import (
    EvidenceReference,
    StorageCollisionError,
    StorageIOError,
    StorageKey,
    StorageNotFoundError,
)


class FakeS3NotFound(Exception):
    def __init__(self) -> None:
        self.response = {"Error": {"Code": "NoSuchKey"}}


class FakeS3PreconditionFailed(Exception):
    def __init__(self) -> None:
        self.response = {
            "Error": {"Code": "PreconditionFailed"},
            "ResponseMetadata": {"HTTPStatusCode": 412},
        }


class FakeS3Client:
    def __init__(self) -> None:
        self.objects: dict[tuple[str, str], tuple[bytes, dict[str, str]]] = {}
        self.put_calls: list[dict[str, Any]] = []

    def put_object(self, **kwargs: Any) -> None:
        bucket = kwargs["Bucket"]
        key = kwargs["Key"]
        if kwargs.get("IfNoneMatch") == "*" and (bucket, key) in self.objects:
            raise FakeS3PreconditionFailed()
        body = kwargs["Body"]
        metadata = kwargs.get("Metadata", {})
        self.put_calls.append(kwargs)
        self.objects[(bucket, key)] = (body, metadata)

    def get_object(self, **kwargs: Any) -> dict[str, Any]:
        try:
            body, _metadata = self.objects[(kwargs["Bucket"], kwargs["Key"])]
        except KeyError:
            raise FakeS3NotFound() from None
        return {"Body": BytesIO(body)}

    def head_object(self, **kwargs: Any) -> dict[str, Any]:
        try:
            body, metadata = self.objects[(kwargs["Bucket"], kwargs["Key"])]
        except KeyError:
            raise FakeS3NotFound() from None
        return {"ContentLength": len(body), "Metadata": metadata}


def test_s3_compatible_storage_matches_local_reference_for_synthetic_xml(tmp_path) -> None:
    content = b"synthetic XML evidence bytes"
    digest = sha256_bytes(content)
    key = StorageKey.xml("XAXX010101000", datetime(2024, 1, 15, tzinfo=timezone.utc), "SYN-UUID", digest)
    local = LocalStorage(tmp_path / "storage")
    object_storage = S3CompatibleStorage(bucket="cfdi-vault-evidence", client=FakeS3Client())

    local_reference = local.write_bytes_idempotent(key, content).reference
    object_reference = object_storage.write_bytes_idempotent(key, content)

    assert object_reference == local_reference
    assert object_storage.read_bytes(key) == local.read_bytes(key)
    assert object_storage.stat(key) == local.stat(key)


def test_s3_compatible_storage_writes_hash_metadata_and_no_evidence_bytes() -> None:
    content = b"synthetic package bytes"
    digest = sha256_bytes(content)
    key = StorageKey.package("XAXX010101000", datetime(2024, 1, 15), "PKG-DUMMY", digest)
    client = FakeS3Client()
    storage = S3CompatibleStorage(bucket="cfdi-vault-evidence", client=client)

    reference = storage.write_bytes_idempotent(key, content)
    second_reference = storage.write_bytes_idempotent(key, content)

    assert reference == EvidenceReference(key=key, sha256=digest, size_bytes=len(content))
    assert second_reference == reference
    assert len(client.put_calls) == 1
    assert client.put_calls[0]["Metadata"] == {"sha256": digest, "size-bytes": str(len(content))}
    assert reference.as_dict() == {"storage_key": str(key), "sha256": digest, "size_bytes": len(content)}
    assert content not in str(reference.as_dict()).encode()


def test_s3_compatible_storage_uses_opaque_physical_object_keys() -> None:
    content = b"synthetic object bytes"
    digest = sha256_bytes(content)
    key = StorageKey.metadata(
        "XAXX010101000",
        datetime(2024, 1, 15),
        "REQ-SAT-RAW-123456",
        digest,
    )
    client = FakeS3Client()
    storage = S3CompatibleStorage(bucket="cfdi-vault-evidence", client=client)

    storage.write_bytes_idempotent(key, content)
    object_key = client.put_calls[0]["Key"]
    metadata = client.put_calls[0]["Metadata"]

    assert object_key.startswith("evidence/")
    assert object_key != str(key)
    assert len(object_key.removeprefix("evidence/")) == 64
    assert storage.read_bytes(key) == content
    assert storage.stat(key) == EvidenceReference(key=key, sha256=digest, size_bytes=len(content))
    for forbidden in ("XAXX010101000", "REQ-SAT-RAW-123456"):
        assert forbidden not in object_key
        assert forbidden not in str(metadata)


def test_s3_compatible_storage_opaque_key_hides_package_and_uuid_identifiers() -> None:
    content = b"synthetic package bytes"
    digest = sha256_bytes(content)
    package_key = StorageKey.package("XAXX010101000", datetime(2024, 1, 15), "PKG-SAT-RAW-987654", digest)
    xml_key = StorageKey.xml(
        "XAXX010101000",
        datetime(2024, 1, 15),
        "SYN-UUID-RAW-SAT-ID-001",
        digest,
    )
    client = FakeS3Client()
    storage = S3CompatibleStorage(bucket="cfdi-vault-evidence", client=client)

    storage.write_bytes_idempotent(package_key, content)
    storage.write_bytes_idempotent(xml_key, content)

    physical_keys = [call["Key"] for call in client.put_calls]
    assert physical_keys[0] != physical_keys[1]
    for object_key in physical_keys:
        for forbidden in (
            "XAXX010101000",
            "PKG-SAT-RAW-987654",
            "SYN-UUID-RAW-SAT-ID-001",
        ):
            assert forbidden not in object_key


def test_s3_compatible_storage_opaque_key_hides_raw_document_ids_and_fiscal_names() -> None:
    content = b"synthetic document bytes"
    key = StorageKey.parse("SYNTHETIC-FISCAL-NAME-SA-DE-CV/raw-documents/DOC-SAT-RAW-001.xml")
    client = FakeS3Client()
    storage = S3CompatibleStorage(bucket="cfdi-vault-evidence", client=client)

    storage.write_bytes_idempotent(key, content)
    object_key = client.put_calls[0]["Key"]
    metadata = client.put_calls[0]["Metadata"]

    for forbidden in ("SYNTHETIC-FISCAL-NAME-SA-DE-CV", "DOC-SAT-RAW-001", str(key)):
        assert forbidden not in object_key
        assert forbidden not in str(metadata)


def test_s3_compatible_storage_precondition_race_returns_existing_reference() -> None:
    class RacingClient(FakeS3Client):
        def __init__(self) -> None:
            super().__init__()
            self.raise_once = True

        def put_object(self, **kwargs: Any) -> None:
            if self.raise_once:
                self.raise_once = False
                self.objects[(kwargs["Bucket"], kwargs["Key"])] = (
                    kwargs["Body"],
                    kwargs.get("Metadata", {}),
                )
                raise FakeS3PreconditionFailed()
            super().put_object(**kwargs)

    content = b"synthetic race bytes"
    digest = sha256_bytes(content)
    key = StorageKey.package("XAXX010101000", datetime(2024, 1, 15), "PKG-RACE", digest)
    storage = S3CompatibleStorage(bucket="cfdi-vault-evidence", client=RacingClient())

    assert storage.write_bytes_idempotent(key, content) == EvidenceReference(
        key=key,
        sha256=digest,
        size_bytes=len(content),
    )


@pytest.mark.parametrize("bucket", ["Bad_Bucket", "ab", "bucket..name", "bucket-.name"])
def test_s3_compatible_storage_rejects_invalid_bucket_names_without_echo(bucket: str) -> None:
    with pytest.raises(ValueError, match="object storage bucket name is invalid") as caught:
        S3CompatibleStorage(bucket=bucket, client=FakeS3Client())

    assert bucket not in str(caught.value)


def test_s3_compatible_storage_refuses_different_bytes_for_existing_key() -> None:
    first = b"first synthetic object"
    key = StorageKey.xml("XAXX010101000", datetime(2024, 1, 15), "SYN-UUID", sha256_bytes(first))
    storage = S3CompatibleStorage(bucket="cfdi-vault-evidence", client=FakeS3Client())
    storage.write_bytes_idempotent(key, first)

    with pytest.raises(StorageCollisionError, match="storage write collision") as caught:
        storage.write_bytes_idempotent(key, b"second synthetic object")

    assert caught.value.key == key
    assert str(key) not in str(caught.value)
    assert storage.read_bytes(key) == first


@pytest.mark.parametrize("operation", ["read", "stat"])
def test_s3_compatible_storage_missing_objects_raise_adapter_neutral_errors(operation: str) -> None:
    key = StorageKey.parse("XAXX010101000/xml/2024/01/MISSING.xml")
    storage = S3CompatibleStorage(bucket="cfdi-vault-evidence", client=FakeS3Client())

    with pytest.raises(StorageNotFoundError, match=f"storage {operation} not found") as caught:
        getattr(storage, "read_bytes" if operation == "read" else operation)(key)

    assert caught.value.key == key
    assert str(key) not in str(caught.value)


def test_s3_compatible_storage_rejects_unsafe_keys_before_client_calls() -> None:
    client = FakeS3Client()
    storage = S3CompatibleStorage(bucket="cfdi-vault-evidence", client=client)

    with pytest.raises(ValueError, match="storage key"):
        storage.write_bytes_idempotent("../outside.xml", b"blocked")

    assert client.put_calls == []


def test_s3_compatible_storage_wraps_client_failures_without_key_or_bucket() -> None:
    class FailingClient(FakeS3Client):
        def put_object(self, **kwargs: Any) -> None:
            raise RuntimeError(f"boom {kwargs['Bucket']} {kwargs['Key']}")

    key = StorageKey.parse("XAXX010101000/xml/2024/01/SYNTHETIC.xml")
    storage = S3CompatibleStorage(bucket="private-bucket-name", client=FailingClient())

    with pytest.raises(StorageIOError, match="storage write failed") as caught:
        storage.write_bytes_idempotent(key, b"synthetic")

    assert str(key) not in str(caught.value)
    assert "private-bucket-name" not in str(caught.value)
