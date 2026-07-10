"""S3-compatible object storage adapter for optional evidence storage labs.

The adapter implements the same ``StoragePort`` contract as ``LocalStorage`` but
does not make MinIO, S3, or boto3 part of the default runtime. Callers inject a
compatible client, or opt in through ``from_boto3`` after installing the
``object-storage`` extra.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import re
from typing import Any, Protocol, runtime_checkable

from cfdi_vault.storage import sha256_bytes
from cfdi_vault.storage_contract import (
    EvidenceReference,
    StorageCollisionError,
    StorageError,
    StorageIOError,
    StorageKey,
    StorageNotFoundError,
)


@runtime_checkable
class S3ObjectClient(Protocol):
    """Minimal S3-compatible client surface used by ``S3CompatibleStorage``."""

    def put_object(self, **kwargs: Any) -> Any:
        """Write an object."""

    def get_object(self, **kwargs: Any) -> dict[str, Any]:
        """Read an object and return a body-like stream."""

    def head_object(self, **kwargs: Any) -> dict[str, Any]:
        """Return object metadata without returning the object body."""


@dataclass(frozen=True, slots=True)
class S3CompatibleStorage:
    """StoragePort adapter for MinIO or another S3-compatible object store.

    Public ``StorageKey`` values may contain fiscal identifiers required by the
    control plane. This adapter never sends those values to S3/MinIO object
    keys or metadata; it derives a deterministic opaque physical key instead.
    """

    bucket: str
    client: S3ObjectClient

    def __post_init__(self) -> None:
        _validate_bucket_name(self.bucket)

    @classmethod
    def from_boto3(
        cls,
        *,
        bucket: str,
        endpoint_url: str | None = None,
        region_name: str | None = None,
    ) -> S3CompatibleStorage:
        """Create an adapter from boto3 without accepting credentials directly.

        Boto3 resolves credentials through its standard environment/profile
        chain so this library surface does not receive or retain secret values.
        """

        try:
            import boto3
        except ImportError as exc:
            raise RuntimeError("install cfdi-vault-mx[object-storage] to use boto3 object storage") from exc

        client = boto3.client(
            "s3",
            endpoint_url=endpoint_url,
            region_name=region_name,
        )
        return cls(bucket=bucket, client=client)

    def write_bytes_idempotent(self, key: str | StorageKey, content: bytes) -> EvidenceReference:
        """Store bytes once and reject collisions for an existing different object."""

        storage_key = StorageKey.parse(key)
        digest = sha256_bytes(content)
        try:
            existing_reference = self._existing_reference_or_none(storage_key, digest, len(content))
            if existing_reference is not None:
                return existing_reference

            self.client.put_object(
                Bucket=self.bucket,
                Key=_physical_key(storage_key),
                Body=content,
                ContentLength=len(content),
                Metadata={"sha256": digest, "size-bytes": str(len(content))},
                IfNoneMatch="*",
            )
        except StorageError:
            raise
        except Exception as exc:
            if _is_precondition_failed(exc):
                raced_reference = self._existing_reference_or_none(storage_key, digest, len(content))
                if raced_reference is not None:
                    return raced_reference
            raise StorageIOError(storage_key, "write") from None
        return EvidenceReference(key=storage_key, sha256=digest, size_bytes=len(content))

    def read_bytes(self, key: str | StorageKey) -> bytes:
        """Read evidence bytes from object storage by stable key."""

        storage_key = StorageKey.parse(key)
        try:
            response = self.client.get_object(Bucket=self.bucket, Key=_physical_key(storage_key))
            body = response["Body"]
            content = body.read()
        except KeyError:
            raise StorageIOError(storage_key, "read") from None
        except Exception as exc:
            if _is_not_found(exc):
                raise StorageNotFoundError(storage_key, "read") from None
            raise StorageIOError(storage_key, "read") from None
        if not isinstance(content, bytes):
            raise StorageIOError(storage_key, "read")
        return content

    def stat(self, key: str | StorageKey) -> EvidenceReference:
        """Return stored evidence metadata without returning evidence bytes."""

        storage_key = StorageKey.parse(key)
        try:
            head = self.client.head_object(Bucket=self.bucket, Key=_physical_key(storage_key))
            return self._reference_from_head(storage_key, head)
        except Exception as exc:
            if _is_not_found(exc):
                raise StorageNotFoundError(storage_key, "stat") from None
            raise StorageIOError(storage_key, "stat") from None

    def _head_or_none(self, key: StorageKey) -> dict[str, Any] | None:
        try:
            return self.client.head_object(Bucket=self.bucket, Key=_physical_key(key))
        except Exception as exc:
            if _is_not_found(exc):
                return None
            raise

    def _existing_reference_or_none(
        self, key: StorageKey, expected_sha256: str, expected_size: int
    ) -> EvidenceReference | None:
        existing = self._head_or_none(key)
        if existing is None:
            return None
        existing_reference = self._reference_from_head(key, existing)
        if existing_reference.sha256 == expected_sha256 and existing_reference.size_bytes == expected_size:
            return existing_reference
        existing_content = self.read_bytes(key)
        if sha256_bytes(existing_content) != expected_sha256:
            raise StorageCollisionError(key)
        return EvidenceReference(key=key, sha256=expected_sha256, size_bytes=len(existing_content))

    def _reference_from_head(self, key: StorageKey, head: dict[str, Any]) -> EvidenceReference:
        metadata = {str(name).lower(): str(value) for name, value in head.get("Metadata", {}).items()}
        sha256 = metadata.get("sha256")
        content_length = head.get("ContentLength")
        if sha256 is None or not isinstance(content_length, int):
            content = self.read_bytes(key)
            return EvidenceReference(key=key, sha256=sha256_bytes(content), size_bytes=len(content))
        return EvidenceReference(key=key, sha256=sha256, size_bytes=content_length)


def _is_not_found(exc: Exception) -> bool:
    response = getattr(exc, "response", None)
    if isinstance(response, dict):
        code = response.get("Error", {}).get("Code")
        return str(code).lower() in {"404", "nosuchkey", "notfound"}
    return isinstance(exc, FileNotFoundError)


_BUCKET_PATTERN = re.compile(r"^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$")


def _physical_key(key: StorageKey) -> str:
    digest = hashlib.sha256(str(key).encode("utf-8")).hexdigest()
    return f"evidence/{digest}"


def _validate_bucket_name(bucket: str) -> None:
    if (
        not isinstance(bucket, str)
        or not _BUCKET_PATTERN.fullmatch(bucket)
        or ".." in bucket
        or ".-" in bucket
        or "-." in bucket
    ):
        raise ValueError("object storage bucket name is invalid")


def _is_precondition_failed(exc: Exception) -> bool:
    response = getattr(exc, "response", None)
    if isinstance(response, dict):
        error = response.get("Error", {})
        code = str(error.get("Code", "")).lower()
        status = response.get("ResponseMetadata", {}).get("HTTPStatusCode")
        return code in {"preconditionfailed", "precondition failed"} or status == 412
    return False
