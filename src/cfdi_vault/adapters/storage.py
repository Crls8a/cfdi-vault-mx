"""Read-only filesystem adapter for storage metadata observation."""

from __future__ import annotations

import hashlib
from pathlib import Path

from cfdi_vault.storage_contract import (
    EvidenceReference,
    StorageCollisionError,
    StorageError,
    StorageIOError,
    StorageKey,
    StorageNotFoundError,
)


class ReadOnlyFilesystemStorage:
    """Inspect existing evidence without creating or modifying its root.

    Construction only retains the configured root. ``stat`` reads one validated
    storage key and never creates directories, writes bytes, or repairs layout.
    """

    def __init__(self, root: str | Path = "storage") -> None:
        self.root = Path(root)

    def stat(self, key: str | StorageKey) -> EvidenceReference:
        """Return hash and size metadata for existing evidence.

        Raises:
            StorageNotFoundError: If the configured root or evidence is absent.
            StorageCollisionError: If a case-insensitive path alias is found.
            StorageIOError: If the reference cannot be resolved or read safely.
        """

        storage_key = StorageKey.parse(key)
        content = self._read_bytes(storage_key)
        return EvidenceReference(
            key=storage_key,
            sha256=hashlib.sha256(content).hexdigest(),
            size_bytes=len(content),
        )

    def _read_bytes(self, key: StorageKey) -> bytes:
        try:
            return self._path_for_key(key).read_bytes()
        except StorageError:
            raise
        except FileNotFoundError:
            raise StorageNotFoundError(key, "stat") from None
        except OSError:
            raise StorageIOError(key, "stat") from None

    def _path_for_key(self, key: StorageKey) -> Path:
        try:
            self._reject_case_alias(key)
            path = self.root.joinpath(*key.parts)
            path.resolve().relative_to(self.root.resolve())
            return path
        except StorageError:
            raise
        except (OSError, ValueError):
            raise StorageIOError(key, "resolve") from None

    def _reject_case_alias(self, key: StorageKey) -> None:
        current = self.root
        for part in key.parts:
            try:
                if not current.is_dir():
                    return
                entries = tuple(current.iterdir())
            except FileNotFoundError:
                return
            except OSError:
                raise StorageIOError(key, "resolve") from None
            for entry in entries:
                if entry.name.casefold() == part.casefold() and entry.name != part:
                    raise StorageCollisionError(
                        key,
                        "case-insensitive alias",
                        operation="resolve",
                    )
            current /= part
