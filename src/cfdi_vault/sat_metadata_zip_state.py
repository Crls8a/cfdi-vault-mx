"""Private receipt for one stored SAT Metadata raw ZIP."""

from __future__ import annotations

import re
from dataclasses import dataclass

_REFS = {
    "recovery": re.compile(r"run-[0-9a-f]{12}"),
    "package": re.compile(r"pkg-[0-9a-f]{12}"),
    "campaign": re.compile(r"cmp-[0-9a-f]{12}"),
    "work": re.compile(r"work-[0-9a-f]{12}"),
}
_DIGEST = re.compile(r"[0-9a-f]{64}")


class MetadataZipReceiptError(ValueError):
    """Reject malformed or unsafe private ZIP receipt data."""

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


@dataclass(frozen=True, repr=False)
class MetadataZipReceipt:
    """Private evidence reference for an accepted raw ZIP, never its bytes."""

    recovery_ref: str
    package_ref: str
    campaign_ref: str
    work_ref: str
    sha256: str
    byte_count: int
    zip_valid: bool
    storage_key: str

    def __post_init__(self) -> None:
        if (
            type(self.recovery_ref) is not str or not _REFS["recovery"].fullmatch(self.recovery_ref)
            or type(self.package_ref) is not str or not _REFS["package"].fullmatch(self.package_ref)
            or type(self.campaign_ref) is not str or not _REFS["campaign"].fullmatch(self.campaign_ref)
            or type(self.work_ref) is not str or not _REFS["work"].fullmatch(self.work_ref)
            or type(self.sha256) is not str or not _DIGEST.fullmatch(self.sha256)
            or type(self.byte_count) is not int or self.byte_count <= 0
            or type(self.zip_valid) is not bool or not self.zip_valid
            or not self._valid_storage_key()
        ):
            raise MetadataZipReceiptError("zip-receipt-invalid")

    def _valid_storage_key(self) -> bool:
        if type(self.storage_key) is not str:
            return False
        prefix = f"sat-metadata/{self.campaign_ref}/{self.work_ref}/packages/"
        if not self.storage_key.startswith(prefix) or self.storage_key.count("/") != 4:
            return False
        filename = self.storage_key[len(prefix):]
        return re.fullmatch(rf"[1-9][0-9]*-{self.sha256[:12]}\.zip", filename) is not None

    def to_private_document(self) -> dict[str, object]:
        """Return the complete private receipt for local persistence only."""

        return {
            "recoveryRef": self.recovery_ref,
            "packageRef": self.package_ref,
            "campaignRef": self.campaign_ref,
            "workRef": self.work_ref,
            "sha256": self.sha256,
            "byteCount": self.byte_count,
            "zipValid": self.zip_valid,
            "storageKey": self.storage_key,
        }

    def to_redacted_document(self) -> dict[str, object]:
        """Expose only non-identifying ZIP facts in a sanitized projection."""

        return {"zipValid": self.zip_valid, "byteCount": self.byte_count}

    def __repr__(self) -> str:
        return "MetadataZipReceipt(<private>)"


MetadataRawZipReceipt = MetadataZipReceipt
RawMetadataZipReceipt = MetadataZipReceipt
