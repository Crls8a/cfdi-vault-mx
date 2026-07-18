"""Package and external-artifact portion of the legacy JSON importer."""

from __future__ import annotations

import hashlib
import re
from typing import Any, Callable

from sqlalchemy import select

from cfdi_vault.recovery_db import SatArtifactRecord, SatClaimRecord, SatPackageRecord, SatRequestRecord

_STORAGE_KEY = re.compile(
    r"^sat-(?:metadata|cfdi)/[A-Za-z0-9_-]{1,96}(?:/[A-Za-z0-9_-]{1,96})?/packages/"
    r"[1-9][0-9]*-[0-9a-f]{12}\.zip$"
)
_PACKAGE_STATUSES = {"pending", "downloading", "completed", "failed", "uncertain", "downloaded"}


def import_packages(
    session: Any,
    request: SatRequestRecord,
    campaign_id: int,
    values: Any,
    stamp: Any,
    *,
    error_cls: type[ValueError],
    parse_int: Callable[[Any, str, int], int],
    artifact_by_package: dict[str, dict[str, Any]],
) -> int:
    if values is None:
        return 0
    if not isinstance(values, list):
        raise error_cls("legacy-packages-invalid")
    imported = 0
    for value in values:
        if not isinstance(value, dict) or (not value.get("packageRef") and not value.get("idPaquete")):
            raise error_cls("legacy-package-invalid")
        package_ref = str(value.get("packageRef") or value.get("idPaquete"))
        existing = session.scalar(select(SatPackageRecord).where(SatPackageRecord.id_paquete == package_ref))
        if existing is not None:
            artifact_doc = artifact_by_package.get(package_ref)
            expected_linked = bool(value.get("artifactRef") or value.get("storageKey") or artifact_doc)
            expected_ordinal = parse_int(value["ordinal"], "package-ordinal", 0) if value.get("ordinal") is not None else None
            if (existing.id_solicitud != request.id_solicitud or
                    existing.campaign_id not in (None, campaign_id) or
                    existing.window_id not in (None, request.window_id) or
                    existing.ordinal != expected_ordinal or
                    existing.status != str(value.get("status", "pending")) or
                    existing.download_state != str(value.get("downloadState", "pending")) or
                    existing.attempts != parse_int(value.get("attempts"), "package-attempts", 0) or
                    bool(existing.artifact_id) != expected_linked):
                raise error_cls("legacy-import-conflict")
            if expected_linked and artifact_doc:
                artifact_ref = str(value.get("artifactRef") or artifact_doc.get("artifactRef") or
                                   f"legacy-artifact-{package_ref}")
                artifact = session.scalar(select(SatArtifactRecord).where(
                    SatArtifactRecord.artifact_ref == artifact_ref))
                if artifact is None:
                    raise error_cls("legacy-import-conflict")
                expected_storage = str(value.get("storageKey") or value.get("packageStorageKey") or
                                       artifact_doc.get("storageKey") or artifact_doc.get("packageStorageKey") or "")
                expected_sha = str(value.get("sha256") or value.get("packageSha256") or
                                   artifact_doc.get("sha256") or artifact_doc.get("packageSha256") or "").lower()
                expected_kind = str(value.get("kind") or artifact_doc.get("kind", "metadata_zip"))
                expected_size = parse_int(value.get("byteCount", artifact_doc.get("byteCount")), "artifact-size", 0)
                if (artifact.storage_key != expected_storage or artifact.sha256 != expected_sha or
                        artifact.kind != expected_kind or artifact.size_bytes != expected_size):
                    raise error_cls("legacy-import-conflict")
            continue
        artifact_doc = artifact_by_package.get(package_ref, {})
        merged = {**artifact_doc, **value}
        linked = bool(merged.get("artifactRef") or merged.get("storageKey") or artifact_doc)
        artifact_id = None
        claim_id = None
        if linked:
            artifact_ref = str(merged.get("artifactRef") or f"legacy-artifact-{package_ref}")
            storage_key = str(merged.get("storageKey") or merged.get("packageStorageKey") or "")
            sha256 = str(merged.get("sha256") or merged.get("packageSha256") or "").lower()
            kind = str(merged.get("kind", "metadata_zip"))
            size_bytes = parse_int(merged.get("byteCount"), "artifact-size", 0)
            if (not artifact_ref or len(sha256) != 64 or
                    any(char not in "0123456789abcdef" for char in sha256) or
                    not _STORAGE_KEY.fullmatch(storage_key) or storage_key.startswith(("/", "\\")) or
                    ".." in storage_key.replace("\\", "/").split("/") or
                    any(ord(char) < 32 for char in storage_key) or
                    not storage_key.startswith(("sat-metadata/", "sat-cfdi/")) or
                    kind not in {"metadata_zip", "cfdi_zip"} or size_bytes < 0):
                raise error_cls("legacy-artifact-invalid")
            artifact = session.scalar(select(SatArtifactRecord).where(
                SatArtifactRecord.artifact_ref == artifact_ref))
            if artifact is None:
                artifact = SatArtifactRecord(
                    campaign_id=campaign_id, window_id=request.window_id,
                    artifact_ref=artifact_ref, kind=kind, storage_key=storage_key,
                    sha256=sha256, size_bytes=size_bytes,
                    validation_status="legacy_json", counts={}, created_at=stamp,
                )
                session.add(artifact)
                session.flush()
            elif (artifact.campaign_id != campaign_id or artifact.window_id != request.window_id or
                  artifact.sha256 != sha256 or artifact.storage_key != storage_key):
                raise error_cls("legacy-import-conflict")
            artifact_id = artifact.id
            claim_key = hashlib.sha256(package_ref.encode("utf-8")).hexdigest()[:24]
            claim_ref = f"legacy-download-{claim_key}"
            claim = session.scalar(select(SatClaimRecord).where(SatClaimRecord.claim_ref == claim_ref))
            if claim is None:
                claim = SatClaimRecord(
                    claim_ref=claim_ref, campaign_id=campaign_id, window_id=request.window_id,
                    request_id=request.id, operation_kind="download",
                    idempotency_key=f"legacy-download-{claim_key}", operation_slot=1,
                    worker_ref="legacy_json", claimed_at=stamp, lease_until=stamp,
                    active=False, completed_at=stamp, result="package", result_code="legacy_json",
                )
                session.add(claim)
                session.flush()
            elif (claim.campaign_id != campaign_id or claim.window_id != request.window_id or
                  claim.request_id != request.id or claim.result != "package"):
                raise error_cls("legacy-import-conflict")
            claim_id = claim.id
        ordinal = parse_int(value["ordinal"], "package-ordinal", 0) if value.get("ordinal") is not None else None
        if ordinal is not None and ordinal <= 0:
            raise error_cls("legacy-package-invalid")
        attempts = parse_int(value.get("attempts"), "package-attempts", 0)
        status = str(value.get("status", "pending"))
        download_state = str(value.get("downloadState", "pending"))
        if (attempts < 0 or status not in _PACKAGE_STATUSES or
                download_state not in {"pending", "downloaded", "download_uncertain", "download_failed"}):
            raise error_cls("legacy-package-invalid")
        session.add(SatPackageRecord(
            tenant_id=request.tenant_id, id_paquete=package_ref, id_solicitud=request.id_solicitud,
            status=status, attempts=attempts,
            created_at=stamp, updated_at=stamp, campaign_id=campaign_id if linked else None,
            window_id=request.window_id if linked else None, artifact_id=artifact_id,
            claim_id=claim_id,
            ordinal=ordinal,
            download_state=download_state, validation_status="unvalidated",
            last_error={"legacy_json": True, "artifact_linked": linked},
        ))
        imported += 1
    return imported
