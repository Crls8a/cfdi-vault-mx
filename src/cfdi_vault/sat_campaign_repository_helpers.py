"""Private lookup and claim lifecycle helpers for SAT persistence."""

from __future__ import annotations

import re
from collections.abc import Mapping
from datetime import datetime
from typing import Any

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from cfdi_vault.recovery_db import (
    SatCampaignRecord,
    SatCampaignWindowRecord,
    SatClaimRecord,
    SatGrantRecord,
)
from cfdi_vault.storage_contract import StorageKey

_ARTIFACT_KINDS = frozenset({"metadata_zip", "metadata_txt", "cfdi_zip", "cfdi_xml"})
_ZIP_ARTIFACT_KINDS = frozenset({"metadata_zip", "cfdi_zip"})
_SHA256 = re.compile(r"[0-9a-f]{64}").fullmatch
_COUNT_KEYS = frozenset({
    "records", "eligible", "cancelled", "duplicates", "conflicts", "unknown",
    "txt_count", "xml_count", "packages",
})


class SatCampaignRepositoryHelpers:
    """Keep repository transaction helpers out of the main operation surface."""

    @staticmethod
    def _campaign(session: Session, campaign_ref: str) -> SatCampaignRecord:
        record = session.scalar(select(SatCampaignRecord).where(SatCampaignRecord.campaign_ref == campaign_ref))
        if record is None:
            raise ValueError("campaign not found")
        return record

    @staticmethod
    def _window(session: Session, campaign_id: int, work_ref: str | None) -> SatCampaignWindowRecord:
        if not work_ref:
            raise ValueError("window reference is required")
        record = session.scalar(select(SatCampaignWindowRecord).where(
            SatCampaignWindowRecord.campaign_id == campaign_id, SatCampaignWindowRecord.work_ref == work_ref))
        if record is None:
            raise ValueError("window not found")
        return record

    @staticmethod
    def _claim(session: Session, claim_ref: str) -> SatClaimRecord:
        record = session.scalar(select(SatClaimRecord).where(SatClaimRecord.claim_ref == claim_ref).with_for_update())
        if record is None:
            raise ValueError("claim not found")
        return record

    @staticmethod
    def _grant(session: Session, campaign_id: int, grant_ref: str, now: datetime) -> SatGrantRecord:
        record = session.scalar(select(SatGrantRecord).where(
            SatGrantRecord.campaign_id == campaign_id,
            SatGrantRecord.grant_ref == grant_ref,
        ))
        if record is None or record.expires_at <= now:
            raise ValueError("claim grant is invalid or expired")
        return record

    @staticmethod
    def _artifact_metadata(
        *, kind: str, storage_key: str, sha256: str, size_bytes: int,
        validation_status: str, counts: Mapping[str, object] | None,
    ) -> dict[str, object]:
        """Validate the DB projection without accepting artifact payloads."""

        if type(kind) is not str or kind not in _ARTIFACT_KINDS:
            raise ValueError("artifact metadata kind is invalid")
        if type(storage_key) is not str:
            raise ValueError("artifact metadata storage key is invalid")
        try:
            StorageKey.parse(storage_key)
        except (TypeError, ValueError):
            raise ValueError("artifact metadata storage key is invalid") from None
        if type(sha256) is not str or _SHA256(sha256) is None:
            raise ValueError("artifact metadata hash is invalid")
        if type(size_bytes) is not int or isinstance(size_bytes, bool) or size_bytes < 0:
            raise ValueError("artifact metadata size is invalid")
        if type(validation_status) is not str or not validation_status or len(validation_status) > 32:
            raise ValueError("artifact metadata status is invalid")
        normalized = dict(counts or {})
        if not isinstance(counts, Mapping) and counts is not None:
            raise ValueError("artifact metadata counts are invalid")
        if any(type(key) is not str or key not in _COUNT_KEYS for key in normalized):
            raise ValueError("artifact metadata counts are invalid")
        if any(type(value) is not int or isinstance(value, bool) or value < 0 for value in normalized.values()):
            raise ValueError("artifact metadata counts are invalid")
        return normalized

    @staticmethod
    def _close_expired_claims(session: Session, now: datetime, campaign_id: int | None = None) -> None:
        predicate: list[Any] = [SatClaimRecord.active.is_(True), SatClaimRecord.lease_until <= now,
                                SatClaimRecord.operation_kind == "verify"]
        if campaign_id is not None:
            predicate.append(SatClaimRecord.campaign_id == campaign_id)
        session.execute(update(SatClaimRecord).where(*predicate).values(
            active=False, completed_at=now, result="lease_expired", result_code="lease_expired"))
        download_predicate: list[Any] = [
            SatClaimRecord.active.is_(True), SatClaimRecord.lease_until <= now,
            SatClaimRecord.operation_kind == "download", SatClaimRecord.result.is_(None),
        ]
        if campaign_id is not None:
            download_predicate.append(SatClaimRecord.campaign_id == campaign_id)
        session.execute(update(SatClaimRecord).where(*download_predicate).values(
            active=False, completed_at=now, result="uncertain", result_code="download_lease_manual_review"))
        submit_predicate: list[Any] = [
            SatClaimRecord.active.is_(True), SatClaimRecord.lease_until <= now,
            SatClaimRecord.operation_kind == "submit", SatClaimRecord.result.is_(None),
        ]
        if campaign_id is not None:
            submit_predicate.append(SatClaimRecord.campaign_id == campaign_id)
        session.execute(update(SatClaimRecord).where(*submit_predicate).values(
            active=False, completed_at=now, result="uncertain", result_code="submit_lease_manual_review"))

    @staticmethod
    def _finish_claim(claim: SatClaimRecord, now: datetime, result: str,
                      result_code: str | None = None) -> None:
        claim.active = False
        claim.completed_at = now
        claim.result = result
        claim.result_code = result_code

    @staticmethod
    def _verify_idempotency_key(session: Session, campaign_id: int, request_id: int, attempt: int) -> str:
        base = f"verify:{request_id}:{attempt}"
        claims = session.execute(select(SatClaimRecord.id, SatClaimRecord.active).where(
                SatClaimRecord.campaign_id == campaign_id,
                SatClaimRecord.idempotency_key.like(f"{base}%")
            ).order_by(SatClaimRecord.id)).all()
        if not claims:
            return base
        if any(active for _, active in claims):
            raise ValueError("verify operation already claimed")
        return f"{base}:retry:{claims[-1][0] + 1}"
