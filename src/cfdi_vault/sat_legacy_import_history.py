"""VERIFY history portion of the legacy JSON importer."""

from __future__ import annotations

from typing import Any, Callable

from sqlalchemy import select

from cfdi_vault.recovery_db import SatClaimRecord, SatRequestRecord, SatVerifyAttemptRecord


def import_history(
    session: Any,
    request: SatRequestRecord,
    campaign_id: int,
    values: Any,
    stamp: Any,
    *,
    error_cls: type[ValueError],
    parse_datetime: Callable[..., Any],
    parse_int: Callable[[Any, str, int], int],
    category_map: dict[str, str],
    categories: set[str],
    codes: set[str],
) -> int:
    if values is None:
        return 0
    if not isinstance(values, list):
        raise error_cls("legacy-verify-history-invalid")
    imported = 0
    for value in values:
        if not isinstance(value, dict) or value.get("attempt") is None:
            raise error_cls("legacy-verify-history-invalid")
        attempt_number = parse_int(value["attempt"], "verify-attempt", 0)
        if attempt_number <= 0:
            raise error_cls("legacy-verify-attempt-invalid")
        raw_category = str(value.get("category", "pending"))
        category = category_map.get(raw_category, raw_category)
        result = str(value.get("result", "pending"))
        result_code = str(value.get("errorKind")) if value.get("errorKind") else None
        if category not in categories or result not in categories:
            raise error_cls("legacy-verify-result-invalid")
        if result_code not in codes and result_code is not None:
            raise error_cls("legacy-verify-code-invalid")
        scheduled_at = parse_datetime(value.get("scheduledAt"), "scheduled-at", default=stamp)
        contacted_at = parse_datetime(value.get("contactedAt"), "contacted-at", default=stamp) if value.get("contactedAt") else None
        next_check_at = parse_datetime(value.get("nextCheckAt"), "next-check", default=stamp) if value.get("nextCheckAt") else None
        if contacted_at is not None and contacted_at < scheduled_at:
            raise error_cls("legacy-verify-dates-invalid")
        existing = session.scalar(select(SatVerifyAttemptRecord).where(
            SatVerifyAttemptRecord.request_id == request.id,
            SatVerifyAttemptRecord.attempt == attempt_number,
        ))
        if existing is not None:
            if (existing.category, existing.result, existing.result_code,
                    existing.scheduled_at, existing.contacted_at, existing.next_check_at) != (
                        category, result, result_code, scheduled_at, contacted_at, next_check_at):
                raise error_cls("legacy-import-conflict")
            continue
        source_claim_ref = value.get("claimRef")
        claim_ref = str(source_claim_ref) if source_claim_ref else f"legacy-{request.id}-{attempt_number}"
        if (not claim_ref or len(claim_ref) > 96 or
                any(char not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-" for char in claim_ref)):
            raise error_cls("legacy-verify-claim-invalid")
        claim = SatClaimRecord(
            claim_ref=claim_ref, campaign_id=campaign_id,
            window_id=request.window_id, request_id=request.id, operation_kind="verify",
            idempotency_key=f"legacy-verify-{request.id}-{attempt_number}", operation_slot=1,
            worker_ref="legacy_json", claimed_at=stamp, lease_until=stamp, active=True,
        )
        session.add(claim)
        session.flush()
        session.add(SatVerifyAttemptRecord(
            campaign_id=campaign_id, request_id=request.id, claim_id=claim.id,
            attempt=attempt_number, scheduled_at=scheduled_at, contacted_at=contacted_at,
            category=category, result=result, result_code=result_code,
            next_check_at=next_check_at, claim_ref=claim.claim_ref, created_at=stamp,
        ))
        session.flush()
        claim.active = False
        claim.completed_at = stamp
        claim.result = result
        request.verify_attempts = max(request.verify_attempts, attempt_number)
        imported += 1
    return imported
