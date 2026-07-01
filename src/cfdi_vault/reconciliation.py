"""Metadata-first reconciliation and retry policy rules."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from cfdi_vault.domain import ReconciliationState


CANCELLED_STATUSES = frozenset({"cancelado", "cancelada", "cancelled", "canceled"})
ACTIVE_STATUSES = frozenset({"vigente", "active"})
TRANSIENT_STATUSES = frozenset({"en_proceso", "en proceso", "processing", "pending"})
PERMANENT_ERROR_CODES = frozenset({"expired", "rejected", "not_found", "invalid_request", "access_denied"})
TRANSIENT_ERROR_CODES = frozenset({"timeout", "temporary_unavailable", "rate_limited", "in_process"})


class RetryAction(StrEnum):
    """Normalized retry decision for SAT recovery work."""

    DOWNLOAD_XML = "download_xml"
    CHECK_STATUS = "check_status"
    RETRY_LATER = "retry_later"
    DO_NOT_RETRY = "do_not_retry"
    PERMANENT_FAILURE = "permanent_failure"


@dataclass(frozen=True)
class ReconciliationDecision:
    """Decision emitted for one metadata row."""

    state: ReconciliationState
    reason: str
    should_download_xml: bool
    should_check_status: bool


def decide_metadata_state(
    status: str,
    *,
    has_xml: bool,
    is_new: bool = False,
    previous_status: str | None = None,
) -> ReconciliationDecision:
    """Classify metadata against local XML evidence and previous ledger state."""

    normalized = status.strip().lower()
    previous_normalized = (previous_status or "").strip().lower()
    status_changed = bool(previous_normalized and previous_normalized != normalized)

    if has_xml:
        return ReconciliationDecision(
            state=ReconciliationState.XML_DOWNLOADED,
            reason="xml evidence already exists",
            should_download_xml=False,
            should_check_status=status_changed or normalized in CANCELLED_STATUSES,
        )
    if normalized in CANCELLED_STATUSES:
        return ReconciliationDecision(
            state=ReconciliationState.CANCELLED_METADATA,
            reason="metadata reports cancellation",
            should_download_xml=False,
            should_check_status=True,
        )
    if normalized in TRANSIENT_STATUSES or status_changed:
        return ReconciliationDecision(
            state=ReconciliationState.STATE_CHECK_PENDING,
            reason="metadata status needs confirmation",
            should_download_xml=False,
            should_check_status=True,
        )
    if is_new:
        return ReconciliationDecision(
            state=ReconciliationState.DISCOVERED_IN_METADATA,
            reason="new UUID discovered in metadata",
            should_download_xml=True,
            should_check_status=False,
        )
    return ReconciliationDecision(
        state=ReconciliationState.XML_PENDING,
        reason="metadata exists without XML evidence",
        should_download_xml=True,
        should_check_status=False,
    )


def retry_action_for_state(state: ReconciliationState, *, attempts: int = 0, max_attempts: int = 3, error_code: str | None = None) -> RetryAction:
    """Decide whether recovery should retry, stop, or request status confirmation."""

    normalized_error = (error_code or "").strip().lower()
    if normalized_error in PERMANENT_ERROR_CODES:
        return RetryAction.PERMANENT_FAILURE
    if state in {ReconciliationState.CANCELLED_METADATA, ReconciliationState.CANCELLED_CONFIRMED, ReconciliationState.STATE_CHECK_PENDING}:
        return RetryAction.CHECK_STATUS
    if state == ReconciliationState.XML_DOWNLOADED:
        return RetryAction.DO_NOT_RETRY
    if state == ReconciliationState.FAILED_PERMANENT:
        return RetryAction.PERMANENT_FAILURE
    if attempts >= max_attempts:
        return RetryAction.PERMANENT_FAILURE
    if normalized_error in TRANSIENT_ERROR_CODES:
        return RetryAction.RETRY_LATER
    if state in {
        ReconciliationState.DISCOVERED_IN_METADATA,
        ReconciliationState.XML_PENDING,
        ReconciliationState.XML_REQUESTED,
        ReconciliationState.RETRY_SCHEDULED,
    }:
        return RetryAction.DOWNLOAD_XML if state in {ReconciliationState.DISCOVERED_IN_METADATA, ReconciliationState.XML_PENDING} else RetryAction.RETRY_LATER
    return RetryAction.DO_NOT_RETRY
