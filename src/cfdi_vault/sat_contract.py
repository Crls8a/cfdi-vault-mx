"""Non-live SAT mass-download contract objects and outcome policy."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Any

from cfdi_vault.domain import SatRequestState


class SatOperation(StrEnum):
    """SAT operation stages that return different meanings for the same code."""

    AUTHENTICATE = "authenticate"
    REQUEST = "request"
    VERIFY = "verify"
    DOWNLOAD = "download"
    STATUS = "status"


class SatOutcomeAction(StrEnum):
    """Internal action selected from SAT code and state signals."""

    ACCEPTED = "accepted"
    IN_PROGRESS = "in_progress"
    FINISHED = "finished"
    RETRY = "retry"
    PERMANENT_FAILURE = "permanent_failure"
    EXPIRED = "expired"
    UNAUTHORIZED = "unauthorized"
    DUPLICATE = "duplicate"
    DOWNLOADS_EXHAUSTED = "downloads_exhausted"


@dataclass(frozen=True)
class SatOutcomeClassification:
    """Normalized action plus operator-facing reason for one SAT outcome."""

    action: SatOutcomeAction
    reason: str
    retryable: bool = False


@dataclass(frozen=True, repr=False)
class SatAuthResult:
    """Normalized authentication result returned by a SAT auth adapter."""

    authorization: str
    expires_at: datetime | None = None
    raw_response: dict[str, Any] = field(default_factory=dict)

    def __repr__(self) -> str:
        return (
            "SatAuthResult("
            "authorization=<redacted>, "
            f"expires_at={self.expires_at!r}, "
            "raw_response=<redacted>"
            ")"
        )


@dataclass(frozen=True)
class SatRequestResult:
    """Normalized result of submitting a SAT download request."""

    request_id: str
    sat_code: str
    message: str
    action: SatOutcomeAction
    raw_response: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class SatVerificationResult:
    """Normalized result of verifying a SAT request."""

    request_id: str
    state: SatRequestState
    sat_code: str
    message: str
    package_ids: tuple[str, ...] = ()
    action: SatOutcomeAction = SatOutcomeAction.IN_PROGRESS
    raw_response: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, repr=False)
class SatDownloadResult:
    """Normalized result of downloading one SAT package."""

    package_id: str
    sat_code: str
    message: str
    action: SatOutcomeAction
    content: bytes | None = None
    raw_response: dict[str, Any] = field(default_factory=dict)

    def __repr__(self) -> str:
        return (
            "SatDownloadResult("
            f"package_id={self.package_id!r}, "
            f"sat_code={self.sat_code!r}, "
            f"message={self.message!r}, "
            f"action={self.action!r}, "
            "content=<redacted>, "
            "raw_response=<redacted>"
            ")"
        )


def classify_sat_outcome(
    operation: SatOperation,
    *,
    sat_code: str | int | None = None,
    state: SatRequestState | str | None = None,
) -> SatOutcomeClassification:
    """Map a SAT code/state signal to the next internal action."""

    normalized_code = _normalize_code(sat_code)
    normalized_state = _normalize_state(state)
    if normalized_state is not None:
        state_action = _classify_state(normalized_state)
        if state_action is not None:
            return state_action

    if normalized_code in {"300", "303", "304", "305", "5001"}:
        return SatOutcomeClassification(SatOutcomeAction.UNAUTHORIZED, "requester is not authorized for this SAT operation")
    if normalized_code in {"301", "302", "5003", "5004"}:
        return SatOutcomeClassification(SatOutcomeAction.PERMANENT_FAILURE, "SAT returned a terminal validation or empty-result condition")
    if normalized_code in {"5002", "5005"}:
        return SatOutcomeClassification(SatOutcomeAction.DUPLICATE, "SAT reports a duplicate or still-active equivalent request")
    if normalized_code == "5007":
        return SatOutcomeClassification(SatOutcomeAction.EXPIRED, "SAT package or request window is expired")
    if normalized_code in {"5008", "5011"}:
        return SatOutcomeClassification(SatOutcomeAction.DOWNLOADS_EXHAUSTED, "SAT download or daily limit is exhausted")
    if normalized_code == "404":
        return SatOutcomeClassification(SatOutcomeAction.RETRY, "SAT returned a transient or uncontrolled error", retryable=True)
    if normalized_code == "5000":
        if operation == SatOperation.DOWNLOAD:
            return SatOutcomeClassification(SatOutcomeAction.FINISHED, "SAT package download succeeded")
        return SatOutcomeClassification(SatOutcomeAction.ACCEPTED, "SAT accepted the operation")

    return SatOutcomeClassification(SatOutcomeAction.RETRY, "unknown SAT code; retry once before escalation", retryable=True)


def _normalize_code(sat_code: str | int | None) -> str:
    return "" if sat_code is None else str(sat_code).strip()


def _normalize_state(state: SatRequestState | str | None) -> SatRequestState | None:
    if state is None:
        return None
    if isinstance(state, SatRequestState):
        return state
    try:
        return SatRequestState(str(state))
    except ValueError:
        return None


def _classify_state(state: SatRequestState) -> SatOutcomeClassification | None:
    if state == SatRequestState.ACCEPTED:
        return SatOutcomeClassification(SatOutcomeAction.ACCEPTED, "SAT request is accepted")
    if state == SatRequestState.IN_PROCESS:
        return SatOutcomeClassification(SatOutcomeAction.IN_PROGRESS, "SAT request is still being processed", retryable=True)
    if state == SatRequestState.FINISHED:
        return SatOutcomeClassification(SatOutcomeAction.FINISHED, "SAT request finished and package ids can be downloaded")
    if state == SatRequestState.EXPIRED:
        return SatOutcomeClassification(SatOutcomeAction.EXPIRED, "SAT request expired")
    if state in {SatRequestState.ERROR, SatRequestState.REJECTED}:
        return SatOutcomeClassification(SatOutcomeAction.PERMANENT_FAILURE, "SAT request ended in a terminal state")
    return None
