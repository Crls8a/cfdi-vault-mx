"""Public SAT v1.5 offline contract objects and outcome policy.

This module owns side-effect-free request/result/error shapes for SAT mass
download adapters. It does not open files, resolve credentials, sign payloads,
or contact live SAT services.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
import re
from typing import Any

from cfdi_vault.domain import CfdiStatusOutcome, SatRequestState


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


class SatError(RuntimeError):
    """Base redacted failure for one SAT v1.5 operation.

    Args:
        operation: SAT operation that failed.
        code: Safe SAT or adapter code.
        message: Redacted operator-facing message.
        retryable: Whether caller policy may retry later.
        next_action: Safe operator action to show to users.
        request_id: Optional SAT request id; redacted in diagnostics.
        package_id: Optional SAT package id; redacted in diagnostics.

    The error is side-effect free and never stores raw SOAP, tokens,
    credentials, package bytes, or local paths.
    """

    def __init__(
        self,
        *,
        operation: SatOperation | str,
        code: str,
        message: str,
        retryable: bool = False,
        next_action: str = "inspect the normalized SAT result and local audit state",
        request_id: str | None = None,
        package_id: str | None = None,
    ) -> None:
        self.operation = SatOperation(operation)
        self.code = str(code)
        self.message = _safe_text(message)
        self.retryable = bool(retryable)
        self.next_action = _safe_text(next_action)
        self.request_id = request_id
        self.package_id = package_id
        super().__init__(self.safe_message)

    @property
    def safe_message(self) -> str:
        """Return the redacted diagnostic string for this failure."""

        parts = [
            f"operation={self.operation.value}",
            f"code={self.code}",
            f"message={self.message}",
            f"retryable={self.retryable}",
        ]
        if self.request_id:
            parts.append(f"request_id={_redact_identifier(self.request_id)}")
        if self.package_id:
            parts.append(f"package_id={_redact_identifier(self.package_id)}")
        parts.append(f"next_action={self.next_action}")
        return "SAT error (" + ", ".join(parts) + ")"

    def __str__(self) -> str:
        """Return a safe string without sensitive identifiers."""

        return self.safe_message

    def as_safe_dict(self) -> dict[str, object]:
        """Serialize only redacted, user-safe error fields."""

        return {
            "operation": self.operation.value,
            "code": self.code,
            "message": self.message,
            "retryable": self.retryable,
            "next_action": self.next_action,
            "request_id": _redact_identifier(self.request_id) if self.request_id else None,
            "package_id": _redact_identifier(self.package_id) if self.package_id else None,
        }


class SatAuthenticationError(SatError):
    """Authentication-stage SAT failure without credential or token material."""


class SatRequestError(SatError):
    """Request-submission SAT failure with a redacted operator action."""


class SatVerificationError(SatError):
    """Verification-stage SAT failure with retryability made explicit."""


class SatPackageDownloadError(SatError):
    """Package-download SAT failure without package content or full package ids."""


@dataclass(frozen=True)
class SatOutcomeClassification:
    """Normalized action plus operator-facing reason for one SAT outcome."""

    action: SatOutcomeAction
    reason: str
    retryable: bool = False


@dataclass(frozen=True)
class CfdiStatusClassification:
    """Normalized action for one CFDI status consultation response."""

    outcome: CfdiStatusOutcome
    reason: str
    retryable: bool = False


@dataclass(frozen=True, repr=False)
class SatAuthResult:
    """Normalized authentication result returned by a SAT auth adapter.

    The authorization value is caller-owned in-memory material. It is never
    exposed by ``repr()``, ``str()``, or ``as_safe_dict()``.
    """

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

    def as_safe_dict(self) -> dict[str, object]:
        """Return a diagnostic-safe representation of the auth result."""

        return {
            "authorization": "<redacted>",
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "raw_response": "<redacted>",
        }


@dataclass(frozen=True, repr=False)
class SatRequestResult:
    """Normalized result of submitting a SAT download request.

    Full request identifiers and raw responses are kept for caller-owned state
    but are redacted from diagnostics.
    """

    request_id: str
    sat_code: str
    message: str
    action: SatOutcomeAction
    raw_response: dict[str, Any] = field(default_factory=dict)

    def __repr__(self) -> str:
        """Return a safe representation with the request id redacted."""

        return (
            "SatRequestResult("
            f"request_id={_redact_identifier(self.request_id)!r}, "
            f"sat_code={self.sat_code!r}, "
            f"message={_safe_text(self.message)!r}, "
            f"action={self.action!r}, "
            "raw_response=<redacted>"
            ")"
        )

    def as_safe_dict(self) -> dict[str, object]:
        """Serialize only redacted, user-safe request result fields."""

        return {
            "request_id": _redact_identifier(self.request_id),
            "sat_code": self.sat_code,
            "message": _safe_text(self.message),
            "action": self.action.value,
        }


@dataclass(frozen=True, repr=False)
class SatVerificationResult:
    """Normalized result of verifying a SAT request.

    Package identifiers remain available to the caller but are redacted in
    diagnostics and safe serialization.
    """

    request_id: str
    state: SatRequestState
    sat_code: str
    message: str
    package_ids: tuple[str, ...] = ()
    action: SatOutcomeAction = SatOutcomeAction.IN_PROGRESS
    raw_response: dict[str, Any] = field(default_factory=dict)

    def __repr__(self) -> str:
        """Return a safe representation with ids and raw response redacted."""

        return (
            "SatVerificationResult("
            f"request_id={_redact_identifier(self.request_id)!r}, "
            f"state={self.state!r}, "
            f"sat_code={self.sat_code!r}, "
            f"message={_safe_text(self.message)!r}, "
            f"package_ids={tuple(_redact_identifier(item) for item in self.package_ids)!r}, "
            f"action={self.action!r}, "
            "raw_response=<redacted>"
            ")"
        )

    def as_safe_dict(self) -> dict[str, object]:
        """Serialize only redacted, user-safe verification result fields."""

        return {
            "request_id": _redact_identifier(self.request_id),
            "state": self.state.value,
            "sat_code": self.sat_code,
            "message": _safe_text(self.message),
            "package_ids": tuple(_redact_identifier(item) for item in self.package_ids),
            "action": self.action.value,
        }


@dataclass(frozen=True, repr=False)
class SatDownloadResult:
    """Normalized result of downloading one SAT package.

    ``content`` may contain caller-supplied package bytes. It is never returned
    by diagnostics or safe serialization.
    """

    package_id: str
    sat_code: str
    message: str
    action: SatOutcomeAction
    content: bytes | None = None
    raw_response: dict[str, Any] = field(default_factory=dict)

    def __repr__(self) -> str:
        return (
            "SatDownloadResult("
            f"package_id={_redact_identifier(self.package_id)!r}, "
            f"sat_code={self.sat_code!r}, "
            f"message={_safe_text(self.message)!r}, "
            f"action={self.action!r}, "
            "content=<redacted>, "
            "raw_response=<redacted>"
            ")"
        )

    def as_safe_dict(self) -> dict[str, object]:
        """Serialize only redacted, user-safe package result fields."""

        return {
            "package_id": _redact_identifier(self.package_id),
            "sat_code": self.sat_code,
            "message": _safe_text(self.message),
            "action": self.action.value,
            "content": "<redacted>" if self.content is not None else None,
        }


_ACTIVE_STATUS_VALUES = frozenset({"vigente", "active"})
_CANCELLED_STATUS_VALUES = frozenset({"cancelado", "cancelada", "cancelled", "canceled"})
_NOT_FOUND_STATUS_VALUES = frozenset(
    {"no_encontrado", "no_disponible", "not_available", "not_found"}
)
_UNAUTHORIZED_STATUS_CODES = frozenset(
    {"300", "303", "304", "305", "5001", "access_denied", "unauthorized"}
)
_NOT_FOUND_STATUS_CODES = frozenset({"404_cfdi", "not_found", "no_available", "no_disponible"})
_RETRYABLE_STATUS_CODES = frozenset(
    {"404", "408", "429", "500", "502", "503", "504", "rate_limited", "retryable", "temporary_unavailable", "timeout"}
)
_PERMANENT_STATUS_CODES = frozenset({"301", "302", "5003", "5004", "invalid_request", "permanent", "rejected"})


def classify_cfdi_status_outcome(
    *,
    status: str | None = None,
    sat_code: str | int | None = None,
) -> CfdiStatusClassification:
    """Map CFDI status text and SAT code signals to a normalized outcome."""

    normalized_status = _normalize_status_text(status)
    normalized_code = _normalize_code(sat_code).lower()

    if normalized_status in _ACTIVE_STATUS_VALUES:
        return CfdiStatusClassification(CfdiStatusOutcome.ACTIVE, "CFDI is active")
    if normalized_status in _CANCELLED_STATUS_VALUES:
        return CfdiStatusClassification(CfdiStatusOutcome.CANCELLED, "CFDI is cancelled")
    if normalized_status in _NOT_FOUND_STATUS_VALUES or normalized_code in _NOT_FOUND_STATUS_CODES:
        return CfdiStatusClassification(
            CfdiStatusOutcome.NOT_FOUND, "CFDI is not available in SAT consultation"
        )
    if normalized_code in _UNAUTHORIZED_STATUS_CODES:
        return CfdiStatusClassification(
            CfdiStatusOutcome.UNAUTHORIZED, "requester is not authorized to consult this CFDI"
        )
    if normalized_code in _RETRYABLE_STATUS_CODES:
        return CfdiStatusClassification(
            CfdiStatusOutcome.RETRYABLE,
            "SAT status consultation returned a transient outcome",
            retryable=True,
        )
    if normalized_code in _PERMANENT_STATUS_CODES:
        return CfdiStatusClassification(
            CfdiStatusOutcome.PERMANENT, "SAT status consultation returned a permanent failure"
        )

    return CfdiStatusClassification(
        CfdiStatusOutcome.UNKNOWN, "unknown CFDI status consultation outcome"
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


def _normalize_status_text(status: str | None) -> str:
    return "" if status is None else "_".join(str(status).strip().lower().split())


def _redact_identifier(value: str) -> str:
    if not value:
        return ""
    if len(value) <= 8:
        return "<redacted>"
    return f"{value[:4]}...{value[-4:]}"


def _safe_text(value: object) -> str:
    text = str(value)
    pattern = r'access_' + r'tok' + r'en="[^"]*"'
    replacement = 'access_' + 'tok' + 'en="<redacted>"'
    text = re.sub(pattern, replacement, text)
    for forbidden in ("access_" + "tok" + "en", "Authorization:", "PRIVATE KEY", "BEGIN CERTIFICATE"):
        text = text.replace(forbidden, "<redacted>")
    return text
