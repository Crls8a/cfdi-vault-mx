"""Allowed categorized SAT results for the PostgreSQL repository."""


class RepositoryBusy(RuntimeError):
    """No operation slot is available for a campaign."""


class ClaimAlreadyCompleted(RuntimeError):
    """An idempotency key points to a terminal or expired claim."""

VERIFY_RESULTS = {
    "pending", "package", "no_data", "error", "expired",
    "duplicate_active_request", "sat_too_many_results", "service_window_exceeded",
    "download_uncertain",
}
REQUEST_STATUS = {
    "pending": "waiting_verify", "package": "package", "no_data": "no_data",
    "error": "failed", "expired": "expired",
    "duplicate_active_request": "failed", "sat_too_many_results": "failed",
    "service_window_exceeded": "service_window_exceeded", "download_uncertain": "uncertain",
}
