"""Origin/CSRF guard and access-log redaction for the local control-panel API.

ADR 0004 requires every state-changing request to be rejected unless its
``Origin`` header matches the panel's own origin, and requires that the FIEL
phrase field is never emitted by the API's own access-log middleware.  This
module implements both: an ASGI middleware for the origin check, and a small
redaction helper that follows the same phrase-field naming convention already
used by the wizard (``phrase_value``/``phrase_confirmation`` in
``adapters/ui/fiel_wizard_logic.py``).
"""

from __future__ import annotations

import logging
from typing import Awaitable, Callable

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.types import ASGIApp

_STATE_CHANGING_METHODS = frozenset({"POST", "PUT", "DELETE", "PATCH"})
# ``value`` is the credential-registration body field (``POST /api/secret/register``,
# ADR 0006).  It carries raw credential material and therefore gets exactly the
# same access-log treatment as the FIEL phrase.
REDACTED_FIELD_NAMES = frozenset({"phrase", "phrase_value", "phrase_confirmation", "value"})
REDACTED_PLACEHOLDER = "<redacted>"


class OriginGuardMiddleware(BaseHTTPMiddleware):
    """Reject state-changing requests whose Origin does not match the panel's own origin."""

    def __init__(self, app: ASGIApp, *, allowed_origin: str) -> None:
        super().__init__(app)
        self._allowed_origin = allowed_origin

    async def dispatch(
        self, request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        if request.method in _STATE_CHANGING_METHODS:
            origin = request.headers.get("origin")
            if origin != self._allowed_origin:
                return JSONResponse({"error": "origin-forbidden"}, status_code=403)
        return await call_next(request)


def redact_sensitive_fields(payload: dict[str, object]) -> dict[str, object]:
    """Return a copy of ``payload`` with any FIEL phrase field masked."""

    return {
        key: (REDACTED_PLACEHOLDER if key.lower() in REDACTED_FIELD_NAMES else value)
        for key, value in payload.items()
    }


class RedactingAccessLogFilter(logging.Filter):
    """Mask any FIEL phrase field carried in a log record's ``payload`` extra.

    Call sites that log a request body must pass it as
    ``extra={"payload": body}``; this filter redacts it in place before the
    record is formatted, so the phrase field can never reach an access log.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        payload = getattr(record, "payload", None)
        if isinstance(payload, dict):
            record.payload = redact_sensitive_fields(payload)
        return True
