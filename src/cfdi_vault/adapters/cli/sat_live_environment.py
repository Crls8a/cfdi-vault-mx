"""Sanitized environment preflight for productive SAT recovery commands."""

from __future__ import annotations

import os
from collections.abc import Mapping

LIVE_CI_FORBIDDEN = "live-ci-forbidden"
CANONICAL_ENDPOINTS_REQUIRED = "canonical-endpoints-required"

_FALSE_CI_VALUES = frozenset({"", "0", "false", "no", "off"})
_SAT_ENDPOINT_OVERRIDES = (
    "CFDI_VAULT_SAT_AUTH_ENDPOINT",
    "CFDI_VAULT_SAT_REQUEST_ENDPOINT",
    "CFDI_VAULT_SAT_VERIFY_ENDPOINT",
    "CFDI_VAULT_SAT_DOWNLOAD_ENDPOINT",
)


def canonical_live_recovery_preflight(
    environ: Mapping[str, str] | None = None,
) -> str | None:
    """Return an allowlisted rejection code without reading endpoint values."""

    current = os.environ if environ is None else environ
    ci_value = current.get("CI")
    if ci_value is not None and ci_value.strip().casefold() not in _FALSE_CI_VALUES:
        return LIVE_CI_FORBIDDEN
    if any(name in current for name in _SAT_ENDPOINT_OVERRIDES):
        return CANONICAL_ENDPOINTS_REQUIRED
    return None
