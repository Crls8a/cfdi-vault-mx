"""Canonical SAT authentication endpoint mapping and redacted descriptions."""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Mapping
from urllib.parse import parse_qsl, urlsplit, urlunsplit

from cfdi_vault.sat_auth_constants import AUTH_ENDPOINT

AUTH_ENDPOINT_ENV = "CFDI_VAULT_SAT_AUTH_ENDPOINT"
DEFAULT_AUTH_ENDPOINT = AUTH_ENDPOINT


@dataclass(frozen=True)
class RedactedEndpoint:
    logical_endpoint: str
    scheme: str
    host: str
    port: int
    path: str
    query_present: bool


def resolve_auth_endpoint(env: Mapping[str, str] | None = None) -> str:
    """Return the live auth endpoint without exposing local config details."""

    source = os.environ if env is None else env
    return source.get(AUTH_ENDPOINT_ENV, DEFAULT_AUTH_ENDPOINT).strip() or DEFAULT_AUTH_ENDPOINT


def auth_wsdl_endpoint(endpoint: str) -> str:
    """Return a singleWSDL URL while preserving endpoint host/path parity."""

    parts = urlsplit(endpoint)
    query = parts.query
    if not any(key.lower() == "singlewsdl" for key, _ in parse_qsl(query, keep_blank_values=True)):
        query = f"{query}&singleWsdl" if query else "singleWsdl"
    return urlunsplit((parts.scheme, parts.netloc, parts.path, query, ""))


def describe_endpoint(logical_endpoint: str, endpoint: str) -> RedactedEndpoint:
    """Describe endpoint routing without query values, headers, SOAP, or secrets."""

    parts = urlsplit(endpoint)
    scheme = parts.scheme or "https"
    host = parts.hostname or "unknown"
    port = parts.port or (443 if scheme == "https" else 80)
    path = parts.path or "/"
    return RedactedEndpoint(
        logical_endpoint=logical_endpoint,
        scheme=scheme,
        host=host,
        port=port,
        path=path,
        query_present=bool(parts.query),
    )
