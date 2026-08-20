"""Runtime composition helpers shared by the local control-panel API.

These functions used to live as private helpers inside ``adapters/cli``
(``common.py``, ``secrets.py``, ``storage.py``).  The Typer CLI has been
retired, but the panel still needs exactly this wiring: build a
:class:`~cfdi_vault.recovery_service.RecoveryService` from a validated
database URL and storage root, resolve a credential reference to its native
OS provider, and compose read-only storage observation.  Rather than keep a
package named ``cli`` alive purely to host them, they moved here unchanged in
behaviour.

Two contracts are preserved deliberately:

* ``provider_for_reference`` / ``credential_reference`` still raise
  ``typer.BadParameter`` on invalid input.  ``adapters/webapi/app.py`` catches
  that exact type to answer with ``secret-kind-invalid`` /
  ``secret-provider-unavailable``, and ADR 0006's tests assert it.  Changing
  the exception type here would silently change panel responses, which this
  move is not allowed to do.
* No function prints anything.  The CLI versions echoed operator text before
  raising ``typer.Exit``; a missing database URL is now a plain ``RuntimeError``
  that the panel already maps to ``*-database-unavailable``.
"""

from __future__ import annotations

import os
from pathlib import Path

import typer

from cfdi_vault import setup as setup_flow
from cfdi_vault.adapters.storage import ReadOnlyFilesystemStorage
from cfdi_vault.cache import RedisCache
from cfdi_vault.os_secret_providers import OsSecretProviderError, native_provider_for_reference
from cfdi_vault.queueing import RabbitMqQueue
from cfdi_vault.recovery_service import RecoveryService
from cfdi_vault.secrets import CredentialKind, CredentialReference
from cfdi_vault.storage_observability import StorageObservabilityService


def recovery_service(
    database_url: str | None = None,
    storage: Path | None = None,
) -> RecoveryService:
    """Build the recovery service, attaching queue/cache adapters only if configured."""

    queue = RabbitMqQueue(os.environ["RABBITMQ_URL"]) if os.getenv("RABBITMQ_URL") else None
    cache = RedisCache(os.environ["REDIS_URL"]) if os.getenv("REDIS_URL") else None
    return RecoveryService(
        database_url=require_database_url(database_url),
        storage_root=resolve_storage_root(storage),
        queue=queue,
        cache=cache,
    )


def require_database_url(database_url: str | None = None) -> str:
    """Return an explicit URL or ``DATABASE_URL``; the URL itself is never echoed."""

    resolved_url = database_url or os.getenv("DATABASE_URL")
    if not resolved_url:
        raise RuntimeError("database_url_required")
    return resolved_url


def resolve_storage_root(storage: Path | None = None) -> Path:
    """Resolve the artifact root from an explicit path, ``CFDI_STORAGE_ROOT``, or ``storage/``."""

    return storage or Path(os.getenv("CFDI_STORAGE_ROOT", "storage"))


def credential_reference(reference_uri: str, raw_kind: str) -> CredentialReference:
    """Build a typed credential reference, rejecting an unknown kind."""

    normalized = raw_kind.strip().lower().replace("-", "_")
    try:
        kind = CredentialKind(normalized)
    except ValueError as exc:
        raise typer.BadParameter("kind must be certificate, private-key, phrase, or generic") from exc
    return CredentialReference(uri=reference_uri, kind=kind)


def provider_for_reference(reference: CredentialReference) -> object:
    """Select the native OS secret provider backing one credential reference."""

    try:
        return native_provider_for_reference(
            reference,
            platform="win32" if os.environ.get("LOCALAPPDATA") else None,
            allow_synthetic=True,
        )
    except OsSecretProviderError as exc:
        raise typer.BadParameter(str(exc)) from None


def setup_provider(profile_id: str) -> object:
    """Select the provider for a profile's phrase reference, falling back to the default reference."""

    try:
        phrase_ref = setup_flow.load_profile(profile_id).phrase_ref
    except setup_flow.SetupError:
        phrase_ref = setup_flow.default_phrase_reference(
            profile_id,
            platform="win32" if os.environ.get("LOCALAPPDATA") else None,
        )
    return provider_for_reference(CredentialReference(uri=phrase_ref, kind=CredentialKind.PHRASE))


def storage_observability_service(storage: Path | None = None) -> StorageObservabilityService:
    """Compose read-only filesystem observation without checking or creating roots."""

    return StorageObservabilityService(ReadOnlyFilesystemStorage(resolve_storage_root(storage)))


__all__ = [
    "credential_reference",
    "provider_for_reference",
    "recovery_service",
    "require_database_url",
    "resolve_storage_root",
    "setup_provider",
    "storage_observability_service",
]
