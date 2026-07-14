"""Offline storage observability CLI commands."""

from __future__ import annotations

import os
from collections.abc import Callable
from pathlib import Path

import typer

from cfdi_vault.adapters.storage import ReadOnlyFilesystemStorage
from cfdi_vault.storage_observability import (
    InvalidStorageReferenceError,
    StorageObservabilityService,
    StorageObservation,
    StorageObservationError,
)

StorageServiceFactory = Callable[[Path | None], StorageObservabilityService]


def _default_service(storage: Path | None) -> StorageObservabilityService:
    """Compose read-only filesystem observation without checking or creating roots."""

    root = storage or Path(os.getenv("CFDI_STORAGE_ROOT", "storage"))
    return StorageObservabilityService(ReadOnlyFilesystemStorage(root))


_service_factory: StorageServiceFactory = _default_service


def status(
    reference: str = typer.Argument(
        ...,
        help="Canonical relative storage reference; its raw value is never echoed.",
    ),
    storage: Path | None = typer.Option(
        None,
        "--storage",
        help="Filesystem root to inspect; the resolved physical path is never printed.",
    ),
) -> None:
    """Report whether offline filesystem evidence exists, using redacted output."""

    observation = _observe(reference, storage, locate=False)
    _print_status(observation)
    if not observation.exists:
        raise typer.Exit(code=1)


def locate(
    reference: str = typer.Argument(
        ...,
        help="Canonical relative storage reference; its raw value is never echoed.",
    ),
    storage: Path | None = typer.Option(
        None,
        "--storage",
        help="Filesystem root to inspect; the resolved physical path is never printed.",
    ),
) -> None:
    """Return a redacted logical location without exposing a physical path."""

    observation = _observe(reference, storage, locate=True)
    if not observation.exists:
        typer.echo("location=unavailable")
        typer.echo(f"reference={observation.reference}")
        typer.echo("reason=not_found")
        raise typer.Exit(code=1)
    typer.echo(f"location={observation.location}")
    typer.echo(f"size_bytes={observation.size_bytes}")
    typer.echo(f"sha256={observation.sha256_prefix}")


def _observe(reference: str, storage: Path | None, *, locate: bool) -> StorageObservation:
    """Map validation, adapter, and composition failures to stable CLI errors."""

    try:
        service = _service_factory(storage)
        return service.locate(reference) if locate else service.status(reference)
    except InvalidStorageReferenceError:
        typer.echo("error=invalid_storage_reference", err=True)
        raise typer.Exit(code=1) from None
    except StorageObservationError:
        typer.echo("error=storage_observation_failed", err=True)
        raise typer.Exit(code=1) from None
    except Exception:
        typer.echo("error=storage_observation_failed", err=True)
        raise typer.Exit(code=1) from None


def _print_status(observation: StorageObservation) -> None:
    typer.echo(f"status={'exists' if observation.exists else 'not_found'}")
    typer.echo(f"reference={observation.reference}")
    typer.echo(f"category={observation.category}")
    if observation.exists:
        typer.echo(f"size_bytes={observation.size_bytes}")
        typer.echo(f"sha256={observation.sha256_prefix}")


def register(storage_app: typer.Typer) -> None:
    """Register the offline storage command family."""

    storage_app.command("status")(status)
    storage_app.command("locate")(locate)
