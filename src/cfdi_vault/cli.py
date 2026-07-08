"""Compatibility shim for the public Typer CLI entrypoint."""

from __future__ import annotations

from cfdi_vault.adapters.cli.app import app

__all__ = ["app"]
