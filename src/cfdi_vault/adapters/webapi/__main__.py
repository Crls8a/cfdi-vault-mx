"""Entry point for ``python -m cfdi_vault.adapters.webapi`` (ADR 0004)."""

from __future__ import annotations

from cfdi_vault.adapters.webapi.app import run

if __name__ == "__main__":
    run()
