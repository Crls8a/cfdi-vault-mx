"""Reserved SAT CLI registration boundary.

The public SAT surface is registered by the productive campaign adapter. The
former smoke, probe, diagnostic, live-gate, manual-recovery, backfill, and
legacy-scheduler command modules have been deleted outright — they were
unregistered, unimported, and untested (see `tests/test_cli_import_graph.py`).
"""

from __future__ import annotations

import typer


def register(sat_app: typer.Typer) -> None:
    """Keep the SAT family hook without exposing experimental commands."""

    del sat_app
