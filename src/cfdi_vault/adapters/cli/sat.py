"""Reserved SAT CLI registration boundary.

The public SAT surface is registered by the productive campaign adapter.  The
former smoke, probe, diagnostic, live-gate, manual-recovery, backfill, and
legacy-scheduler commands remain available only as internal modules while
their public registrations are retired.
"""

from __future__ import annotations

import typer


def register(sat_app: typer.Typer) -> None:
    """Keep the SAT family hook without exposing experimental commands."""

    del sat_app
