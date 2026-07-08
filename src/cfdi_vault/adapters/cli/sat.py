"""SAT CLI command registration."""

from __future__ import annotations

import typer

from .sat_auth import (
    sat_auth_smoke,
    sat_diff_auth_oracle,
    sat_inspect_auth_contract,
    sat_lint_auth_envelope,
    sat_oracle_auth_fingerprint,
)
from .sat_backfill import sat_backfill_plan, sat_backfill_submit
from .sat_metadata import sat_diagnose_live, sat_metadata_request_smoke, sat_metadata_request_state
from .sat_probes import sat_probe_auth_matrix, sat_probe_auth_post, sat_probe_transport, sat_probe_verify_post
from .sat_verify import (
    sat_download_live_gate,
    sat_metadata_verify_smoke,
    sat_package_download_smoke,
    sat_verify_due,
    sat_verify_live_gate,
)


def register(sat_app: typer.Typer, backfill_app: typer.Typer) -> None:
    """Register SAT commands."""

    sat_app.command("auth-smoke")(sat_auth_smoke)
    sat_app.command("metadata-request-smoke")(sat_metadata_request_smoke)
    sat_app.command("metadata-request-state")(sat_metadata_request_state)
    backfill_app.command("plan")(sat_backfill_plan)
    backfill_app.command("submit")(sat_backfill_submit)
    sat_app.command("verify-due")(sat_verify_due)
    sat_app.command("package-download-smoke")(sat_package_download_smoke)
    sat_app.command("metadata-verify-smoke")(sat_metadata_verify_smoke)
    sat_app.command("verify-live-gate")(sat_verify_live_gate)
    sat_app.command("download-live-gate")(sat_download_live_gate)
    sat_app.command("inspect-auth-contract")(sat_inspect_auth_contract)
    sat_app.command("lint-auth-envelope")(sat_lint_auth_envelope)
    sat_app.command("oracle-auth-fingerprint")(sat_oracle_auth_fingerprint)
    sat_app.command("diff-auth-oracle")(sat_diff_auth_oracle)
    sat_app.command("diagnose-live")(sat_diagnose_live)
    sat_app.command("probe-transport")(sat_probe_transport)
    sat_app.command("probe-auth-post")(sat_probe_auth_post)
    sat_app.command("probe-verify-post")(sat_probe_verify_post)
    sat_app.command("probe-auth-matrix")(sat_probe_auth_matrix)
