"""Operator-facing aggregate financial analysis commands.

This adapter validates the local profile and period, then delegates all report
composition to the read-only PostgreSQL analysis service.  It never prints
tenant values, database URLs, source rows, paths, hashes, or payloads.
"""

from __future__ import annotations

import json
import os
from datetime import date
from typing import Any

import typer

from cfdi_vault.analysis.postgres import MonthlyAnalysisPostgresAdapter
from cfdi_vault.analysis.postgres_accounting import AccountingPostgresAdapter
from cfdi_vault.analysis.postgres_report import PostgresFinancialAnalysisService
from cfdi_vault.db import create_engine_from_url, create_session_factory, ensure_tables_exist
from cfdi_vault.setup_core import LocalProfile, SetupError, load_profile

_ANALYSIS_TABLES = (
    "cfdi_documents",
    "cfdi_metadata_ledger",
    "cfdi_taxes",
    "cfdi_payments",
    "cfdi_payroll",
    "xml_evidence",
)


def report(
    profile: str = typer.Option(..., "--profile", help="Exact local profile identifier."),
    tenant_id: str = typer.Option(..., "--tenant-id", help="Tenant scope; must match the profile."),
    from_date: str = typer.Option(..., "--from", help="Inclusive period start (YYYY-MM-DD)."),
    to_date: str = typer.Option(..., "--to", help="Inclusive period end (YYYY-MM-DD)."),
    database_url: str | None = typer.Option(None, "--database-url", help="PostgreSQL URL; defaults to DATABASE_URL."),
) -> None:
    """Print one PostgreSQL V5 financial report as sanitized aggregate JSON."""

    try:
        url = _database_url(database_url)
        loaded = _load_exact_profile(profile)
        if tenant_id != loaded.profile_id:
            raise _AnalysisCliError("analysis-tenant-profile-mismatch")
        start = _parse_date(from_date)
        end = _parse_date(to_date)
        if start > end:
            raise _AnalysisCliError("analysis-period-invalid")
        payload = _build_report(database_url=url, tenant_id=tenant_id, start=start, end=end)
    except _AnalysisCliError as error:
        _fail(error.reason)
    except SetupError:
        _fail("analysis-profile-invalid")
    except Exception:
        _fail("analysis-database-operation-failed")

    output = dict(payload)
    output["provenance"] = "postgres-v5-read"
    typer.echo(json.dumps(output, ensure_ascii=True, sort_keys=True, separators=(",", ":")))


class _AnalysisCliError(ValueError):
    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


def _database_url(value: str | None) -> str:
    resolved = value or os.getenv("DATABASE_URL")
    if not isinstance(resolved, str) or not resolved.strip():
        raise _AnalysisCliError("analysis-database-required")
    return resolved


def _load_exact_profile(profile_id: str) -> LocalProfile:
    try:
        loaded = load_profile(profile_id)
    except SetupError:
        raise
    except Exception as exc:
        raise SetupError(["profile unavailable"]) from exc
    if loaded.profile_id != profile_id:
        raise _AnalysisCliError("analysis-profile-mismatch")
    return loaded


def _parse_date(value: str) -> date:
    if not isinstance(value, str) or not value.strip():
        raise _AnalysisCliError("analysis-date-invalid")
    try:
        parsed = date.fromisoformat(value.strip())
    except ValueError as exc:
        raise _AnalysisCliError("analysis-date-invalid") from exc
    return parsed


def _build_report(*, database_url: str, tenant_id: str, start: date, end: date) -> dict[str, Any]:
    engine = create_engine_from_url(database_url)
    try:
        ensure_tables_exist(engine, _ANALYSIS_TABLES)
        factory = create_session_factory(engine)
        service = PostgresFinancialAnalysisService(
            MonthlyAnalysisPostgresAdapter(factory),
            AccountingPostgresAdapter(factory),
        )
        return service.build_report(tenant_id, start, end).to_public_dict()
    finally:
        engine.dispose()


def _fail(reason: str) -> None:
    typer.echo("error=analysis_report_failed", err=True)
    typer.echo(f"reason={reason}", err=True)
    raise typer.Exit(code=1)


def register(analysis_app: typer.Typer) -> None:
    """Register the aggregate-only analysis command family."""

    analysis_app.command("report")(report)
