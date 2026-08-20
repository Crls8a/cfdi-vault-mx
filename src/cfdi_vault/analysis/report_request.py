"""Request validation and composition for one aggregate financial report.

These helpers used to be private functions in ``adapters/cli/analysis.py``.
The Typer command is gone; the validation it performed is not, because
``GET /api/analysis/report`` still has to answer the same questions before
touching PostgreSQL: is a database URL configured, does the named profile
exist and match itself, is the period a valid ISO range.

Nothing here prints, and nothing here returns tenant values, database URLs,
source rows, paths, hashes, or payloads — failures carry a bounded
``analysis-*`` reason slug only.
"""

from __future__ import annotations

import os
from datetime import date
from typing import Any

from cfdi_vault.analysis.postgres import MonthlyAnalysisPostgresAdapter
from cfdi_vault.analysis.postgres_accounting import AccountingPostgresAdapter
from cfdi_vault.analysis.postgres_report import PostgresFinancialAnalysisService
from cfdi_vault.db import create_engine_from_url, create_session_factory, ensure_tables_exist
from cfdi_vault.setup_core import LocalProfile, SetupError, load_profile

ANALYSIS_TABLES = (
    "cfdi_documents",
    "cfdi_metadata_ledger",
    "cfdi_taxes",
    "cfdi_payments",
    "cfdi_payroll",
    "xml_evidence",
)


class AnalysisReportError(ValueError):
    """Reject an analysis request with a bounded reason slug and nothing else."""

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


def resolve_database_url(value: str | None) -> str:
    """Return an explicit URL or ``DATABASE_URL``; the URL itself is never echoed."""

    resolved = value or os.getenv("DATABASE_URL")
    if not isinstance(resolved, str) or not resolved.strip():
        raise AnalysisReportError("analysis-database-required")
    return resolved


def load_exact_profile(profile_id: str) -> LocalProfile:
    """Load a profile and refuse one whose document disagrees with the requested id."""

    try:
        loaded = load_profile(profile_id)
    except SetupError:
        raise
    except Exception as exc:
        raise SetupError(["profile unavailable"]) from exc
    if loaded.profile_id != profile_id:
        raise AnalysisReportError("analysis-profile-mismatch")
    return loaded


def parse_date(value: str) -> date:
    """Parse one inclusive ISO period bound."""

    if not isinstance(value, str) or not value.strip():
        raise AnalysisReportError("analysis-date-invalid")
    try:
        parsed = date.fromisoformat(value.strip())
    except ValueError as exc:
        raise AnalysisReportError("analysis-date-invalid") from exc
    return parsed


def build_report(*, database_url: str, tenant_id: str, start: date, end: date) -> dict[str, Any]:
    """Read one sanitized aggregate report from the PostgreSQL V5 projection."""

    engine = create_engine_from_url(database_url)
    try:
        ensure_tables_exist(engine, ANALYSIS_TABLES)
        factory = create_session_factory(engine)
        service = PostgresFinancialAnalysisService(
            MonthlyAnalysisPostgresAdapter(factory),
            AccountingPostgresAdapter(factory),
        )
        return service.build_report(tenant_id, start, end).to_public_dict()
    finally:
        engine.dispose()


__all__ = [
    "ANALYSIS_TABLES",
    "AnalysisReportError",
    "build_report",
    "load_exact_profile",
    "parse_date",
    "resolve_database_url",
]
