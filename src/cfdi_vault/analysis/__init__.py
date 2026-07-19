"""Private financial-analysis contracts for normalized CFDI evidence."""

from cfdi_vault.analysis.monthly import (
    MonthlyAggregate,
    MonthlyAnalysisRecord,
    MonthlyAnalysisReport,
    analyze_monthly,
)
from cfdi_vault.analysis.postgres import (
    MonthlyAnalysisPostgresAdapter,
    monthly_records_statement,
)

__all__ = [
    "MonthlyAggregate",
    "MonthlyAnalysisRecord",
    "MonthlyAnalysisReport",
    "analyze_monthly",
    "MonthlyAnalysisPostgresAdapter",
    "monthly_records_statement",
]
