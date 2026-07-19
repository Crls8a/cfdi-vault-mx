"""Private financial-analysis contracts for normalized CFDI evidence."""

from cfdi_vault.analysis.accounting import (
    PaymentSummaryReport,
    PaymentSummaryRow,
    PayrollSummaryReport,
    PayrollSummaryRow,
    TaxSummaryReport,
    TaxSummaryRow,
    summarize_payments,
    summarize_payroll,
    summarize_taxes,
)
from cfdi_vault.analysis.monthly import (
    MonthlyAggregate,
    MonthlyAnalysisRecord,
    MonthlyAnalysisReport,
    MonthlyTrend,
    analyze_monthly,
)
from cfdi_vault.analysis.normalization import (
    ConceptNormalizationResult,
    ConceptRecord,
    normalize_concepts,
)
from cfdi_vault.analysis.payments import (
    PaymentNormalizationResult,
    PaymentRecord,
    normalize_payments,
)
from cfdi_vault.analysis.payroll import (
    PayrollNormalizationResult,
    PayrollRecord,
    normalize_payroll,
)
from cfdi_vault.analysis.postgres import (
    MonthlyAnalysisPostgresAdapter,
    monthly_records_statement,
)
from cfdi_vault.analysis.projection import (
    AccountingDispatch,
    AccountingProjection,
    AccountingProjectionDispatcher,
    project_accounting_xml,
)
from cfdi_vault.analysis.quality import (
    QUALITY_CATEGORIES,
    QualityBucket,
    QualityObservation,
    QualitySnapshot,
    snapshot_quality,
)
from cfdi_vault.analysis.reporting import AnalysisPeriod, FinancialAnalysisReport
from cfdi_vault.analysis.taxes import (
    TaxNormalizationResult,
    TaxRecord,
    normalize_taxes,
)

__all__ = [
    "MonthlyAggregate",
    "MonthlyAnalysisRecord",
    "MonthlyAnalysisReport",
    "MonthlyTrend",
    "analyze_monthly",
    "TaxSummaryRow",
    "TaxSummaryReport",
    "summarize_taxes",
    "PaymentSummaryRow",
    "PaymentSummaryReport",
    "summarize_payments",
    "PayrollSummaryRow",
    "PayrollSummaryReport",
    "summarize_payroll",
    "MonthlyAnalysisPostgresAdapter",
    "monthly_records_statement",
    "QUALITY_CATEGORIES",
    "QualityObservation",
    "QualityBucket",
    "QualitySnapshot",
    "snapshot_quality",
    "AnalysisPeriod",
    "FinancialAnalysisReport",
    "ConceptNormalizationResult",
    "ConceptRecord",
    "normalize_concepts",
    "TaxNormalizationResult",
    "TaxRecord",
    "normalize_taxes",
    "PaymentNormalizationResult",
    "PaymentRecord",
    "normalize_payments",
    "PayrollNormalizationResult",
    "PayrollRecord",
    "normalize_payroll",
    "AccountingDispatch",
    "AccountingProjection",
    "AccountingProjectionDispatcher",
    "project_accounting_xml",
]
