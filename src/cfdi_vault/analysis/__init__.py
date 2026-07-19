"""Private financial-analysis contracts for normalized CFDI evidence."""

from cfdi_vault.analysis.monthly import (
    MonthlyAggregate,
    MonthlyAnalysisRecord,
    MonthlyAnalysisReport,
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
from cfdi_vault.analysis.postgres import (
    MonthlyAnalysisPostgresAdapter,
    monthly_records_statement,
)
from cfdi_vault.analysis.taxes import (
    TaxNormalizationResult,
    TaxRecord,
    normalize_taxes,
)

__all__ = [
    "MonthlyAggregate",
    "MonthlyAnalysisRecord",
    "MonthlyAnalysisReport",
    "analyze_monthly",
    "MonthlyAnalysisPostgresAdapter",
    "monthly_records_statement",
    "ConceptNormalizationResult",
    "ConceptRecord",
    "normalize_concepts",
    "TaxNormalizationResult",
    "TaxRecord",
    "normalize_taxes",
    "PaymentNormalizationResult",
    "PaymentRecord",
    "normalize_payments",
]
