"""Internal bridge from parsed XML projections to the V5 child ledgers.

The bridge owns only the post-artifact handoff.  It does not parse XML, open
storage, contact SAT, or expose fiscal rows.  Callers provide committed
document/evidence references so the V5 repository can verify provenance before
writing its idempotent child rows.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from cfdi_vault.accounting_ledger_v5_mapper import LedgerIntentMapping, LedgerWriteIntentMapper
from cfdi_vault.analysis.ledger_intent import LedgerWriteContext
from cfdi_vault.analysis.projection import AccountingProjection


@dataclass(frozen=True, slots=True)
class LedgerArtifactBinding:
    """Opaque durable references required to bind one parsed projection."""

    tenant_id: str
    work_ref: str
    document_id: int
    source_evidence_id: int
    parser_version: str

    def __post_init__(self) -> None:
        if type(self.document_id) is not int or self.document_id <= 0:
            raise ValueError("ledger-artifact-document-required")
        if type(self.source_evidence_id) is not int or self.source_evidence_id <= 0:
            raise ValueError("ledger-artifact-evidence-required")
        if not isinstance(self.tenant_id, str) or not self.tenant_id.strip():
            raise ValueError("ledger-artifact-tenant-required")
        if not isinstance(self.work_ref, str) or not self.work_ref.strip():
            raise ValueError("ledger-artifact-work-required")
        if not isinstance(self.parser_version, str) or not self.parser_version.strip():
            raise ValueError("ledger-artifact-parser-version-required")

    def __repr__(self) -> str:
        return "LedgerArtifactBinding(references_redacted=True)"


class LedgerProjectionWriter(Protocol):
    """Post-commit callback used by an artifact worker."""

    def write(self, projection: AccountingProjection, binding: LedgerArtifactBinding) -> LedgerIntentMapping:
        """Persist one parsed projection and return aggregate counters."""


class V5LedgerProjectionWriter:
    """Build and persist one provenance-bound V5 intent."""

    def __init__(self, mapper: LedgerWriteIntentMapper, *, normalization_generation: str = "cfdi-v5") -> None:
        if not isinstance(mapper, LedgerWriteIntentMapper):
            raise TypeError("ledger-artifact-mapper-required")
        self._mapper = mapper
        self._normalization_generation = normalization_generation

    def write(self, projection: AccountingProjection, binding: LedgerArtifactBinding) -> LedgerIntentMapping:
        """Map a projection exactly once per durable idempotency identity."""

        if not isinstance(projection, AccountingProjection):
            raise TypeError("ledger-artifact-projection-required")
        if not isinstance(binding, LedgerArtifactBinding):
            raise TypeError("ledger-artifact-binding-required")
        from cfdi_vault.analysis.ledger_intent import build_ledger_write_intent

        intent = build_ledger_write_intent(
            projection,
            context=LedgerWriteContext(tenant_ref=binding.tenant_id, work_ref=binding.work_ref),
            normalization_generation=self._normalization_generation,
        )
        return self._mapper.map(
            intent,
            tenant_id=binding.tenant_id,
            document_id=binding.document_id,
            source_evidence_id=binding.source_evidence_id,
            parser_version=binding.parser_version,
        )


__all__ = ["LedgerArtifactBinding", "LedgerProjectionWriter", "V5LedgerProjectionWriter"]
