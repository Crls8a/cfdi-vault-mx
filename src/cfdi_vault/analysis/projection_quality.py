"""Bridge an in-memory accounting projection into quality evidence.

This module owns only the pure handoff from :class:`AccountingProjection` to
the identifier-free :class:`QualityObservation` contract.  It does not read
PostgreSQL or artifacts, infer metadata/cancellation/reconciliation facts,
persist results, publish jobs, or contact SAT.  Those facts remain explicit
inputs until a tenant-safe worker mapper is approved.
"""

from __future__ import annotations

from cfdi_vault.analysis.projection import AccountingProjection
from cfdi_vault.analysis.quality import QualityObservation
from cfdi_vault.domain import ReconciliationState

__all__ = ["quality_observation_from_projection"]

_PARSER_STATUS_BY_COMPLETENESS = {
    "complete": "complete",
    "empty": "empty",
    "partial": "partial",
    "unsupported": "unsupported-error",
}


def quality_observation_from_projection(
    projection: AccountingProjection,
    *,
    metadata_present: bool,
    cancelled_metadata: bool = False,
    xml_conflict: bool = False,
    payment_expected: bool = False,
    reconciliation_state: str | ReconciliationState = ReconciliationState.DISCOVERED_IN_METADATA,
    payment_evidence_available: bool = True,
) -> QualityObservation:
    """Create redacted quality evidence from one in-memory projection.

    XML is present by definition because a projection could only be produced
    from XML.  Payment presence is derived solely from ``projection.payments``;
    cancellation, XML conflict, payment expectation, reconciliation, and
    payment-evidence availability are never inferred and must be supplied by
    the caller.

    ``metadata_present`` is intentionally required because the projection does
    not contain SAT metadata evidence.  The returned value contains booleans
    and bounded status categories only; its representation is redacted by
    :class:`QualityObservation`.

    Raises:
        TypeError: if ``projection`` is not an ``AccountingProjection``.  The
            remaining input types are validated by ``QualityObservation``.
        ValueError: if a projection has an unsupported completeness value.
    """

    if not isinstance(projection, AccountingProjection):
        raise TypeError("projection-quality-projection-required")
    try:
        parser_status = _PARSER_STATUS_BY_COMPLETENESS[projection.completeness]
    except KeyError:
        raise ValueError("projection-quality-completeness-invalid") from None

    return QualityObservation(
        metadata_present=metadata_present,
        xml_present=True,
        cancelled_metadata=cancelled_metadata,
        xml_conflict=xml_conflict,
        payment_expected=payment_expected,
        payment_present=bool(projection.payments),
        parser_status=parser_status,
        reconciliation_state=reconciliation_state,
        payment_evidence_available=payment_evidence_available,
    )
