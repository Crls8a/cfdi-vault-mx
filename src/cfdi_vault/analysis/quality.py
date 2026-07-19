"""Pure, redacted quality aggregates for normalized CFDI evidence.

The module owns only classification of already-normalized observations.  It
does not read PostgreSQL or artifacts, contact SAT, persist findings, or make
tax/accounting conclusions.  A database adapter can map durable ledger rows
and worker state into :class:`QualityObservation` values later.

The snapshot has a fixed, documented category vocabulary.  ``parser_status``
uses the existing parser statuses (``complete``, ``partial`` and
``unsupported-error``); unknown parser values are explicitly classified as
``unsupported_parser``.  ``reconciliation_state`` accepts the existing
``domain.ReconciliationState`` values.  Unknown/invalid reconciliation values
are classified as ``manual_review`` rather than becoming a new state.  The
small set of recovery aliases (for example ``service_window_exceeded``) are
input categories from the runner and are not added to the domain enum.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from types import MappingProxyType

from cfdi_vault.domain import ReconciliationState

QUALITY_CATEGORIES: tuple[str, ...] = (
    "metadata_without_xml",
    "xml_without_metadata",
    "cancelled_with_xml",
    "duplicate_or_conflicting_xml",
    "partial_parser",
    "unsupported_parser",
    "missing_payment_complement",
    "uncertain_recovery",
    "expired_recovery",
    "manual_review",
    "failed_recovery",
)

_CATEGORY_SET = frozenset(QUALITY_CATEGORIES)
_PARSER_COMPLETE = frozenset({"complete", "empty"})
_PARSER_PARTIAL = frozenset({"partial", "partial_parser", "metadata_only"})
_RECONCILIATION_STATES = frozenset(state.value.lower() for state in ReconciliationState)
_UNCERTAIN_STATES = frozenset(
    {
        ReconciliationState.XML_PENDING.value.lower(),
        ReconciliationState.XML_REQUESTED.value.lower(),
        ReconciliationState.STATE_CHECK_PENDING.value.lower(),
        ReconciliationState.RETRY_SCHEDULED.value.lower(),
        "uncertain",
        "uncertain_recovery",
        "download_uncertain",
    }
)
_EXPIRED_STATES = frozenset(
    {"expired", "expired_recovery", "service_window_exceeded", "pending_after_budget", "sat_expired"}
)
_FAILED_STATES = frozenset(
    {
        ReconciliationState.FAILED_PERMANENT.value.lower(),
        "failed",
        "failed_recovery",
        "download_failed",
        "verify_failed",
        "error",
    }
)
_MANUAL_STATES = frozenset({"", "unknown", "manual_review", "manual-review"})


@dataclass(frozen=True, slots=True)
class QualityObservation:
    """One identifier-free quality input copied from durable evidence.

    The booleans deliberately carry only presence/conflict facts; they do not
    contain UUIDs, RFCs, SAT identifiers, paths, or raw payloads.  Statuses
    are normalized to lowercase at construction and are safe to include only
    in private classification logic, never in the aggregate output.
    """

    metadata_present: bool = False
    xml_present: bool = False
    cancelled_metadata: bool = False
    xml_conflict: bool = False
    payment_expected: bool = False
    payment_present: bool = False
    parser_status: str = "complete"
    reconciliation_state: str = ReconciliationState.DISCOVERED_IN_METADATA.value

    def __post_init__(self) -> None:
        for name in (
            "metadata_present",
            "xml_present",
            "cancelled_metadata",
            "xml_conflict",
            "payment_expected",
            "payment_present",
        ):
            if type(getattr(self, name)) is not bool:
                raise TypeError(f"quality-{name}-bool-required")
        object.__setattr__(self, "parser_status", _normalize_status(self.parser_status, "parser"))
        object.__setattr__(
            self,
            "reconciliation_state",
            _normalize_status(self.reconciliation_state, "reconciliation"),
        )

    def __repr__(self) -> str:
        """Return a representation that cannot expose source status values."""

        return "QualityObservation(<redacted>)"


@dataclass(frozen=True, slots=True)
class QualityBucket:
    """Aggregate count for one documented quality category."""

    category: str
    count: int

    def __post_init__(self) -> None:
        if self.category not in _CATEGORY_SET:
            raise ValueError("quality-category-invalid")
        if type(self.count) is not int or self.count < 0:
            raise TypeError("quality-count-invalid")

    def __repr__(self) -> str:
        """Return a redacted representation of one aggregate bucket."""

        return "QualityBucket(<redacted>)"


@dataclass(frozen=True, slots=True)
class QualitySnapshot:
    """Deterministic, aggregate-only quality result.

    ``buckets`` contains only categories with a positive count, in the fixed
    ``QUALITY_CATEGORIES`` order.  ``counts`` exposes all documented
    categories, including zeroes, through an immutable mapping.
    """

    buckets: tuple[QualityBucket, ...]
    total_observations: int

    def __post_init__(self) -> None:
        if type(self.buckets) is not tuple or any(not isinstance(bucket, QualityBucket) for bucket in self.buckets):
            raise TypeError("quality-buckets-required")
        if type(self.total_observations) is not int or self.total_observations < 0:
            raise TypeError("quality-observation-count-invalid")
        categories = tuple(bucket.category for bucket in self.buckets)
        if categories != tuple(category for category in QUALITY_CATEGORIES if category in categories):
            raise ValueError("quality-bucket-order-invalid")

    @property
    def counts(self) -> Mapping[str, int]:
        """Return immutable counts for every documented category."""

        values = {category: 0 for category in QUALITY_CATEGORIES}
        values.update({bucket.category: bucket.count for bucket in self.buckets})
        return MappingProxyType(values)

    @property
    def rows(self) -> tuple[QualityBucket, ...]:
        """Return buckets using the common analysis-report terminology."""

        return self.buckets

    def count(self, category: str) -> int:
        """Return one category count, raising for an undocumented category."""

        if category not in _CATEGORY_SET:
            raise ValueError("quality-category-invalid")
        return self.counts[category]

    def __repr__(self) -> str:
        """Return a representation that contains no observation details."""

        return "QualitySnapshot(<redacted>)"


def snapshot_quality(observations: Iterable[QualityObservation]) -> QualitySnapshot:
    """Classify observations into deterministic, de-duplicated categories.

    Each observation increments a category at most once, even when multiple
    boolean/status signals map to the same category.  No row-level input is
    copied to the result.  The function is pure and has no filesystem,
    database, network, or fiscal-policy side effects.

    Raises:
        TypeError: if ``observations`` is not iterable or contains a value
            other than :class:`QualityObservation`.
    """

    if isinstance(observations, (str, bytes)):
        raise TypeError("quality-observations-required")
    try:
        iterator = iter(observations)
    except TypeError as exc:
        raise TypeError("quality-observations-required") from exc

    counts = {category: 0 for category in QUALITY_CATEGORIES}
    total = 0
    for observation in iterator:
        if not isinstance(observation, QualityObservation):
            raise TypeError("quality-observation-required")
        total += 1
        for category in _categories_for(observation):
            counts[category] += 1

    buckets = tuple(QualityBucket(category, counts[category]) for category in QUALITY_CATEGORIES if counts[category])
    return QualitySnapshot(buckets=buckets, total_observations=total)


def _categories_for(observation: QualityObservation) -> tuple[str, ...]:
    categories: set[str] = set()
    if observation.metadata_present and not observation.xml_present:
        categories.add("metadata_without_xml")
    if observation.xml_present and not observation.metadata_present:
        categories.add("xml_without_metadata")
    if observation.cancelled_metadata and observation.xml_present:
        categories.add("cancelled_with_xml")
    if observation.xml_conflict:
        categories.add("duplicate_or_conflicting_xml")
    if observation.payment_expected and not observation.payment_present:
        categories.add("missing_payment_complement")

    parser_status = observation.parser_status
    if parser_status in _PARSER_PARTIAL:
        categories.add("partial_parser")
    elif parser_status not in _PARSER_COMPLETE:
        # Unknown and invalid parser statuses fail closed as unsupported.
        categories.add("unsupported_parser")

    reconciliation_state = observation.reconciliation_state
    if reconciliation_state in _UNCERTAIN_STATES:
        categories.add("uncertain_recovery")
    elif reconciliation_state in _EXPIRED_STATES:
        categories.add("expired_recovery")
    elif reconciliation_state in _FAILED_STATES:
        categories.add("failed_recovery")
    elif reconciliation_state not in _RECONCILIATION_STATES or reconciliation_state in _MANUAL_STATES:
        # UNKNOWN and invalid values never become new domain states.
        categories.add("manual_review")

    return tuple(category for category in QUALITY_CATEGORIES if category in categories)


def _normalize_status(value: str | ReconciliationState, kind: str) -> str:
    if isinstance(value, ReconciliationState):
        value = value.value
    if not isinstance(value, str):
        raise TypeError(f"quality-{kind}-status-required")
    return value.strip().lower().replace("-", "_")
