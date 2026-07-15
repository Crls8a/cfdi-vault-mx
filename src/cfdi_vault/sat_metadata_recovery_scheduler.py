"""Pure due selection for one persisted SAT metadata recovery wake."""

from __future__ import annotations

from collections.abc import Iterable
from datetime import datetime, timezone

from cfdi_vault.sat_metadata_recovery import RecoveryStatus
from cfdi_vault.sat_metadata_recovery_state import MetadataRecoveryStateRecord

_IMMEDIATE = frozenset({RecoveryStatus.PACKAGES_READY, RecoveryStatus.DOWNLOADING})


def select_due_metadata_recovery(
    records: Iterable[MetadataRecoveryStateRecord], *, profile_id: str, now: datetime,
) -> str | None:
    """Return at most one safe recovery reference due for the exact profile."""

    checked_at = _utc(now)
    due: list[str] = []
    for record in records:
        recovery = record.recovery
        actionable = recovery.status in _IMMEDIATE
        if recovery.status is RecoveryStatus.VERIFY_SCHEDULED:
            next_due = recovery.next_check_at
            actionable = next_due is not None and checked_at >= min(
                _utc(next_due), _utc(recovery.deadline_at)
            )
        if record.profile_id == profile_id and actionable:
            due.append(recovery.recovery_ref)
    return min(due) if due else None


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)
