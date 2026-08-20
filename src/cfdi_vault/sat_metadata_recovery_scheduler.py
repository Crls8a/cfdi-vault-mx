"""Pure due selection for one persisted SAT metadata recovery wake."""

from __future__ import annotations

from collections.abc import Iterable
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

from cfdi_vault import sat_metadata_recovery_state as recovery_state
from cfdi_vault.sat_metadata_recovery import RecoveryStatus
from cfdi_vault.sat_metadata_recovery_state import MetadataRecoveryStateRecord

_IMMEDIATE = frozenset({RecoveryStatus.PACKAGES_READY, RecoveryStatus.DOWNLOADING})


@contextmanager
def campaign_monitor_lock(
    storage_root: str | Path, *, repo_root: str | Path | None = None,
):
    """Serialize one whole campaign-run invocation across scheduler wakes."""
    path = recovery_state._resolved_state_path(
        storage_root, repo_root=repo_root, create_parent=True,
    )
    anchor = path.with_name("sat-campaign-monitor-operation")
    with recovery_state._exclusive_state_lock(anchor):
        yield


def render_campaign_cron_entry(*, executable: str = "cfdi-vault-campaign-run-worker") -> str:
    """Render a five-minute POSIX wake-up without installing or executing it.

    ADR 0005 moved campaign execution off a per-invocation ``--profile
    --campaign-ref --grant`` command: the host-only campaign-run consumer
    claims whatever is due from the durable ``sat_campaign_runs`` queue on
    its own, so a scheduled wake-up only needs to invoke it for one pass
    (``--once``) — there is nothing profile- or campaign-specific left to
    template.
    """
    value = executable
    if (
        not isinstance(value, str) or not value.strip()
        or any(char in value for char in "\r\n\0")
        or any(char.isspace() for char in value.strip())
    ):
        raise ValueError("scheduler-template-invalid")
    return f"*/5 * * * * {value.strip()} --once\n"


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
            deadline = getattr(recovery, "service_window_expires_at", None) or recovery.deadline_at
            actionable = next_due is not None and checked_at >= min(
                _utc(next_due), _utc(deadline)
            )
        if record.profile_id == profile_id and actionable:
            due.append(recovery.recovery_ref)
    return min(due) if due else None


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)
