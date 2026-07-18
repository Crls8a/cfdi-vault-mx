from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

from cfdi_vault import sat_metadata_recovery_state as recovery_state
from cfdi_vault.sat_metadata_recovery import RecoveryStatus
from cfdi_vault.sat_metadata_recovery_scheduler import (
    campaign_monitor_lock,
    render_campaign_cron_entry,
    select_due_metadata_recovery,
)

NOW = datetime(2026, 7, 1, tzinfo=timezone.utc)


def _record(ref: str, status: RecoveryStatus, *, profile: str = "profile-synthetic",
            due: datetime | None = None, deadline: datetime | None = None):
    recovery = SimpleNamespace(
        recovery_ref=ref, status=status, created_at=NOW - timedelta(days=1),
        next_check_at=due, deadline_at=deadline or NOW + timedelta(days=6),
    )
    return SimpleNamespace(profile_id=profile, recovery=recovery)


def test_selector_filters_profile_terminal_and_not_due_records() -> None:
    records = (
        _record("run-000000000001", RecoveryStatus.VERIFY_SCHEDULED, due=NOW + timedelta(minutes=1)),
        _record("run-000000000002", RecoveryStatus.COMPLETED),
        _record("run-000000000003", RecoveryStatus.PACKAGES_READY, profile="other-profile"),
    )

    assert select_due_metadata_recovery(records, profile_id="profile-synthetic", now=NOW) is None


def test_selector_uses_deadline_and_returns_at_most_one_deterministically() -> None:
    records = (
        _record("run-000000000003", RecoveryStatus.DOWNLOADING),
        _record("run-000000000002", RecoveryStatus.PACKAGES_READY),
        _record("run-000000000001", RecoveryStatus.VERIFY_SCHEDULED,
                due=NOW + timedelta(hours=1), deadline=NOW),
    )

    assert select_due_metadata_recovery(
        records, profile_id="profile-synthetic", now=NOW
    ) == "run-000000000001"


def test_selector_uses_new_service_window_deadline() -> None:
    records = (_record(
        "run-000000000001", RecoveryStatus.VERIFY_SCHEDULED,
        due=NOW + timedelta(hours=1), deadline=NOW + timedelta(days=6),
    ),)
    records[0].recovery.service_window_expires_at = NOW

    assert select_due_metadata_recovery(
        records, profile_id="profile-synthetic", now=NOW
    ) == "run-000000000001"


def test_campaign_monitor_lock_is_non_reentrant_and_cron_is_due_only(tmp_path: Path) -> None:
    root = tmp_path / "private-storage"
    with campaign_monitor_lock(root):
        with pytest.raises(recovery_state.MetadataRecoveryStateError, match="recovery-state-busy"):
            with campaign_monitor_lock(root):
                pass

    assert render_campaign_cron_entry(
        profile_id="default", campaign_ref="cmp-0123456789ab", grant_ref="grt-0123456789ab",
    ) == (
        "*/5 * * * * cfdi-vault sat campaign run --profile default "
        "--campaign-ref cmp-0123456789ab --grant grt-0123456789ab\n"
    )
