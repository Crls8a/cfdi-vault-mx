from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

from cfdi_vault.sat_metadata_recovery import RecoveryStatus
from cfdi_vault.sat_metadata_recovery_scheduler import select_due_metadata_recovery

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
