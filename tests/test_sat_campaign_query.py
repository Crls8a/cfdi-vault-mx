from __future__ import annotations

from datetime import date, time, timezone
from pathlib import Path

import pytest

from cfdi_vault.domain import DownloadDirection, RequestType
from cfdi_vault.sat_campaign_manifest import (
    CampaignManifestError,
    CampaignWorkState,
    bind_campaign_recovery,
    build_campaign_manifest,
    record_campaign_result,
    reserve_campaign_work,
)
from cfdi_vault.sat_campaign_query import CampaignQueryError, build_outstanding_metadata_queries
from cfdi_vault.setup_core import CredentialMode, LocalProfile, LocalProfileStatus

PROFILE_ID = "profile-synthetic"
RFC = "AAA010101AAA"


def _profile(profile_id: str = PROFILE_ID) -> LocalProfile:
    root = Path("synthetic-private-storage")
    return LocalProfile(
        profile_id=profile_id,
        rfc=RFC,
        storage_root=root,
        credential_mode=CredentialMode.REFERENCED,
        certificate_path=root / "synthetic.cer",
        private_key_path=root / "synthetic.key",
        phrase_ref="test-provider://synthetic",
        status=LocalProfileStatus.READY,
        certificate_fingerprint="0" * 64,
    )


def _reserved():  # type: ignore[no-untyped-def]
    return reserve_campaign_work(build_campaign_manifest(PROFILE_ID))


def test_builds_received_and_issued_queries_in_canonical_work_order() -> None:
    manifest = _reserved()
    outstanding = tuple(
        item for item in manifest.items if item.state is CampaignWorkState.OUTSTANDING
    )

    queries = build_outstanding_metadata_queries(manifest, _profile())

    assert tuple(queries) == tuple(item.work_ref for item in outstanding)
    assert tuple(query.direction for query in queries.values()) == (
        DownloadDirection.RECEIVED,
        DownloadDirection.ISSUED,
    )
    assert all(query.tenant_id == PROFILE_ID for query in queries.values())
    assert all(query.requester_rfc == RFC for query in queries.values())
    assert all(query.request_type is RequestType.METADATA for query in queries.values())
    assert queries == build_outstanding_metadata_queries(manifest, _profile())


def test_uses_inclusive_utc_day_bounds_for_each_work_item() -> None:
    manifest = _reserved()

    for item in (item for item in manifest.items if item.state is CampaignWorkState.OUTSTANDING):
        period = build_outstanding_metadata_queries(manifest, _profile())[item.work_ref].period
        assert period is not None
        assert period.start.date() == item.start == date(2026, 1, 1)
        assert period.end.date() == item.end == date(2026, 1, 14)
        assert period.start.timetz() == time(0, 0, tzinfo=timezone.utc)
        assert period.end.timetz() == time(23, 59, 59, 999999, tzinfo=timezone.utc)


def test_returns_only_outstanding_work_and_never_reserves_planned_work() -> None:
    planned = build_campaign_manifest(PROFILE_ID)
    assert build_outstanding_metadata_queries(planned, _profile()) == {}
    reserved = reserve_campaign_work(planned)
    first = next(item for item in reserved.items if item.state is CampaignWorkState.OUTSTANDING)
    bound = bind_campaign_recovery(reserved, first.work_ref, recovery_ref="run-000000000000")
    completed = record_campaign_result(
        bound,
        first.work_ref,
        CampaignWorkState.COMPLETED,
        recovery_ref="run-000000000000",
    )

    queries = build_outstanding_metadata_queries(completed, _profile())

    assert first.work_ref not in queries
    assert tuple(queries) == tuple(
        item.work_ref for item in completed.items if item.state is CampaignWorkState.OUTSTANDING
    )


def test_rejects_profile_manifest_mismatch_without_private_output() -> None:
    with pytest.raises(CampaignQueryError, match="profile-manifest-mismatch") as captured:
        build_outstanding_metadata_queries(_reserved(), _profile("profile-other"))

    assert PROFILE_ID not in str(captured.value)
    assert RFC not in str(captured.value)


def test_all_optional_filters_are_absent() -> None:
    query = next(iter(build_outstanding_metadata_queries(_reserved(), _profile()).values()))

    assert query.issuer_rfc is None
    assert query.receiver_rfcs == ()
    assert query.uuid is None
    assert query.document_status is None
    assert query.document_type is None
    assert query.complement is None
    assert query.rfc_on_behalf is None
    assert query.recovery_variant_reason is None
    assert query.validate() == ()


def test_rejects_noncanonical_profile_or_unsupported_mutated_work() -> None:
    profile = _profile()
    object.__setattr__(profile, "rfc", RFC.lower())
    with pytest.raises(CampaignQueryError, match="profile-rfc-invalid"):
        build_outstanding_metadata_queries(_reserved(), profile)

    manifest = _reserved()
    object.__setattr__(manifest.items[0], "direction", DownloadDirection.FOLIO)
    with pytest.raises(CampaignManifestError):
        build_outstanding_metadata_queries(manifest, _profile())
