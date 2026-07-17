from __future__ import annotations

from dataclasses import fields, replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

import cfdi_vault.sat_metadata_recovery as lifecycle
from cfdi_vault.domain import DownloadDirection
from cfdi_vault.sat_campaign_manifest import (
    bind_campaign_recovery,
    build_campaign_manifest,
    reserve_campaign_work,
)
from cfdi_vault.sat_campaign_query import build_metadata_query_for_work
from cfdi_vault.sat_campaign_status import CampaignStatusError, project_campaign_status
from cfdi_vault.sat_metadata_artifact_state import (
    MetadataPackageArtifactState,
    MetadataTextArtifact,
)
from cfdi_vault.sat_metadata_package import MetadataTextInspection
from cfdi_vault.sat_metadata_recovery_state import (
    MetadataRecoveryStateRecord,
    campaign_metadata_recovery_ref,
    new_metadata_observation_provenance,
    new_metadata_recovery_state,
    package_ref,
)
from cfdi_vault.setup_core import CredentialMode, LocalProfile, LocalProfileStatus

NOW = datetime(2026, 7, 16, 12, tzinfo=timezone.utc)
PROFILE_ID = "campaign-status-test"


def _profile(tmp_path: Path) -> LocalProfile:
    return LocalProfile(
        PROFILE_ID, "AAA010101AAA", tmp_path, CredentialMode.REFERENCED,
        tmp_path / "synthetic.cer", tmp_path / "synthetic.key", "provider://synthetic",
        LocalProfileStatus.READY, "0" * 64,
    )


def _bound_record(manifest, profile, work_ref: str, created_at: datetime):  # type: ignore[no-untyped-def]
    query = build_metadata_query_for_work(manifest, profile, work_ref)
    criteria = query.criteria_hash()
    recovery_ref = campaign_metadata_recovery_ref(profile.profile_id, criteria)
    manifest = bind_campaign_recovery(manifest, work_ref, recovery_ref=recovery_ref)
    item = next(item for item in manifest.items if item.work_ref == work_ref)
    record = new_metadata_recovery_state(
        recovery=lifecycle.start_metadata_recovery(recovery_ref, created_at=created_at),
        id_solicitud="synthetic-request",
        profile_id=profile.profile_id,
        direction=item.direction.value,
        kind="metadata",
        fecha_inicial=item.start.isoformat(),
        fecha_final=item.end.isoformat(),
        criteria_hash=criteria,
        authorization_ref="grt-" + "1" * 24,
        observation_provenance=new_metadata_observation_provenance(
            tested_commit="a" * 40, observed_at=created_at, entry_point="sat-campaign",
        ),
    )
    return manifest, record


def test_empty_status_is_immutable_ref_free_and_preserves_manifest_counts(tmp_path: Path) -> None:
    result = project_campaign_status(build_campaign_manifest(PROFILE_ID), (), _profile(tmp_path))

    assert result.base_count == result.leaf_count == result.total_count == 28
    assert result.planned_count == 28
    assert (result.verify_attempts, result.next_check_at) == (0, "")
    assert (result.package_count, result.zip_valid_count, result.txt_count) == (0, 0, 0)
    assert not any("ref" in field.name for field in fields(result))
    with pytest.raises(AttributeError):
        result.txt_count = 1  # type: ignore[misc]


def test_status_aggregates_only_bound_lineage_and_uses_earliest_due(tmp_path: Path) -> None:
    profile = _profile(tmp_path)
    manifest = reserve_campaign_work(build_campaign_manifest(PROFILE_ID))
    work = [item.work_ref for item in manifest.items if item.recovery_ref is None and item.state.value == "outstanding"]
    manifest, first = _bound_record(manifest, profile, work[0], NOW + timedelta(hours=1))
    manifest, second = _bound_record(manifest, profile, work[1], NOW)
    first = replace(
        first,
        recovery=lifecycle.record_pending_verification(
            first.recovery, checked_at=first.recovery.next_check_at,
        ),
    )
    second = replace(
        second,
        recovery=lifecycle.record_pending_verification(
            second.recovery, checked_at=second.recovery.next_check_at,
        ),
    )
    other_profile = replace(profile, profile_id="unrelated-profile")
    other_manifest = reserve_campaign_work(build_campaign_manifest(other_profile.profile_id))
    other_work = next(item.work_ref for item in other_manifest.items if item.state.value == "outstanding")
    _, unrelated = _bound_record(other_manifest, other_profile, other_work, NOW)

    result = project_campaign_status(manifest, (first, unrelated, second), profile)

    assert result.verify_attempts == 2
    assert result.next_check_at == "2026-07-16T12:20:00Z"
    assert result.outstanding_count == 2


def test_status_sums_downloaded_package_and_txt_evidence(tmp_path: Path) -> None:
    profile = _profile(tmp_path)
    manifest = reserve_campaign_work(build_campaign_manifest(PROFILE_ID))
    work_ref = next(item.work_ref for item in manifest.items if item.state.value == "outstanding")
    manifest, record = _bound_record(manifest, profile, work_ref, NOW)
    raw_package = "synthetic-package"
    ready = lifecycle.record_finished_verification(
        record.recovery, checked_at=record.recovery.next_check_at,
        package_refs=(package_ref(raw_package),), record_count=1,
    )
    record = new_metadata_recovery_state(
        recovery=ready, id_solicitud=record.id_solicitud, profile_id=record.profile_id,
        direction=record.direction, kind=record.kind, fecha_inicial=record.fecha_inicial,
        fecha_final=record.fecha_final, criteria_hash=record.criteria_hash,
        authorization_ref=record.authorization_ref, package_ids=(raw_package,),
        observation_provenance=record.observation_provenance,
    )
    recovery = lifecycle.begin_package_download(ready, ready.packages[0].package_ref)
    recovery = lifecycle.record_package_download(
        recovery, recovery.packages[0].package_ref, zip_valid=True, txt_count=1,
    )
    digest, text_digest = "b" * 64, "c" * 64
    artifact = MetadataPackageArtifactState(
        recovery.packages[0].package_ref, digest,
        f"sat-metadata/{recovery.recovery_ref}/packages/1-{digest[:12]}.zip", True,
        (MetadataTextArtifact(
            text_digest, f"sat-metadata/{recovery.recovery_ref}/txt/1-{text_digest[:12]}.txt",
            True, MetadataTextInspection("utf-8-sig", "~", ("Uuid", "FechaEmision"), 2, True),
        ),),
    )
    record = replace(record, recovery=recovery, artifact_bindings=(artifact,))

    result = project_campaign_status(manifest, (record,), profile)

    assert (result.verify_attempts, result.package_count) == (1, 1)
    assert (result.zip_valid_count, result.txt_count, result.next_check_at) == (1, 1, "")


@pytest.mark.parametrize("mismatch", ("missing", "direction", "entry-point"))
def test_bound_recovery_errors_are_fixed_and_redacted(tmp_path: Path, mismatch: str) -> None:
    profile = _profile(tmp_path)
    manifest = reserve_campaign_work(build_campaign_manifest(PROFILE_ID))
    work_ref = next(item.work_ref for item in manifest.items if item.state.value == "outstanding")
    manifest, record = _bound_record(manifest, profile, work_ref, NOW)
    records: tuple[MetadataRecoveryStateRecord, ...] = ()
    if mismatch == "direction":
        other = DownloadDirection.ISSUED if record.direction == "received" else DownloadDirection.RECEIVED
        records = (replace(record, direction=other.value),)
    elif mismatch == "entry-point":
        records = (replace(
            record,
            observation_provenance=replace(record.observation_provenance, entry_point="metadata-recover-live"),
        ),)

    with pytest.raises(CampaignStatusError) as caught:
        project_campaign_status(manifest, records, profile)

    assert caught.value.reason == "campaign-status-recovery-invalid"
    assert "synthetic" not in repr(caught.value)
