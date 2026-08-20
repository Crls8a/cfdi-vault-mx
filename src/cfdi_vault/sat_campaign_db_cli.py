"""Database-backed campaign application service used by the CLI adapter."""

from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timedelta, timezone
from typing import Mapping

from sqlalchemy import select

from cfdi_vault.db import create_engine_from_url, create_session_factory, ensure_tables_exist
from cfdi_vault.recovery_db import SatCampaignRecord, Tenant
from cfdi_vault.runtime_settings import campaign_run_lease_seconds
from cfdi_vault.sat_campaign_manifest import build_campaign_manifest
from cfdi_vault.sat_campaign_repository import SatCampaignRepository
from cfdi_vault.sat_campaign_repository_constants import VERIFY_RESULTS


class CampaignDatabaseError(RuntimeError):
    """Expose a fixed reason for database-backed CLI failures."""

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


def _repository(environ: Mapping[str, str] | None = None) -> tuple[SatCampaignRepository, object]:
    environment = environ if environ is not None else os.environ
    try:
        url = environment.get("DATABASE_URL")
        if not isinstance(url, str) or not url.strip():
            raise CampaignDatabaseError("campaign-database-required")
        engine = create_engine_from_url(url)
        ensure_tables_exist(engine, ("sat_campaigns", "sat_campaign_windows", "sat_grants", "sat_requests"))
    except CampaignDatabaseError:
        raise
    except Exception as exc:
        raise CampaignDatabaseError("campaign-database-unavailable") from exc
    return SatCampaignRepository(create_session_factory(engine)), engine


def create_campaign(
    profile_id: str, *, tenant_rfc: str = "SYNTHETIC", environ: Mapping[str, str] | None = None,
) -> dict[str, object]:
    """Create the fixed 28-window campaign in PostgreSQL idempotently."""

    manifest = build_campaign_manifest(profile_id)
    repository, engine = _repository(environ)
    try:
        factory = create_session_factory(engine)
        with factory() as session:
            if session.get(Tenant, profile_id) is None:
                session.add(Tenant(
                    id=profile_id, name="Local profile", rfc=tenant_rfc,
                    created_at=datetime.now(timezone.utc),
                ))
                session.commit()
        now = datetime.now(timezone.utc)
        digest = _manifest_digest(manifest)
        record = repository.create_campaign(
            campaign_ref=manifest.campaign_ref, tenant_id=profile_id, profile_ref=profile_id,
            manifest_sha256=digest, commit_ref=_commit_ref(environ),
            phase="metadata-proof", status="planned", budget=28, now=now,
        )
        for item in manifest.items:
            repository.reserve_window(
                campaign_ref=record.campaign_ref, work_ref=item.work_ref, direction=item.direction.value,
                start_date=item.start, end_date=item.end, status="planned", now=now,
            )
        return _summary(
            repository.get_campaign_status(record.campaign_ref), manifest.campaign_ref,
            repository.get_last_campaign_run(record.campaign_ref),
        )
    finally:
        engine.dispose()


def authorize_campaign(
    profile_id: str, campaign_ref: str, phase: str, expires_days: int, reason: str,
    *, environ: Mapping[str, str] | None = None,
) -> dict[str, object]:
    """Persist one exact grant without credentials or SAT contact.

    CFDI authorization is evidence-gated: the campaign must already contain
    a validated, header-compatible metadata import with eligible records. A
    ``continue`` grant is subject to the same gate once the campaign is in its
    CFDI phase; continuation of the metadata lane remains independently
    authorizable.
    """

    if phase not in {"metadata-proof", "cfdi-proof", "continue"}:
        raise CampaignDatabaseError("campaign-grant-phase-invalid")
    if type(expires_days) is not int or not 1 <= expires_days <= 14:
        raise CampaignDatabaseError("campaign-grant-validity-invalid")
    if type(reason) is not str or not reason.strip() or len(reason) > 256:
        raise CampaignDatabaseError("campaign-grant-reason-invalid")
    repository, engine = _repository(environ)
    try:
        try:
            status = repository.get_campaign_status(campaign_ref, profile_ref=profile_id)
        except ValueError as exc:
            raise CampaignDatabaseError("campaign-profile-mismatch") from exc
        if status is None:
            raise CampaignDatabaseError("campaign-not-found")
        commit_ref = _commit_ref(environ)
        with repository._session_factory() as session:
            campaign = session.scalar(select(SatCampaignRecord).where(
                SatCampaignRecord.campaign_ref == campaign_ref,
            ))
            if campaign is None or campaign.commit_ref != commit_ref or campaign.profile_ref != profile_id:
                raise CampaignDatabaseError("campaign-profile-or-commit-mismatch")
            advances_to_cfdi = phase == "cfdi-proof" or (
                phase == "continue" and campaign.phase == "cfdi-proof"
            )
        if advances_to_cfdi and not repository.has_eligible_metadata_import(campaign_ref):
            raise CampaignDatabaseError("campaign-metadata-evidence-required")
        stamp = datetime.now(timezone.utc)
        grant_ref = "grant-" + hashlib.sha256(
            f"{campaign_ref}\x1f{phase}\x1f{reason}".encode("utf-8")
        ).hexdigest()[:24]
        expires_at = stamp + timedelta(days=expires_days)
        repository.create_grant(
            campaign_ref=campaign_ref, grant_ref=grant_ref, phase=phase, reason=reason,
            budget=2, expires_at=expires_at, now=stamp,
        )
        return {"grant_ref": grant_ref, "phase": phase, "expires_at": expires_at.isoformat(),
                "max_open_operations": 2}
    finally:
        engine.dispose()


def campaign_status(profile_id: str, campaign_ref: str, *, environ: Mapping[str, str] | None = None) -> dict[str, object]:
    """Return sanitized campaign counts from PostgreSQL only."""

    repository, engine = _repository(environ)
    try:
        try:
            status = repository.get_campaign_status(campaign_ref, profile_ref=profile_id)
        except ValueError as exc:
            raise CampaignDatabaseError("campaign-profile-mismatch") from exc
        if status is None:
            raise CampaignDatabaseError("campaign-not-found")
        return _summary(status, campaign_ref, repository.get_last_campaign_run(campaign_ref))
    finally:
        engine.dispose()


def run_without_adapter(profile_id: str, campaign_ref: str, grant_ref: str, *, environ: Mapping[str, str] | None = None) -> dict[str, object]:
    """Return due status without contacting SAT when no live adapter is supplied."""

    repository, engine = _repository(environ)
    try:
        try:
            status = repository.get_campaign_status(campaign_ref, profile_ref=profile_id)
            if status is None:
                raise CampaignDatabaseError("campaign-not-found")
            repository.validate_grant(
                campaign_ref=campaign_ref, grant_ref=grant_ref, profile_ref=profile_id,
                commit_ref=_commit_ref(environ), phase=None,
            )
        except ValueError as exc:
            raise CampaignDatabaseError("campaign-grant-invalid") from exc
        if status is None:
            raise CampaignDatabaseError("campaign-not-found")
        if status.get("next_check_at"):
            raise CampaignDatabaseError("campaign-adapter-required")
        return {"status": "no_due_operations", "contacted_count": 0, "next_check_at": None}
    finally:
        engine.dispose()


def resolve_run_lane(
    repository: SatCampaignRepository, profile_id: str, campaign_ref: str, grant_ref: str,
    *, commit_ref: str,
) -> str:
    """Validate the grant and resolve which lane a run would execute.

    This is the exact pre-check the synchronous runner has always performed
    before touching a SAT factory.  The asynchronous panel path calls it too, so
    a run that could never succeed is rejected while the operator is still
    looking at the request instead of failing later inside a background process.

    A ``ValueError`` from :meth:`SatCampaignRepository.validate_grant` is left to
    propagate so each caller keeps its own established error mapping.
    """

    grant = repository.validate_grant(
        campaign_ref=campaign_ref, grant_ref=grant_ref, profile_ref=profile_id,
        commit_ref=commit_ref, phase=None,
    )
    lane_phase = grant.phase
    if grant.phase == "continue":
        lane_phase = str(repository.get_campaign_status(
            campaign_ref, profile_ref=profile_id,
        ).get("phase", ""))
    if lane_phase not in {"metadata-proof", "cfdi-proof"}:
        raise CampaignDatabaseError("campaign-lane-required")
    return lane_phase


def enqueue_campaign_run(
    profile_id: str, campaign_ref: str, grant_ref: str, *, requested_via: str = "panel",
    environ: Mapping[str, str] | None = None,
) -> dict[str, object]:
    """Queue one campaign run durably instead of executing it in this process.

    The same synchronous pre-checks the runner performs happen here, so an
    unusable request still fails fast for the caller.  Only after those pass is
    a ``sat_campaign_runs`` row committed; the SAT sequence itself runs later in
    the host-only consumer that owns the credential store (ADR 0005).

    Returns the existing run when one is already active for this grant, so a
    repeated request never authorizes a second live SAT sequence.
    """

    environment = environ if environ is not None else os.environ
    commit_ref = _commit_ref(environment)
    lease_seconds = campaign_run_lease_seconds(environment)
    repository, engine = _repository(environment)
    try:
        try:
            status = repository.get_campaign_status(campaign_ref, profile_ref=profile_id)
        except ValueError as exc:
            raise CampaignDatabaseError("campaign-profile-mismatch") from exc
        if status is None:
            raise CampaignDatabaseError("campaign-not-found")
        try:
            resolve_run_lane(
                repository, profile_id, campaign_ref, grant_ref, commit_ref=commit_ref,
            )
            record = repository.enqueue_campaign_run(
                campaign_ref=campaign_ref, grant_ref=grant_ref, profile_ref=profile_id,
                commit_ref=commit_ref, requested_via=requested_via, lease_seconds=lease_seconds,
            )
        except ValueError as exc:
            raise CampaignDatabaseError("campaign-grant-invalid") from exc
        return {
            "status": "queued",
            "run_ref": record.run_ref,
            "campaign_ref": campaign_ref,
            "requested_at": record.requested_at.isoformat(),
        }
    finally:
        engine.dispose()


def publish_campaign_run_hint(
    profile_id: str, campaign_ref: str, grant_ref: str, run_ref: str,
    *, environ: Mapping[str, str] | None = None,
) -> bool:
    """Publish the non-durable wake hint for an already committed run row.

    This must only be called *after* the ``sat_campaign_runs`` row is committed,
    the same ordering the durable ledger outbox uses.  The message carries no
    work item and losing it is harmless: the consumer polls PostgreSQL, and the
    reaper closes a row nobody ever claimed.  A broker failure therefore returns
    ``False`` instead of raising and undoing an accepted request.
    """

    environment = environ if environ is not None else os.environ
    rabbitmq_url = str(environment.get("RABBITMQ_URL", "")).strip()
    if not rabbitmq_url:
        return False
    try:
        from cfdi_vault.domain import QueueMessage, QueueName
        from cfdi_vault.queueing import RabbitMqQueue

        repository, engine = _repository(environment)
        try:
            tenant_id = repository.tenant_id_for_campaign(campaign_ref)
        finally:
            engine.dispose()
        RabbitMqQueue(rabbitmq_url).publish(QueueMessage(
            queue=QueueName.SAT_CAMPAIGN_RUN,
            tenant_id=tenant_id,
            profile_id=profile_id,
            job_id=run_ref,
            correlation_id=run_ref,
            idempotency_key=f"campaign-run:{campaign_ref}:{grant_ref}",
        ))
        return True
    except Exception:
        # PostgreSQL is the source of truth. A missing hint only delays the run
        # until the consumer's next poll; it never loses or duplicates it.
        return False


def run_from_environment(
    profile_id: str, campaign_ref: str, grant_ref: str, *, environ: Mapping[str, str] | None = None,
) -> dict[str, object]:
    """Run the DB runner with explicit live factories, or fail closed offline."""

    environment = environ if environ is not None else os.environ
    if environment.get("CFDI_VAULT_LIVE_WORKER_ENABLED") != "1":
        return run_without_adapter(profile_id, campaign_ref, grant_ref, environ=environment)
    repository, engine = _repository(environment)
    try:
        from cfdi_vault.sat_live_worker_runtime import (
            build_cfdi_worker_factories,
            build_metadata_worker_factories,
        )

        if hasattr(repository, "validate_grant"):
            lane_phase = resolve_run_lane(
                repository, profile_id, campaign_ref, grant_ref, commit_ref=_commit_ref(environment),
            )
            if lane_phase == "metadata-proof":
                build_factories = build_metadata_worker_factories
            else:
                build_factories = build_cfdi_worker_factories
        else:
            # Tests and explicit adapter callers may provide a narrow fake
            # repository; the guarded factory still validates the real grant.
            build_factories = build_metadata_worker_factories
        factories = build_factories(
            profile_id,
            repository,
            campaign_ref=campaign_ref,
            grant_ref=grant_ref,
            environ=environment,
        )
        # Keep the repository that was validated by the guarded runtime.  In
        # particular, the artifact coordinator holds this repository for the
        # later package commit; opening a second engine here would make the
        # runner and coordinator use different durable handles.
        return _run_with_repository(
            repository,
            profile_id,
            campaign_ref,
            grant_ref,
            verifier_factory=factories.verifier_factory,
            downloader_factory=factories.downloader_factory,
            submitter_factory=factories.submitter_factory,
            query_factory=factories.query_factory,
            artifact_coordinator=factories.artifact_coordinator,
            package_kind=factories.package_kind,
            environ=environment,
        )
    except CampaignDatabaseError:
        raise
    except Exception as exc:
        raise CampaignDatabaseError("campaign-live-runtime-unavailable") from exc
    finally:
        engine.dispose()


def run_with_adapter(
    profile_id: str,
    campaign_ref: str,
    grant_ref: str,
    *,
    verifier_factory: object,
    downloader_factory: object | None = None,
    artifact_coordinator: object | None = None,
    submitter_factory: object | None = None,
    query_factory: object | None = None,
    package_kind: str = "metadata_zip",
    environ: Mapping[str, str] | None = None,
) -> dict[str, object]:
    """Run due PostgreSQL operations through an already-authorized adapter factory."""

    repository, engine = _repository(environ)
    try:
        return _run_with_repository(
            repository,
            profile_id,
            campaign_ref,
            grant_ref,
            verifier_factory=verifier_factory,
            downloader_factory=downloader_factory,
            artifact_coordinator=artifact_coordinator,
            submitter_factory=submitter_factory,
            query_factory=query_factory,
            package_kind=package_kind,
            environ=environ,
        )
    finally:
        engine.dispose()


def _run_with_repository(
    repository: SatCampaignRepository,
    profile_id: str,
    campaign_ref: str,
    grant_ref: str,
    *,
    verifier_factory: object,
    downloader_factory: object | None = None,
    artifact_coordinator: object | None = None,
    submitter_factory: object | None = None,
    query_factory: object | None = None,
    package_kind: str = "metadata_zip",
    environ: Mapping[str, str] | None = None,
) -> dict[str, object]:
    """Run one bounded operation set against one PostgreSQL repository.

    The guarded runtime and the artifact coordinator may retain the repository
    while a package is being persisted.  Keeping validation and runner
    construction on the same repository avoids opening a second engine and
    preserves one durable source of truth for the whole invocation.
    """

    from cfdi_vault.sat_db_campaign_runner import SatCampaignRunner

    try:
        status = repository.get_campaign_status(campaign_ref, profile_ref=profile_id)
        if status is None:
            raise CampaignDatabaseError("campaign-not-found")
        repository.validate_grant(
            campaign_ref=campaign_ref,
            grant_ref=grant_ref,
            profile_ref=profile_id,
            commit_ref=_commit_ref(environ),
            phase=None,
        )
        runner = SatCampaignRunner(
            repository,
            verifier_factory,  # type: ignore[arg-type]
            downloader_factory=downloader_factory,  # type: ignore[arg-type]
            artifact_coordinator=artifact_coordinator,
            submitter_factory=submitter_factory,  # type: ignore[arg-type]
            query_factory=query_factory,  # type: ignore[arg-type]
            package_kind=package_kind,
            grant_ref=grant_ref,
            campaign_ref=campaign_ref,
        )
        return runner.run().as_safe_dict()
    except ValueError as exc:
        raise CampaignDatabaseError("campaign-grant-invalid") from exc


def _commit_ref(environ: Mapping[str, str] | None) -> str:
    environment = environ if environ is not None else os.environ
    value = environment.get("CFDI_VAULT_COMMIT_REF", "").strip()
    if not value:
        raise CampaignDatabaseError("campaign-commit-ref-required")
    return value


def _manifest_digest(manifest: object) -> str:
    payload = {
        "campaign_ref": manifest.campaign_ref, "profile_id": manifest.profile_id,
        "schema_version": manifest.schema_version, "policy_version": manifest.policy_version,
        "start": manifest.start.isoformat(), "end": manifest.end.isoformat(),
        "window_days": manifest.window_days,
        "directions": [direction.value for direction in manifest.directions],
        "max_outstanding": manifest.max_outstanding, "max_split_depth": manifest.max_split_depth,
        "kind": manifest.kind.value,
        "items": [
            {"work_ref": item.work_ref, "direction": item.direction.value,
             "start": item.start.isoformat(), "end": item.end.isoformat(),
             "depth": item.depth, "parent_ref": item.parent_ref}
            for item in manifest.items
        ],
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _summary(
    status: dict[str, object] | None, campaign_ref: str,
    last_run: dict[str, object] | None = None,
) -> dict[str, object]:
    if status is None:
        raise CampaignDatabaseError("campaign-not-found")
    windows = status.get("windows", {})
    if not isinstance(windows, dict):
        raise CampaignDatabaseError("campaign-status-invalid")
    base = sum(int(value) for key, value in windows.items() if key in {"planned", "reserved", "metadata", "cfdi", "no_data", "complete", "failed", "manual_review"})
    packages = status.get("packages", {})
    package_count = sum(int(value) for value in packages.values()) if isinstance(packages, dict) else 0
    last_result = status.get("last_verify_result")
    if not isinstance(last_result, str) or last_result not in VERIFY_RESULTS:
        last_result = None
    service_window_state = status.get("service_window_state", "legacy")
    if not isinstance(service_window_state, str) or service_window_state not in {"legacy", "active", "exceeded"}:
        service_window_state = "legacy"
    return {
        "campaign_ref": campaign_ref, "base_count": status.get("base_count", base),
        "split_count": status.get("split_count", 0),
        "leaf_count": status.get("leaf_count", base), "total_count": status.get("total_count", base),
        "outstanding_count": windows.get("reserved", 0),
        "terminal_count": sum(int(windows.get(key, 0)) for key in ("no_data", "complete", "failed", "manual_review")),
        "planned_count": windows.get("planned", 0), "completed_count": windows.get("complete", 0),
        "no_data_count": windows.get("no_data", 0), "failed_count": windows.get("failed", 0),
        "threshold_blocked_count": windows.get("manual_review", 0), "verify_attempts": status.get("verify_attempts", 0),
        "next_check_at": status.get("next_check_at") or "", "package_count": package_count,
        "zip_valid_count": 0, "txt_count": 0, "verify_history_count": status.get("verify_attempts", 0),
        "last_verify_result": last_result,
        "service_window_state": service_window_state,
        # A run that fails before it ever reaches a VERIFY attempt leaves no
        # trace in any of the counters above.  This projection is the only place
        # the operator can see that the run was requested at all (ADR 0005).
        "last_run": last_run,
    }
