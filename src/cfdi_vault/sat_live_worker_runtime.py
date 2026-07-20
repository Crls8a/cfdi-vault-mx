"""Explicit SAT v1.5 runtime wiring for the PostgreSQL campaign worker.

The module is deliberately opt-in.  Unit tests inject fake ports; this
factory is only used after a current-commit campaign grant has been validated
and an operator enables the live worker environment gate.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import datetime, time, timezone
from typing import Mapping

from cfdi_vault.domain import DateTimePeriod, DownloadDirection, DownloadQuery, RequestType
from cfdi_vault.os_secret_providers import OsSecretProviderError, native_provider_for_reference
from cfdi_vault.sat_campaign_repository import SatCampaignRepository
from cfdi_vault.sat_transport import GuardedSoapHttpTransport, LiveSatGuardInput
from cfdi_vault.sat_v15_adapter import SatV15Adapter
from cfdi_vault.secrets import CredentialKind, CredentialReference
from cfdi_vault.setup_core import LocalProfile, LocalProfileStatus, load_profile
from cfdi_vault.setup_status import inspect_profile


class SatLiveWorkerRuntimeError(RuntimeError):
    """Safe reason for refusing to build a live worker adapter."""

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


@dataclass(frozen=True)
class SatWorkerFactories:
    """Ports consumed by ``SatCampaignRunner`` for one campaign grant."""

    submitter_factory: object
    verifier_factory: object
    downloader_factory: object
    query_factory: object
    artifact_coordinator: object | None = None
    request_type: RequestType = RequestType.METADATA
    package_kind: str = "metadata_zip"


def build_metadata_worker_factories(
    profile_id: str,
    repository: SatCampaignRepository,
    *,
    campaign_ref: str,
    grant_ref: str,
    environ: Mapping[str, str] | None = None,
) -> SatWorkerFactories:
    """Build the Metadata lane; a CFDI grant is rejected fail-closed."""

    return _build_worker_factories(
        profile_id,
        repository,
        campaign_ref=campaign_ref,
        grant_ref=grant_ref,
        environ=environ,
        expected_phase="metadata-proof",
        request_type=RequestType.METADATA,
        package_kind="metadata_zip",
    )


def build_cfdi_worker_factories(
    profile_id: str,
    repository: SatCampaignRepository,
    *,
    campaign_ref: str,
    grant_ref: str,
    environ: Mapping[str, str] | None = None,
) -> SatWorkerFactories:
    """Build the CFDI lane; only an exact ``cfdi-proof`` grant may use it."""

    return _build_worker_factories(
        profile_id,
        repository,
        campaign_ref=campaign_ref,
        grant_ref=grant_ref,
        environ=environ,
        expected_phase="cfdi-proof",
        request_type=RequestType.CFDI,
        package_kind="cfdi_zip",
    )


def _build_worker_factories(
    profile_id: str,
    repository: SatCampaignRepository,
    *,
    campaign_ref: str,
    grant_ref: str,
    environ: Mapping[str, str] | None,
    expected_phase: str,
    request_type: RequestType,
    package_kind: str,
) -> SatWorkerFactories:
    """Build the guarded SAT v1.5 ports without contacting SAT.

    The returned adapter sends traffic only when one of its methods is called.
    ``SatCampaignRunner`` calls those methods only after a PostgreSQL claim.
    """

    # ``{}`` is an intentional injection in tests and in isolated workers;
    # do not silently replace it with the host process environment.
    env = environ if environ is not None else os.environ
    if env.get("CFDI_VAULT_LIVE_WORKER_ENABLED") != "1":
        raise SatLiveWorkerRuntimeError("live-worker-disabled")
    if env.get("CI"):
        raise SatLiveWorkerRuntimeError("ci-enabled")
    if any(env.get(name) for name in (
        "CFDI_VAULT_SAT_AUTH_ENDPOINT",
        "CFDI_VAULT_SAT_REQUEST_ENDPOINT",
        "CFDI_VAULT_SAT_VERIFY_ENDPOINT",
        "CFDI_VAULT_SAT_DOWNLOAD_ENDPOINT",
    )):
        raise SatLiveWorkerRuntimeError("sat-endpoint-override-disallowed")
    commit_ref = env.get("CFDI_VAULT_COMMIT_REF", "").strip()
    if not commit_ref:
        raise SatLiveWorkerRuntimeError("campaign-commit-ref-required")
    scanner_passed = env.get("CFDI_VAULT_SCANNER_PASSED") == "1"
    repo_clean = env.get("CFDI_VAULT_REPO_CLEAN") == "1"
    if not scanner_passed:
        raise SatLiveWorkerRuntimeError("preflight-scanner-required")
    if not repo_clean:
        raise SatLiveWorkerRuntimeError("preflight-clean-tree-required")
    try:
        campaign = repository.get_campaign_status(campaign_ref, profile_ref=profile_id)
        if campaign is None:
            raise ValueError
        grant = repository.validate_grant(
            campaign_ref=campaign_ref,
            grant_ref=grant_ref,
            profile_ref=profile_id,
            commit_ref=commit_ref,
            # The campaign aggregate can remain in metadata-proof while an
            # evidence-gated cfdi-proof grant is active.  Read the lane from
            # the exact durable grant instead of inferring it from that
            # aggregate projection.
            phase=None,
        )
        if grant.phase != expected_phase and not (
            grant.phase == "continue" and campaign.get("phase") == expected_phase
        ):
            raise ValueError("campaign grant phase does not match worker lane")
        profile = load_profile(profile_id, env=env)
    except Exception as exc:
        raise SatLiveWorkerRuntimeError("campaign-runtime-not-authorized") from exc
    if profile.status is not LocalProfileStatus.READY:
        raise SatLiveWorkerRuntimeError("profile-not-ready")
    # Resolve and verify the native provider before constructing any
    # SAT-facing factory.  A missing or inaccessible phrase must fail closed
    # at the local readiness boundary, not after a claim reaches the runner.
    provider = _provider(profile, environ=env)
    inspection = inspect_profile(profile_id, provider=provider, env=env)
    if inspection.status is not LocalProfileStatus.READY:
        raise SatLiveWorkerRuntimeError("profile-doctor-not-ready")
    transport = GuardedSoapHttpTransport(
        guard_input_factory=lambda: LiveSatGuardInput(
            profile_ready=True,
            credentials_ready=True,
            doctor_ok=True,
            scanner_passed=scanner_passed,
            repo_clean=repo_clean,
            metadata_only=request_type is RequestType.METADATA,
            request_type=request_type.value,
            range_within_limit=True,
            campaign_grant_verified=True,
            campaign_grant_allows_real_credentials=True,
            environ=env,
        )
    )
    adapter = SatV15Adapter(
        profile=profile,
        provider=provider,
        transport=transport,
        max_range_days=14,
        request_type=request_type,
        _credential_purpose=f"sat-{expected_phase}",
    )
    artifact_coordinator = _build_artifact_coordinator(repository, env)

    def query_factory(window: object) -> DownloadQuery:
        direction = DownloadDirection(str(getattr(window, "direction")))
        start = datetime.combine(getattr(window, "start_date"), time.min, tzinfo=timezone.utc)
        end = datetime.combine(getattr(window, "end_date"), time.max, tzinfo=timezone.utc)
        return DownloadQuery(
            tenant_id=profile_id,
            requester_rfc=profile.rfc,
            direction=direction,
            request_type=request_type,
            period=DateTimePeriod(start, end),
            document_status=(
                "Vigente"
                if request_type is RequestType.CFDI and direction is DownloadDirection.RECEIVED
                else None
            ),
        )

    return SatWorkerFactories(
        submitter_factory=lambda _query: adapter,
        verifier_factory=lambda _request_id: adapter,
        downloader_factory=lambda _package_id: adapter,
        query_factory=query_factory,
        artifact_coordinator=artifact_coordinator,
        request_type=request_type,
        package_kind=package_kind,
    )


def _build_artifact_coordinator(
    repository: SatCampaignRepository,
    environ: Mapping[str, str],
) -> object | None:
    """Build external package storage wiring without opening network clients.

    The worker can be constructed before a SAT response exists, so absent
    storage or queue configuration is represented by ``None`` rather than an
    eager failure.  The runner fails closed if SAT later reports a package.
    ``RabbitMqQueue`` opens a connection only from ``publish``/consume calls.
    """

    storage_root = environ.get("CFDI_STORAGE_ROOT", "").strip()
    rabbitmq_url = environ.get("RABBITMQ_URL", "").strip()
    if not storage_root or not rabbitmq_url:
        return None
    try:
        from cfdi_vault.sat_campaign_artifacts import SatCampaignArtifactCoordinator

        session_factory = getattr(repository, "_session_factory", None)
        engine = getattr(session_factory, "kw", {}).get("bind") if session_factory is not None else None
        if engine is not None:
            from cfdi_vault.sat_campaign_ledger_handoff import build_durable_handoff

            return SatCampaignArtifactCoordinator(
                repository,
                storage_root,
                durable_handoff=build_durable_handoff(engine, rabbitmq_url),
            )

        # Explicitly retain the legacy publisher only for offline/fake
        # repositories that have no durable SQLAlchemy bind.
        from cfdi_vault.queueing import RabbitMqQueue

        publisher = RabbitMqQueue(rabbitmq_url).publish
        return SatCampaignArtifactCoordinator(
            repository,
            storage_root,
            job_publisher=publisher,
        )
    except Exception as exc:
        raise SatLiveWorkerRuntimeError("campaign-artifact-runtime-unavailable") from exc


def _provider(profile: LocalProfile, *, environ: Mapping[str, str] | None = None) -> object:
    """Resolve the native secret provider using the injected environment.

    The platform hint is derived from ``environ`` rather than the global
    process environment so worker construction remains deterministic and
    cannot accidentally inherit host-only state from the monitor process.
    """

    reference = CredentialReference(profile.phrase_ref, CredentialKind.PHRASE)
    env = environ if environ is not None else os.environ
    try:
        return native_provider_for_reference(
            reference,
            platform="win32" if env.get("LOCALAPPDATA") else None,
        )
    except OsSecretProviderError:
        raise SatLiveWorkerRuntimeError("credential-provider-unsupported") from None
