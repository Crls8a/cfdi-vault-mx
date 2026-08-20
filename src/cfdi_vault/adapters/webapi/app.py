"""FastAPI app factory for the local control-panel API (ADR 0004).

A thin HTTP adapter over the same functions already used by the CLI
(``setup_status``, ``sat_campaign_db_cli``) — no SAT business logic,
credential handling, or campaign state machine is reimplemented here. No
``sat campaign create``/``authorize`` endpoint is exposed: authorizing a new
grant remains a deliberate CLI-only action (ADR 0004).

``POST .../run`` queues a durable ``sat_campaign_runs`` row and returns 202; the
live SAT sequence is executed by the separate host-only campaign-run consumer
(``cfdi_vault.sat_campaign_run_service``, ADR 0005).  This process must not set
``CFDI_VAULT_LIVE_WORKER_ENABLED``: leaving it unset keeps the old synchronous
path failing closed if anything ever reaches it.
"""

from __future__ import annotations

import os
import subprocess
from dataclasses import asdict
from pathlib import Path

import typer
from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.exc import SQLAlchemyError

from cfdi_vault.adapters.cli.analysis import _AnalysisCliError
from cfdi_vault.adapters.cli.analysis import _build_report as _analysis_build_report
from cfdi_vault.adapters.cli.analysis import _database_url as _analysis_database_url
from cfdi_vault.adapters.cli.analysis import _load_exact_profile as _analysis_load_exact_profile
from cfdi_vault.adapters.cli.analysis import _parse_date as _analysis_parse_date
from cfdi_vault.adapters.cli.common import _service as _recovery_service
from cfdi_vault.adapters.cli.common import _setup_provider
from cfdi_vault.adapters.cli.secrets import _credential_reference
from cfdi_vault.adapters.cli.storage import _default_service as _storage_service
from cfdi_vault.adapters.webapi.config import WebApiSettings
from cfdi_vault.adapters.webapi.security import OriginGuardMiddleware
from cfdi_vault.local_preflight import default_local_probes, run_local_preflight
from cfdi_vault.os_secret_providers import native_provider_for_reference
from cfdi_vault.runtime_settings import RuntimeSettingsError
from cfdi_vault.sat_campaign_db_cli import (
    CampaignDatabaseError,
    campaign_status,
    enqueue_campaign_run,
    publish_campaign_run_hint,
)
from cfdi_vault.secrets import CredentialProviderError
from cfdi_vault.setup_core import SetupError, find_repo_root, load_profile
from cfdi_vault.setup_status import format_profile_status, inspect_profile
from cfdi_vault.storage_observability import InvalidStorageReferenceError, StorageObservationError

ALLOWED_DOCKER_SERVICES = ("postgres", "rabbitmq", "redis", "worker")


class CampaignRunRequest(BaseModel):
    """Request body for triggering an already-authorized campaign run."""

    grant: str


def create_app(settings: WebApiSettings | None = None) -> FastAPI:
    """Build the local control-panel FastAPI app, resolving settings if not given."""

    resolved = settings if settings is not None else WebApiSettings.resolve()
    app = FastAPI(title="cfdi-vault-mx control panel", docs_url=None, redoc_url=None)
    app.state.settings = resolved
    app.add_middleware(OriginGuardMiddleware, allowed_origin=resolved.webapi_allowed_origin)

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/api/profile/{profile_id}/status")
    def profile_status(profile_id: str) -> dict[str, str]:
        inspection = inspect_profile(profile_id)
        return {"profile_id": profile_id, "status": format_profile_status(inspection)}

    @app.get("/api/campaign/{profile_id}/{campaign_ref}/status")
    def campaign_status_endpoint(profile_id: str, campaign_ref: str) -> dict[str, object]:
        try:
            return campaign_status(profile_id, campaign_ref)
        except CampaignDatabaseError as error:
            raise HTTPException(status_code=400, detail={"reason": error.reason}) from None

    @app.post("/api/campaign/{profile_id}/{campaign_ref}/run", status_code=202)
    def campaign_run_endpoint(
        profile_id: str, campaign_ref: str, body: CampaignRunRequest
    ) -> dict[str, object]:
        """Queue an already-authorized run; the SAT sequence happens elsewhere.

        The panel process must never execute the live sequence itself: it has no
        access to the OS credential store and an HTTP request is the wrong place
        to hold a multi-minute SAT conversation (ADR 0005).  The row is
        committed first and the broker hint published after, so a broker outage
        delays the run instead of losing an accepted request.
        """

        try:
            queued = enqueue_campaign_run(profile_id, campaign_ref, body.grant)
        except CampaignDatabaseError as error:
            raise HTTPException(status_code=400, detail={"reason": error.reason}) from None
        publish_campaign_run_hint(profile_id, campaign_ref, body.grant, str(queued["run_ref"]))
        return queued

    @app.get("/api/docker/services")
    def docker_services() -> list[dict[str, str]]:
        return [_docker_service_status(name) for name in ALLOWED_DOCKER_SERVICES]

    @app.get("/api/system/doctor")
    def system_doctor(profile_id: str = "default") -> dict[str, object]:
        try:
            service = _recovery_service(resolved.runtime.database_url, resolved.runtime.storage_root)
        except (RuntimeError, SQLAlchemyError):
            raise HTTPException(status_code=400, detail={"reason": "doctor-database-unavailable"}) from None
        try:
            checks = service.doctor()
        finally:
            service.close()
        return {
            "checks": [_doctor_check_dict(check) for check in checks],
            "profile_status": format_profile_status(inspect_profile(profile_id)),
        }

    @app.get("/api/system/preflight")
    def system_preflight(profile_id: str = "default") -> dict[str, object]:
        # Reuse the ``RuntimeSettings`` already resolved (and validated) for this
        # app instance instead of re-resolving from process environment, so the
        # panel's own config source of truth is the single one consulted here.
        settings = resolved.runtime
        repository_root = find_repo_root(Path.cwd()) or Path.cwd()
        try:
            profile = load_profile(profile_id)
            provider = _setup_provider(profile_id)
            report = run_local_preflight(
                settings,
                profile,
                provider,
                probes=default_local_probes(settings),
                repository_root=repository_root,
            )
        except (RuntimeSettingsError, SetupError, CredentialProviderError, typer.BadParameter):
            raise HTTPException(
                status_code=400, detail={"reason": "preflight-local-configuration-invalid"},
            ) from None
        return report.sanitized()

    @app.get("/api/analysis/report")
    def analysis_report(
        profile: str = Query(...),
        tenant_id: str = Query(...),
        from_date: str = Query(..., alias="from"),
        to_date: str = Query(..., alias="to"),
    ) -> dict[str, object]:
        try:
            url = _analysis_database_url(None)
            loaded = _analysis_load_exact_profile(profile)
            if tenant_id != loaded.profile_id:
                raise _AnalysisCliError("analysis-tenant-profile-mismatch")
            start = _analysis_parse_date(from_date)
            end = _analysis_parse_date(to_date)
            if start > end:
                raise _AnalysisCliError("analysis-period-invalid")
            payload = _analysis_build_report(database_url=url, tenant_id=tenant_id, start=start, end=end)
        except _AnalysisCliError as error:
            raise HTTPException(status_code=400, detail={"reason": error.reason}) from None
        except SetupError:
            raise HTTPException(status_code=400, detail={"reason": "analysis-profile-invalid"}) from None
        except Exception:
            raise HTTPException(
                status_code=400, detail={"reason": "analysis-database-operation-failed"},
            ) from None
        output = dict(payload)
        output["provenance"] = "postgres-v5-read"
        return output

    @app.get("/api/storage/status")
    def storage_status(reference: str) -> dict[str, object]:
        try:
            observation = _storage_service(None).status(reference)
        except InvalidStorageReferenceError:
            raise HTTPException(status_code=400, detail={"reason": "invalid_storage_reference"}) from None
        except StorageObservationError:
            raise HTTPException(status_code=400, detail={"reason": "storage_observation_failed"}) from None
        return asdict(observation)

    @app.get("/api/storage/locate")
    def storage_locate(reference: str) -> dict[str, object]:
        try:
            observation = _storage_service(None).locate(reference)
        except InvalidStorageReferenceError:
            raise HTTPException(status_code=400, detail={"reason": "invalid_storage_reference"}) from None
        except StorageObservationError:
            raise HTTPException(status_code=400, detail={"reason": "storage_observation_failed"}) from None
        return asdict(observation)

    @app.get("/api/secret/verify")
    def secret_verify(reference: str, kind: str = "generic", purpose: str = "webapi-verify") -> dict[str, object]:
        try:
            credential_reference = _credential_reference(reference, kind)
            provider = native_provider_for_reference(
                credential_reference,
                platform="win32" if os.environ.get("LOCALAPPDATA") else None,
                allow_synthetic=True,
            )
            exists = provider.exists(credential_reference, purpose=purpose)
        except typer.BadParameter:
            raise HTTPException(status_code=400, detail={"reason": "secret-kind-invalid"}) from None
        except CredentialProviderError:
            raise HTTPException(status_code=400, detail={"reason": "secret-verification-failed"}) from None
        return {"reference": credential_reference.uri, "kind": credential_reference.kind.value, "exists": exists}

    @app.post("/api/docker/{service}/start")
    def docker_start(service: str) -> dict[str, str]:
        _require_allowed_service(service)
        _run_compose("start", service)
        return {"service": service, "action": "start"}

    @app.post("/api/docker/{service}/stop")
    def docker_stop(service: str) -> dict[str, str]:
        _require_allowed_service(service)
        _run_compose("stop", service)
        return {"service": service, "action": "stop"}

    return app


def _doctor_check_dict(check: object) -> dict[str, object]:
    """Render one ``DoctorCheck`` as JSON without ever echoing raw exception text.

    ``RecoveryService.doctor()`` is a CLI-terminal helper: its failure details
    are ``str(exc)`` from whatever driver raised (SQLAlchemy, pika, redis,
    filesystem `OSError`), and its storage success detail is the joined
    absolute paths ``LocalStorage.ensure_layout`` just created. Both can carry
    a raw filesystem path or a connection URL with embedded credentials, which
    ADR 0004 forbids in any endpoint response — a local terminal may print
    them, an HTTP response may not. So only the two already-safe success
    details (database schema check, queue/cache adapter reachability) pass
    through verbatim; every failure, and the storage success detail, is
    replaced with a bounded, non-identifying label instead of the exception
    text or path list.
    """

    name = check.name
    if not check.ok:
        return {"name": name, "ok": False, "detail": f"{name} check failed"}
    if name == "storage":
        return {"name": name, "ok": True, "detail": "layout ensured"}
    return {"name": name, "ok": True, "detail": check.detail}


def _require_allowed_service(service: str) -> None:
    if service not in ALLOWED_DOCKER_SERVICES:
        raise HTTPException(status_code=404, detail={"reason": "docker-service-not-allowed"})


def _docker_service_status(service: str) -> dict[str, str]:
    result = subprocess.run(
        ["docker", "compose", "ps", service, "--format", "{{.State}}"],
        capture_output=True,
        text=True,
        check=False,
    )
    state = result.stdout.strip() or "unknown"
    return {"service": service, "state": state}


def _run_compose(action: str, service: str) -> None:
    subprocess.run(["docker", "compose", action, service], capture_output=True, text=True, check=False)


def run(settings: WebApiSettings | None = None) -> None:
    """Start the control-panel server bound to loopback only (ADR 0004)."""

    import uvicorn

    resolved = settings if settings is not None else WebApiSettings.resolve()
    app = create_app(resolved)
    uvicorn.run(app, host=resolved.webapi_host, port=resolved.webapi_port)
