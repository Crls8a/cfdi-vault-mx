"""FastAPI app factory for the local control-panel API (ADR 0004).

A thin HTTP adapter over the same functions already used by the CLI
(``setup_status``, ``sat_campaign_db_cli``, ``setup_service.run_setup``) — no
SAT business logic, credential handling, or campaign state machine is
reimplemented here.

``POST .../run`` queues a durable ``sat_campaign_runs`` row and returns 202; the
live SAT sequence is executed by the separate host-only campaign-run consumer
(``cfdi_vault.sat_campaign_run_service``, ADR 0005).  This process must not set
``CFDI_VAULT_LIVE_WORKER_ENABLED``: leaving it unset keeps the old synchronous
path failing closed if anything ever reaches it.

``create``/``authorize`` are exposed here per ADR 0006, which amends ADR 0004's
"CLI-only" rule: the CLI that provided the deliberation friction is being
retired, so the friction moves into the API itself as a typed-confirmation
gate.  Every such request must carry a ``confirm`` field whose value is exactly
the resource identifier being acted on.  That check is a server-side security
boundary, not frontend UX: it is the first statement in each handler and runs
before any profile load or database call, so a caller that bypasses the panel
entirely still cannot create or authorize anything unconfirmed.

Credential-bearing endpoints (``POST /api/setup``, ``POST /api/secret/register``)
implement the FIEL phrase contract ADR 0004 already specified: the secret
arrives only in a JSON request body, is consumed immediately, and is never
echoed in a response, an error message, or a log line.  Failures are mapped to
bounded reason slugs — never to raw exception text — because the underlying
``SetupError`` messages can carry filesystem paths.
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
from cfdi_vault.adapters.cli.common import _provider_for_reference, _resolve_storage_root, _setup_provider
from cfdi_vault.adapters.cli.common import _service as _recovery_service
from cfdi_vault.adapters.cli.secrets import _credential_reference
from cfdi_vault.adapters.cli.storage import _default_service as _storage_service
from cfdi_vault.adapters.webapi.config import WebApiSettings
from cfdi_vault.adapters.webapi.security import OriginGuardMiddleware
from cfdi_vault.config import ConfigValidationError, load_config
from cfdi_vault.local_preflight import default_local_probes, run_local_preflight
from cfdi_vault.os_secret_providers import native_provider_for_reference
from cfdi_vault.recovery_service import RecoveryService, write_minimal_pdf
from cfdi_vault.runtime_settings import RuntimeSettingsError
from cfdi_vault.sat_campaign_db_cli import (
    CampaignDatabaseError,
    authorize_campaign,
    campaign_status,
    create_campaign,
    enqueue_campaign_run,
    publish_campaign_run_hint,
)
from cfdi_vault.secrets import CredentialProviderError, CredentialReference
from cfdi_vault.service import VaultService
from cfdi_vault.setup_core import CredentialMode, SetupError, find_repo_root, load_profile, redact_rfc
from cfdi_vault.setup_service import run_setup
from cfdi_vault.setup_status import format_profile_status, inspect_profile
from cfdi_vault.storage_observability import InvalidStorageReferenceError, StorageObservationError

ALLOWED_DOCKER_SERVICES = ("postgres", "rabbitmq", "redis", "worker")
CONFIRMATION_MISMATCH_REASON = "confirmation-mismatch"

# ``SetupError`` messages are operator-facing CLI text and can embed a raw
# filesystem path (source folder, explicit .cer/.key path), which ADR 0004
# forbids in any API response.  So a failure is never echoed: its first
# recognized marker selects one bounded slug from this table instead.  None of
# these markers, and no ``SetupError`` raised anywhere on the ``run_setup``
# path, can carry the phrase value itself — the only phrase-related message is
# the fixed "private-key phrase must be provided..." string.
_SETUP_FAILURE_REASONS: tuple[tuple[str, str], ...] = (
    ("private-key phrase must be provided", "setup-phrase-required"),
    ("phrase reference could not be prepared", "setup-phrase-rollback-unsafe"),
    ("credential intake is not allowed in ci", "setup-ci-not-allowed"),
    ("direct credential environment variables", "setup-direct-credential-env-forbidden"),
    ("must be outside the repository", "setup-path-inside-repository"),
    ("source folder does not exist", "setup-source-folder-invalid"),
    ("does not exist or is not a file", "setup-credential-file-invalid"),
    ("candidate found in source folder", "setup-credential-candidate-missing"),
    ("ambiguous", "setup-credential-candidate-ambiguous"),
    ("extension", "setup-credential-extension-invalid"),
    ("must not be empty", "setup-credential-file-empty"),
    ("is not readable", "setup-credential-file-unreadable"),
    ("appears unencrypted", "setup-private-key-unencrypted"),
    ("rfc must be", "setup-rfc-invalid"),
    ("profile id must use", "setup-profile-id-invalid"),
    ("unsupported platform", "setup-platform-unsupported"),
    ("unsupported credential mode or status", "setup-profile-invalid"),
    ("profile is not configured", "setup-profile-invalid"),
    ("profile json is invalid", "setup-profile-invalid"),
)


class CampaignRunRequest(BaseModel):
    """Request body for triggering an already-authorized campaign run."""

    grant: str


class CampaignCreateRequest(BaseModel):
    """Typed-confirmation body for creating a campaign (ADR 0006).

    ``confirm`` must repeat the ``profile_id`` path parameter exactly, the same
    way the retired CLI made the operator type ``--profile <id>``.
    """

    confirm: str


class CampaignAuthorizeRequest(BaseModel):
    """Typed-confirmation body for authorizing a campaign grant (ADR 0006).

    ``confirm`` must repeat the ``campaign_ref`` path parameter exactly.
    ``phase``/``expires_days``/``reason`` are only shape-checked here; their
    value rules (allowed phases, 1-14 day validity, non-empty bounded reason)
    stay in ``sat_campaign_db_cli.authorize_campaign``, which owns them and
    reports them as ``campaign-grant-*`` reason codes.  Re-validating them here
    would duplicate the rule and answer with a different status and vocabulary.
    """

    confirm: str
    phase: str
    expires_days: int
    reason: str


class SetupRequest(BaseModel):
    """FIEL onboarding body — the panel equivalent of ``cfdi-vault setup``.

    ``source_folder``/``certificate_path``/``private_key_path`` are filesystem
    paths read by this process, never browser uploads (ADR 0004).  ``phrase``
    is body-only: it must never appear in a query string, and its field name is
    already covered by ``security.REDACTED_FIELD_NAMES``.
    """

    rfc: str
    source_folder: str
    phrase: str
    profile_id: str = "default"
    certificate_path: str | None = None
    private_key_path: str | None = None
    credential_mode: str = "copied"


class SecretRegisterRequest(BaseModel):
    """Credential-registration body; ``value`` is treated exactly like the phrase."""

    reference: str
    value: str
    kind: str = "generic"
    purpose: str = "webapi-register"


class SecretDeleteRequest(BaseModel):
    """Credential-deletion body.

    A ``CredentialReference.uri`` is a full scheme URI
    (``windows-credential-manager://cfdi-vault/setup/<profile>/private-key-phrase``),
    so it cannot ride in a path segment without escaping; the reference travels
    in the body instead of ``DELETE /api/secret/{reference}``.
    """

    reference: str
    kind: str = "generic"
    purpose: str = "webapi-delete"


class OperationsInitRequest(BaseModel):
    """Body for the ``cfdi-vault operations init`` panel equivalent."""

    tenant_id: str = "default"
    rfc: str
    name: str | None = None


class OperationsReconcileRequest(BaseModel):
    """Body for the ``cfdi-vault operations reconcile`` panel equivalent."""

    tenant_id: str | None = None


class OperationsPrintRequest(BaseModel):
    """Body for the ``cfdi-vault operations print`` panel equivalent.

    ``output_path`` is a plain filesystem path this process reads/writes on
    its own machine, exactly like the CLI's ``--output`` option — not a
    browser upload or download.
    """

    uuid: str
    format: str = "text"
    tenant_id: str | None = None
    output_path: str | None = None


class OperationsExportRequest(BaseModel):
    """Body for the ``cfdi-vault operations export`` panel equivalent."""

    output_path: str | None = None
    tenant_id: str | None = None


class OperationsImportXmlRequest(BaseModel):
    """Body for the ``cfdi-vault operations import-xml`` panel equivalent.

    ``xml_path`` is an existing file already on the panel's own machine.
    """

    xml_path: str


class OperationsImportZipRequest(BaseModel):
    """Body for the ``cfdi-vault operations import-zip`` panel equivalent."""

    zip_path: str


class OperationsExportCsvRequest(BaseModel):
    """Body for the ``cfdi-vault operations export-csv`` panel equivalent."""

    output_path: str


class ConfigValidateRequest(BaseModel):
    """Body for the ``cfdi-vault config validate`` panel equivalent."""

    config_path: str


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

    @app.post("/api/campaign/{profile_id}/create")
    def campaign_create_endpoint(profile_id: str, body: CampaignCreateRequest) -> dict[str, object]:
        """Create the fixed campaign, gated on a typed confirmation (ADR 0006).

        The gate is the first statement on purpose: nothing — not the profile
        load, not ``DATABASE_URL`` resolution, not a single query — may run for
        an unconfirmed request, and no earlier branch exists that could skip it.
        """

        _require_typed_confirmation(body.confirm, profile_id)
        try:
            loaded = load_profile(profile_id)
        except SetupError:
            raise HTTPException(status_code=400, detail={"reason": "campaign-profile-invalid"}) from None
        # Mirror ``sat_campaign.py::_load_exact_profile``: a profile whose
        # document disagrees with the requested id must not be acted on.
        if loaded.profile_id != profile_id:
            raise HTTPException(status_code=400, detail={"reason": "campaign-profile-mismatch"})
        try:
            return create_campaign(profile_id, tenant_rfc=loaded.rfc)
        except CampaignDatabaseError as error:
            raise HTTPException(status_code=400, detail={"reason": error.reason}) from None
        except Exception:
            raise HTTPException(
                status_code=400, detail={"reason": "campaign-database-operation-failed"},
            ) from None

    @app.post("/api/campaign/{profile_id}/{campaign_ref}/authorize")
    def campaign_authorize_endpoint(
        profile_id: str, campaign_ref: str, body: CampaignAuthorizeRequest
    ) -> dict[str, object]:
        """Create one grant, gated on a typed confirmation (ADR 0006).

        As in ``create``, the gate is the first statement and precedes every
        database call; the grant rules themselves stay in the same
        ``authorize_campaign`` the CLI called.
        """

        _require_typed_confirmation(body.confirm, campaign_ref)
        try:
            return authorize_campaign(
                profile_id, campaign_ref, body.phase, body.expires_days, body.reason,
            )
        except CampaignDatabaseError as error:
            raise HTTPException(status_code=400, detail={"reason": error.reason}) from None
        except Exception:
            raise HTTPException(
                status_code=400, detail={"reason": "campaign-database-authorize-failed"},
            ) from None

    @app.post("/api/setup")
    def setup_endpoint(body: SetupRequest) -> dict[str, object]:
        """Run the FIEL onboarding flow the Tkinter wizard and CLI already run.

        The phrase is read once out of the request body, handed straight to
        ``run_setup``, and never referenced again.  Every failure path answers
        with a bounded slug from ``_setup_failure_reason``; no branch here
        interpolates ``body.phrase``, ``str(exc)``, or ``exc.errors`` into a
        response, so the phrase cannot reach the client even on failure.
        """

        try:
            mode = CredentialMode(body.credential_mode.strip().lower())
        except ValueError:
            raise HTTPException(
                status_code=400, detail={"reason": "setup-credential-mode-invalid"},
            ) from None
        try:
            provider = _setup_provider(body.profile_id)
            result = run_setup(
                profile_id=body.profile_id,
                rfc=body.rfc,
                source_folder=Path(body.source_folder),
                certificate_path=Path(body.certificate_path) if body.certificate_path else None,
                private_key_path=Path(body.private_key_path) if body.private_key_path else None,
                phrase_value=body.phrase,
                provider=provider,
                mode=mode,
            )
        except (SetupError, CredentialProviderError, ValueError) as exc:
            raise HTTPException(status_code=400, detail={"reason": _setup_failure_reason(exc)}) from None
        except Exception:
            # Anything else on this path (``typer.BadParameter`` from
            # ``_setup_provider``, an OSError from the staged copy, a provider
            # adapter fault) carries a raw path or driver text that may not be
            # echoed, and must not surface as an unhandled 500.
            raise HTTPException(status_code=400, detail={"reason": "setup-failed"}) from None
        return {
            "profile_id": result.profile.profile_id,
            "rfc": redact_rfc(result.profile.rfc),
            "credential_mode": result.profile.credential_mode.value,
            "credentials_imported": True,
            "phrase_stored": True,
        }

    @app.post("/api/secret/register")
    def secret_register(body: SecretRegisterRequest) -> dict[str, str]:
        """Store one credential value through the native provider, echoing nothing."""

        reference, provider = _secret_reference_and_provider(body.reference, body.kind)
        try:
            provider.store(reference, body.value, purpose=body.purpose)
        except CredentialProviderError:
            raise HTTPException(
                status_code=400, detail={"reason": "secret-registration-failed"},
            ) from None
        return {"reference": reference.uri, "kind": reference.kind.value}

    @app.post("/api/secret/delete")
    def secret_delete(body: SecretDeleteRequest) -> dict[str, object]:
        """Delete one credential reference.

        No typed-confirmation gate: ADR 0006 gates the direction that *grants*
        access (create/authorize/register).  Removing a reference grants
        nothing — it fails closed — so it keeps the plain error mapping.
        """

        reference, provider = _secret_reference_and_provider(body.reference, body.kind)
        try:
            deleted = provider.delete(reference, purpose=body.purpose)
        except CredentialProviderError:
            raise HTTPException(status_code=400, detail={"reason": "secret-deletion-failed"}) from None
        return {"reference": reference.uri, "kind": reference.kind.value, "deleted": bool(deleted)}

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

    def _operations_recovery_service() -> RecoveryService:
        """Build the same ``RecoveryService`` the CLI's ``_service`` builds.

        Construction failures map exactly like ``system_doctor`` already maps
        them: a ``RuntimeError``/``SQLAlchemyError`` here is a local
        PostgreSQL misconfiguration, not something to echo raw.
        """

        try:
            return _recovery_service(resolved.runtime.database_url, resolved.runtime.storage_root)
        except (RuntimeError, SQLAlchemyError):
            raise HTTPException(status_code=400, detail={"reason": "operations-database-unavailable"}) from None

    def _operations_vault_service() -> VaultService:
        """Build the same ``VaultService`` the CLI's import/summary/export commands build."""

        try:
            return VaultService(resolved.runtime.database_url)
        except (RuntimeError, SQLAlchemyError):
            raise HTTPException(status_code=400, detail={"reason": "operations-database-unavailable"}) from None

    def _require_readable_file(path: Path, reason: str) -> None:
        """Mirror Typer's ``exists=True, dir_okay=False, readable=True`` argument validation."""

        if not path.is_file() or not os.access(path, os.R_OK):
            raise HTTPException(status_code=400, detail={"reason": reason})

    @app.post("/api/operations/init")
    def operations_init(body: OperationsInitRequest) -> dict[str, str]:
        service = _operations_recovery_service()
        try:
            service.init_tenant(body.tenant_id, body.rfc, body.name)
        finally:
            service.close()
        return {"tenant_id": body.tenant_id, "rfc": body.rfc.upper()}

    @app.post("/api/operations/reconcile")
    def operations_reconcile(body: OperationsReconcileRequest) -> dict[str, int]:
        service = _operations_recovery_service()
        try:
            updated_count = service.reconcile(tenant_id=body.tenant_id)
        finally:
            service.close()
        return {"updated_count": updated_count}

    @app.get("/api/operations/search")
    def operations_search(
        text: str = "", tenant_id: str | None = None, limit: int = Query(20, ge=1, le=200),
    ) -> list[dict[str, object]]:
        service = _operations_recovery_service()
        try:
            rows = service.search(text, tenant_id=tenant_id, limit=limit)
        finally:
            service.close()
        return list(rows)

    @app.get("/api/operations/cfdi/{uuid}")
    def operations_show(uuid: str, tenant_id: str | None = None) -> dict[str, str]:
        service = _operations_recovery_service()
        try:
            text = service.render_text(uuid, tenant_id=tenant_id)
        except LookupError:
            raise HTTPException(status_code=404, detail={"reason": "cfdi-not-found"}) from None
        finally:
            service.close()
        return {"uuid": uuid, "text": text}

    @app.post("/api/operations/print")
    def operations_print(body: OperationsPrintRequest) -> dict[str, object]:
        """Mirror ``print_invoice``'s three format branches exactly."""

        service = _operations_recovery_service()
        try:
            output_path = Path(body.output_path) if body.output_path else None
            if body.format == "text":
                text = service.render_text(body.uuid, tenant_id=body.tenant_id)
                if output_path is None:
                    return {"uuid": body.uuid, "format": body.format, "output_path": None, "text": text}
                output_path.parent.mkdir(parents=True, exist_ok=True)
                output_path.write_text(text, encoding="utf-8")
                return {"uuid": body.uuid, "format": body.format, "output_path": str(output_path), "text": None}
            if output_path is None:
                output_path = _resolve_storage_root(resolved.runtime.storage_root) / "exports" / f"{body.uuid}.{body.format}"
            if body.format == "html":
                output_path.parent.mkdir(parents=True, exist_ok=True)
                output_path.write_text(service.render_html(body.uuid, tenant_id=body.tenant_id), encoding="utf-8")
            elif body.format == "pdf":
                write_minimal_pdf(output_path, service.render_text(body.uuid, tenant_id=body.tenant_id))
            else:
                raise ValueError("format must be text, html, or pdf")
        except (LookupError, ValueError):
            raise HTTPException(status_code=400, detail={"reason": "operations-print-failed"}) from None
        finally:
            service.close()
        return {"uuid": body.uuid, "format": body.format, "output_path": str(output_path), "text": None}

    @app.post("/api/operations/export")
    def operations_export(body: OperationsExportRequest) -> dict[str, object]:
        service = _operations_recovery_service()
        try:
            output_path = (
                Path(body.output_path)
                if body.output_path
                else _resolve_storage_root(resolved.runtime.storage_root) / "exports" / "cfdi.csv"
            )
            exported_count = service.export_csv(output_path, tenant_id=body.tenant_id)
        finally:
            service.close()
        return {"output_path": str(output_path), "exported_count": exported_count}

    @app.post("/api/operations/import-xml")
    def operations_import_xml(body: OperationsImportXmlRequest) -> dict[str, object]:
        xml_path = Path(body.xml_path)
        _require_readable_file(xml_path, "operations-xml-path-invalid")
        service = _operations_vault_service()
        try:
            record = service.import_xml_file(xml_path)
        finally:
            service.engine.dispose()
        if record.error:
            raise HTTPException(status_code=400, detail={"reason": record.error})
        return asdict(record)

    @app.post("/api/operations/import-zip")
    def operations_import_zip(body: OperationsImportZipRequest) -> dict[str, object]:
        zip_path = Path(body.zip_path)
        _require_readable_file(zip_path, "operations-zip-path-invalid")
        service = _operations_vault_service()
        try:
            result = service.import_zip_file(zip_path)
        finally:
            service.engine.dispose()
        # The CLI's ``typer.Exit(code=1)`` on ``result.failed`` is a shell-exit
        # convention for a batch that partly failed; an HTTP response instead
        # reports the counts (and per-record detail, since none of it is
        # sensitive) with 200, leaving the caller to inspect ``failed``.
        return {
            "total_files": result.total_files,
            "imported": result.imported,
            "duplicates": result.duplicates,
            "failed": result.failed,
            "records": [asdict(record) for record in result.records],
        }

    @app.get("/api/operations/summary")
    def operations_summary() -> dict[str, object]:
        service = _operations_vault_service()
        try:
            vault_summary = service.summary()
        finally:
            service.engine.dispose()
        return {
            "by_month": [asdict(row) for row in vault_summary.by_month],
            "by_issuer": [asdict(row) for row in vault_summary.by_issuer],
            "by_comprobante_type": [asdict(row) for row in vault_summary.by_comprobante_type],
        }

    @app.post("/api/operations/export-csv")
    def operations_export_csv(body: OperationsExportCsvRequest) -> dict[str, object]:
        service = _operations_vault_service()
        output_path = Path(body.output_path)
        try:
            exported_count = service.export_csv(output_path)
        finally:
            service.engine.dispose()
        return {"output_path": str(output_path), "exported_count": exported_count}

    @app.post("/api/config/validate")
    def config_validate_endpoint(body: ConfigValidateRequest) -> dict[str, object]:
        config_path = Path(body.config_path)
        _require_readable_file(config_path, "config-path-invalid")
        try:
            config = load_config(config_path)
        except ConfigValidationError as exc:
            raise HTTPException(
                status_code=400, detail={"reason": "config-invalid", "errors": list(exc.errors)},
            ) from None
        return {
            "schema_version": config.schema_version,
            "profiles": [
                {
                    "profile_id": profile.profile_id,
                    "rfc": profile.rfc,
                    "storage_root": profile.storage_root,
                    "metadata_first": profile.download.metadata_first,
                }
                for profile in config.profiles
            ],
        }

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


def _require_typed_confirmation(submitted: str, expected: str) -> None:
    """Reject a state-changing request whose typed confirmation does not match.

    Exact, case-sensitive string equality with no trimming: this replaces the
    friction the retired CLI provided by making the operator name the resource,
    so "close enough" must not pass.  Callers invoke this as the first
    statement of the handler, before any profile load or database call.
    """

    if submitted != expected:
        raise HTTPException(status_code=400, detail={"reason": CONFIRMATION_MISMATCH_REASON})


def _setup_failure_reason(exc: Exception) -> str:
    """Map a setup failure to a bounded slug without echoing its message.

    ``SetupError.errors`` is a tuple of operator-facing strings that can embed
    a filesystem path; the raw text therefore never leaves this process.  The
    phrase value is not among the things those strings can contain — the only
    phrase-related message ``run_setup`` raises is fixed text — but this
    function ignores the message content either way and returns a slug.
    """

    errors = exc.errors if isinstance(exc, SetupError) else ()
    for error in errors:
        lowered = error.lower()
        for marker, reason in _SETUP_FAILURE_REASONS:
            if marker in lowered:
                return reason
    if errors:
        return "setup-input-invalid"
    return "setup-local-configuration-invalid"


def _secret_reference_and_provider(reference_uri: str, kind: str) -> tuple[CredentialReference, object]:
    """Build the credential reference and its native provider, or fail redacted.

    Both CLI helpers signal invalid input with ``typer.BadParameter``, whose
    message repeats the caller's reference/scheme; only a fixed slug is
    returned to the client.
    """

    try:
        reference = _credential_reference(reference_uri, kind)
    except typer.BadParameter:
        raise HTTPException(status_code=400, detail={"reason": "secret-kind-invalid"}) from None
    try:
        provider = _provider_for_reference(reference)
    except typer.BadParameter:
        raise HTTPException(status_code=400, detail={"reason": "secret-provider-unavailable"}) from None
    return reference, provider


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
