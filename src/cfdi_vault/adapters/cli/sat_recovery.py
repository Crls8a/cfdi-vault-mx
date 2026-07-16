"""Internal CLI callbacks for one guarded, resumable SAT metadata recovery."""

from __future__ import annotations

import os
import re
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timezone
from io import StringIO
from pathlib import Path

import typer

import cfdi_vault.sat_metadata_recovery_state as recovery_state
from cfdi_vault.live_permit import (
    MAX_METADATA_RECOVERY_RANGE_DAYS,
    METADATA_RECOVERY_LIVE_SCOPE,
    LivePermitError,
    load_live_execution_permit,
    permit_expectation_from_query,
    validate_and_consume_live_permit,
    validate_consumed_metadata_recovery_permit,
    validate_consumed_metadata_recovery_permit_id,
)
from cfdi_vault.sat_metadata_observation import MetadataObservationError
from cfdi_vault.sat_metadata_observation_integration import (
    observe_metadata_recovery,
    prepare_metadata_observation_context,
)
from cfdi_vault.sat_metadata_recovery import PackageRecoveryStatus
from cfdi_vault.sat_metadata_recovery_runner import (
    advance_metadata_recovery_once,
    settle_metadata_recovery_locally,
)
from cfdi_vault.sat_metadata_recovery_scheduler import select_due_metadata_recovery
from cfdi_vault.sat_metadata_recovery_state import (
    MetadataRecoveryStateError,
    list_metadata_recovery_states,
    load_metadata_recovery_state,
)
from cfdi_vault.sat_metadata_submission import MetadataSubmissionError, SubmissionStatus, submit_metadata_recovery_once
from cfdi_vault.sat_transport import GuardedSoapHttpTransport, LiveSatGuardInput
from cfdi_vault.sat_v15_adapter import SatLiveV15MetadataAdapter
from cfdi_vault.storage import LocalStorage

from .common import (
    _build_profile_download_query_with_profile,
    _checkout_guard_status,
    _find_checkout_root,
    _load_download_profile,
    _setup_provider,
)
from .sat_live_environment import canonical_live_recovery_preflight

_RECOVERY_REF_RE = re.compile(r"run-[0-9a-f]{12}")


class _RecoveryCliError(ValueError):
    """Carry one allowlisted CLI failure code without private context."""

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)
def sat_metadata_recover_live(
    profile: str = typer.Option(..., "--profile", help="Local setup profile id."),
    direction: str = typer.Option(..., "--direction", help="received or issued."),
    from_date: str = typer.Option(..., "--from", help="Inclusive start date: YYYY-MM-DD."),
    to_date: str = typer.Option(..., "--to", help="Inclusive end date: YYYY-MM-DD."),
    authorization: str = typer.Option(..., "--authorization", help="Exact local recovery permit id."),
) -> None:
    """Submit or advance one permitted Metadata recovery using local state, sanitized aggregate output, and its opaque local recovery reference. Requires canonical SAT endpoints and a non-CI environment."""

    try:
        rejection = canonical_live_recovery_preflight()
        if rejection is not None:
            raise _RecoveryCliError(rejection)
        query, local_profile = _safe_recovery_query(profile, direction, from_date, to_date)
        repo_root = _checked_recovery_repo_root()
        _validate_recovery_state_path(local_profile, repo_root)
        observation = prepare_metadata_observation_context(local_profile.storage_root, repo_root=repo_root)
        existing = next((item for item in list_metadata_recovery_states(
            local_profile.storage_root, repo_root=repo_root,
        ) if item.profile_id == profile and item.criteria_hash == query.criteria_hash()), None)
        now = _recovery_now()
        if existing is not None:
            settled = settle_metadata_recovery_locally(
                storage_root=local_profile.storage_root,
                recovery_ref=existing.recovery.recovery_ref,
                now=now, tested_commit=observation.tested_commit,
                entry_point="metadata-recover-live", repo_root=repo_root,
            )
            if settled.recovery is None:
                _print_runner_failure(settled, existing.recovery.recovery_ref)
                raise typer.Exit(code=1)
            if not settled.requires_live:
                final = load_metadata_recovery_state(
                    local_profile.storage_root, existing.recovery.recovery_ref,
                    repo_root=repo_root,
                )
                observe_metadata_recovery(
                    observation, before=existing, after=final, outcome=settled,
                    observed_at=now, entry_point="metadata-recover-live",
                    reconcile_submission=True,
                )
                _print_recovery_document(settled.recovery)
                return
        permit = _authorize_metadata_recovery(authorization=authorization, profile=profile, query=query,
                                              now=now, repo_root=repo_root)
        package_storage = _new_recovery_storage(local_profile.storage_root)
        adapter = _new_recovery_adapter(local_profile, permit)
        claim = submit_metadata_recovery_once(requester=adapter, query=query, now=now,
            storage_root=local_profile.storage_root, profile_id=profile,
            criteria_hash=query.criteria_hash(), authorization_ref=permit.permit_id,
            tested_commit=observation.tested_commit, entry_point="metadata-recover-live",
            repo_root=repo_root)
        if claim.status is not SubmissionStatus.ACCEPTED:
            _print_submission(claim.status)
            raise typer.Exit(code=1)
        record = load_metadata_recovery_state(local_profile.storage_root, claim.recovery_ref, repo_root=repo_root)
        if record.authorization_ref != permit.permit_id:
            raise _RecoveryCliError("authorization_mismatch")
        outcome = advance_metadata_recovery_once(storage_root=local_profile.storage_root,
            recovery_ref=claim.recovery_ref, verifier=adapter, downloader=adapter,
            package_storage=package_storage, now=now,
            tested_commit=observation.tested_commit, entry_point="metadata-recover-live",
            repo_root=repo_root)
        if outcome.recovery is None:
            _print_runner_failure(outcome, claim.recovery_ref)
            raise typer.Exit(code=1)
        final = load_metadata_recovery_state(local_profile.storage_root, claim.recovery_ref, repo_root=repo_root)
        observe_metadata_recovery(observation, before=existing, after=final, outcome=outcome,
            observed_at=now, entry_point="metadata-recover-live", reconcile_submission=True)
        _print_recovery_document(outcome.recovery)
    except typer.Exit:
        raise
    except (_RecoveryCliError, LivePermitError, MetadataRecoveryStateError) as exc:
        _fail(exc.reason)
    except MetadataObservationError as exc:
        _fail(str(exc))
    except MetadataSubmissionError:
        _fail("submission_state_failed")
    except Exception:
        _fail("recovery_setup_failed")
def sat_metadata_recovery_status(
    profile: str = typer.Option(..., "--profile", help="Local setup profile id."),
    recovery_ref: str = typer.Option(..., "--recovery-ref", help="Opaque local recovery reference."),
) -> None:
    """Read local persisted recovery state and print sanitized aggregates plus its opaque local recovery reference."""

    try:
        local_profile = _safe_recovery_profile(profile)
        repo_root = _recovery_repo_root()
        _validate_recovery_state_path(local_profile, repo_root)
        record = load_metadata_recovery_state(local_profile.storage_root, recovery_ref, repo_root=repo_root)
        _print_recovery_document(record.to_redacted_document())
    except typer.Exit:
        raise
    except (_RecoveryCliError, MetadataRecoveryStateError) as exc:
        _fail(exc.reason)
    except Exception:
        _fail("recovery_status_failed")
def sat_metadata_recovery_runner(
    profile: str = typer.Option(..., "--profile", help="Local setup profile id."),
) -> None:
    """Print the opaque local recovery reference and sanitized totals after advancing one due recovery. Requires canonical SAT endpoints and a non-CI environment."""

    try:
        rejection = canonical_live_recovery_preflight()
        if rejection is not None:
            raise _RecoveryCliError(rejection)
        local_profile = _safe_recovery_profile(profile)
        repo_root = _checked_recovery_repo_root()
        _validate_recovery_state_path(local_profile, repo_root)
        now = _recovery_now()
        records = list_metadata_recovery_states(
            local_profile.storage_root, repo_root=repo_root,
        )
        selected = select_due_metadata_recovery(
            records, profile_id=local_profile.profile_id, now=now,
        )
        if selected is None:
            _print_scheduler_idle()
            return
        record = next(item for item in records if item.recovery.recovery_ref == selected)
        observation = prepare_metadata_observation_context(local_profile.storage_root, repo_root=repo_root)
        settled = settle_metadata_recovery_locally(
            storage_root=local_profile.storage_root, recovery_ref=selected,
            now=now, tested_commit=observation.tested_commit,
            entry_point="metadata-recovery-runner", repo_root=repo_root,
        )
        if settled.recovery is None:
            _print_runner_failure(settled, selected)
            raise typer.Exit(code=1)
        if not settled.requires_live:
            final = load_metadata_recovery_state(local_profile.storage_root, selected, repo_root=repo_root)
            observe_metadata_recovery(observation, before=record, after=final, outcome=settled,
                observed_at=now, entry_point="metadata-recovery-runner")
            _print_recovery_document(settled.recovery)
            return
        permit = validate_consumed_metadata_recovery_permit_id(
            record.authorization_ref, profile_id=record.profile_id,
            direction=record.direction, date_from=record.fecha_inicial,
            date_to=record.fecha_final, now=now, repo_root=repo_root,
        )
        package_storage = _new_recovery_storage(local_profile.storage_root)
        adapter = _new_recovery_adapter(local_profile, permit)
        outcome = advance_metadata_recovery_once(
            storage_root=local_profile.storage_root, recovery_ref=selected,
            verifier=adapter, downloader=adapter, package_storage=package_storage,
            now=now, tested_commit=observation.tested_commit,
            entry_point="metadata-recovery-runner", repo_root=repo_root,
        )
        if outcome.recovery is None:
            _print_runner_failure(outcome, selected)
            raise typer.Exit(code=1)
        final = load_metadata_recovery_state(local_profile.storage_root, selected, repo_root=repo_root)
        observe_metadata_recovery(observation, before=record, after=final, outcome=outcome,
            observed_at=now, entry_point="metadata-recovery-runner")
        _print_recovery_document(outcome.recovery)
    except typer.Exit:
        raise
    except (_RecoveryCliError, LivePermitError, MetadataRecoveryStateError) as exc:
        _fail(exc.reason)
    except MetadataObservationError as exc:
        _fail(str(exc))
    except Exception:
        _fail("recovery_runner_failed")
def _safe_recovery_query(profile: str, direction: str, start: str, end: str):
    hidden = StringIO()
    try:
        with redirect_stdout(hidden), redirect_stderr(hidden):
            return _build_profile_download_query_with_profile(profile_id=profile, from_date=start,
                to_date=end, kind="metadata", direction=direction)
    except Exception:
        raise _RecoveryCliError("recovery_query_invalid") from None
def _safe_recovery_profile(profile: str):
    hidden = StringIO()
    try:
        with redirect_stdout(hidden), redirect_stderr(hidden):
            return _load_download_profile(profile)
    except Exception:
        raise _RecoveryCliError("profile_invalid") from None
def _recovery_repo_root() -> Path:
    root = _find_checkout_root(Path.cwd())
    if root is None:
        raise _RecoveryCliError("checkout_unavailable")
    return root
def _checked_recovery_repo_root() -> Path:
    root = _recovery_repo_root()
    clean, scanner_passed = _checkout_guard_status()
    if not clean:
        raise _RecoveryCliError("checkout_not_clean")
    if not scanner_passed:
        raise _RecoveryCliError("sensitive_scanner_failed")
    return root
def _validate_recovery_state_path(profile, repo_root: Path) -> None:  # type: ignore[no-untyped-def]
    recovery_state._resolved_state_path(profile.storage_root, repo_root=repo_root, create_parent=False)
def _authorize_metadata_recovery(*, authorization, profile, query, now, repo_root):  # type: ignore[no-untyped-def]
    expectation = permit_expectation_from_query(METADATA_RECOVERY_LIVE_SCOPE, profile, query)
    current = load_live_execution_permit(authorization)
    if current.consumed:
        return validate_consumed_metadata_recovery_permit(authorization, profile_id=profile,
            direction=expectation["direction"], date_from=expectation["date_from"],
            date_to=expectation["date_to"], now=now, repo_root=repo_root)
    return validate_and_consume_live_permit(authorization, **expectation, now=now, repo_root=repo_root)
def _new_recovery_storage(root: Path) -> LocalStorage:
    return LocalStorage(root)
def _new_recovery_adapter(profile, _permit):  # type: ignore[no-untyped-def]
    return SatLiveV15MetadataAdapter(profile=profile, provider=_setup_provider(profile.profile_id),
                                    transport=_metadata_recovery_transport(),
                                    max_range_days=MAX_METADATA_RECOVERY_RANGE_DAYS)
def _metadata_recovery_transport() -> GuardedSoapHttpTransport:
    """Build the live transport only after exact permit and repository gates pass."""

    return GuardedSoapHttpTransport(guard_input_factory=lambda: LiveSatGuardInput(
        profile_ready=True, credentials_ready=True, doctor_ok=True, scanner_passed=True,
        repo_clean=True, metadata_only=True, range_within_limit=True, live_permit_verified=True,
        live_permit_allows_real_credentials=True, environ=os.environ))
def _recovery_now() -> datetime:
    return datetime.now(timezone.utc)
def _operation_attempts(document: dict[str, object]) -> int:
    packages = document.get("packages", [])
    attempted = sum(item.get("status") != PackageRecoveryStatus.PENDING.value
                    for item in packages if isinstance(item, dict)) if isinstance(packages, list) else 0
    verify = document.get("verifyAttempts", 0)
    return (verify if type(verify) is int else 0) + attempted
def _print_recovery_document(document: dict[str, object]) -> None:
    status = str(document["status"])
    record_count = document.get("recordCount")
    stage = "waiting_verify" if status == "verify_scheduled" else (
        "downloading" if status in {"packages_ready", "downloading"} else "finished")
    values = (("stage", stage), ("status", status), ("operation_attempts", _operation_attempts(document)),
        ("next_check_at", document.get("nextCheckAt", "")), ("package_count", document.get("packageCount", 0)),
        ("zip_valid_count", document.get("zipValidCount", 0)), ("txt_extracted", document.get("txtCount", 0)),
        ("record_count", "not_reported" if record_count is None else record_count))
    for key, value in values:
        typer.echo(f"{key}={value}")
    _print_safe_recovery_ref(document.get("recoveryRef"))
def _print_submission(status: SubmissionStatus) -> None:
    typer.echo("stage=submission")
    typer.echo(f"status={status.value}")
    typer.echo("operation_attempts=1")
def _print_runner_failure(outcome, recovery_ref=None) -> None:  # type: ignore[no-untyped-def]
    typer.echo("stage=runner")
    typer.echo(f"status={outcome.error_kind or 'runner_failed'}")
    typer.echo(f"operation_attempts={outcome.verify_count + outcome.download_attempts}")
    _print_safe_recovery_ref(recovery_ref)
def _print_safe_recovery_ref(value) -> None:  # type: ignore[no-untyped-def]
    """Print only the validated opaque local recovery reference."""
    if isinstance(value, str) and _RECOVERY_REF_RE.fullmatch(value):
        typer.echo(f"recovery_ref={value}")
def _print_scheduler_idle() -> None:
    typer.echo("stage=scheduler")
    typer.echo("status=no_due")
    typer.echo("operation_attempts=0")
def _fail(reason: str) -> None:
    typer.echo(f"error={reason}")
    raise typer.Exit(code=1)
