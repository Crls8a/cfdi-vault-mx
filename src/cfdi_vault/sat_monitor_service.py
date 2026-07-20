"""Internal five-minute SAT monitor service for the Compose deployment."""

from __future__ import annotations

import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Callable, Mapping, Protocol
from uuid import uuid4

from sqlalchemy import text

from cfdi_vault.queue_safety import validate_reference_string

if TYPE_CHECKING:
    from cfdi_vault.runtime_settings import RuntimeSettings


_REDIS_URL_UNSET = object()


class MonitorLease(Protocol):
    """Process-wide lease used to prevent concurrent monitor effects."""

    def acquire(self) -> bool:
        """Acquire the lease for one bounded runner invocation."""

    def release(self) -> None:
        """Release the lease after the invocation."""


class MonitorRunner(Protocol):
    """Minimal runner surface consumed by the service loop."""

    def run(self, *, now: datetime, limit: int = 2) -> object:
        """Process due work without waiting."""


class SatMonitorService:
    """Wake periodically and delegate only one due-runner invocation."""

    def __init__(
        self,
        runner: MonitorRunner,
        lease: MonitorLease,
        *,
        heartbeat: Callable[[object], None] | None = None,
        sleep: Callable[[float], None] = time.sleep,
        interval_seconds: int = 300,
    ) -> None:
        if type(interval_seconds) is not int or interval_seconds < 60:
            raise ValueError("monitor interval must be at least one minute")
        self._runner = runner
        self._lease = lease
        self._heartbeat = heartbeat or (lambda _: None)
        self._sleep = sleep
        self._interval = interval_seconds

    def run_once(self, *, now: datetime | None = None) -> object:
        """Run once, returning ``busy`` without contacting SAT if leased out."""

        if not self._lease.acquire():
            result = {"busy": True, "contacted_count": 0}
            self._heartbeat(result)
            return result
        try:
            result = self._runner.run(now=_utc(now or datetime.now(timezone.utc)), limit=2)
            self._heartbeat(result)
            return result
        finally:
            self._lease.release()

    def run_forever(self, *, stop: Callable[[], bool] = lambda: False) -> None:
        """Wake every five minutes; the runner itself decides whether work is due."""

        while not stop():
            self.run_once()
            self._sleep(self._interval)


class PostgresAdvisoryLease:
    """Hold a PostgreSQL advisory lock for the duration of one runner call."""

    def __init__(self, engine: object, key: str = "cfdi-vault:sat-monitor") -> None:
        self._engine = engine
        self._key = key
        self._connection = None

    def acquire(self) -> bool:
        connection = self._engine.connect()
        try:
            acquired = bool(
                connection.execute(
                    text("SELECT pg_try_advisory_lock(hashtext(:key))"),
                    {"key": self._key},
                ).scalar()
            )
        except Exception:
            try:
                connection.close()
            except Exception:
                pass
            raise
        if not acquired:
            connection.close()
            return False
        self._connection = connection
        return True

    def release(self) -> None:
        if self._connection is None:
            return
        try:
            self._connection.execute(
                text("SELECT pg_advisory_unlock(hashtext(:key))"),
                {"key": self._key},
            )
        finally:
            self._connection.close()
            self._connection = None


class RedisMonitorLease:
    """Transient process lease for the monitor, fenced by an opaque owner."""

    def __init__(
        self,
        redis_url: str,
        owner_id: str,
        *,
        ttl_seconds: int = 600,
        cache: object | None = None,
    ) -> None:
        if not isinstance(redis_url, str) or not redis_url.strip():
            raise ValueError("redis monitor lease requires a URL")
        validate_reference_string("owner_id", owner_id)
        if type(ttl_seconds) is not int or ttl_seconds < 60:
            raise ValueError("redis monitor lease TTL must be at least one minute")
        if cache is None:
            from cfdi_vault.cache import RedisCache

            cache = RedisCache(redis_url.strip())
        self._cache = cache
        self._owner_id = owner_id
        self._ttl_seconds = ttl_seconds
        self._key = "lock:sat-monitor"

    def acquire(self) -> bool:
        """Acquire the transient lease; the durable work limit remains in PostgreSQL."""

        return bool(self._cache.acquire_lock(self._key, self._owner_id, self._ttl_seconds))

    def release(self) -> None:
        """Release only this process owner's lease."""

        self._cache.release_lock(self._key, self._owner_id)


def build_monitor_lease(engine: object, redis_url: str | None) -> MonitorLease:
    """Prefer Redis for cross-container fencing and retain PostgreSQL fallback."""

    if isinstance(redis_url, str) and redis_url.strip():
        return RedisMonitorLease(redis_url, owner_id=f"sat-monitor-{uuid4().hex}")
    return PostgresAdvisoryLease(engine)


def _utc(value: datetime) -> datetime:
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)


class DatabaseDueInspector:
    """Run an injected PostgreSQL campaign runner, with a safe no-adapter mode."""

    def __init__(self, engine: object, runner: MonitorRunner | None = None) -> None:
        self._engine = engine
        self._runner = runner

    def run(self, *, now: datetime, limit: int = 2) -> object:
        if self._runner is not None:
            return self._runner.run(now=_utc(now), limit=min(limit, 2))
        with self._engine.connect() as connection:
            due = int(
                connection.execute(
                    text(
                        """SELECT count(*) FROM sat_requests
                   WHERE status IN ('submitted', 'waiting_verify')
                     AND next_check_at IS NOT NULL AND next_check_at <= :now
                     AND (service_window_expires_at IS NULL OR service_window_expires_at > :now)""",
                    ),
                    {"now": _utc(now)},
                ).scalar_one()
            )
        return {"monitor_state": "awaiting_live_grant", "due_count": due, "contacted_count": 0}


def build_database_runner(
    repository: object,
    verifier_factory: Callable[[str], object],
    *,
    environ: Mapping[str, str] | None = None,
    downloader_factory: Callable[[str], object] | None = None,
    artifact_coordinator: object | None = None,
    submitter_factory: Callable[[object], object] | None = None,
    query_factory: Callable[[object], object] | None = None,
    grant_ref: str | None = None,
    campaign_ref: str | None = None,
    package_kind: str = "metadata_zip",
) -> MonitorRunner:
    """Compose the production DB runner without performing any I/O at construction."""

    from cfdi_vault.sat_db_campaign_runner import SatCampaignRunner

    environment = environ if environ is not None else os.environ
    rabbitmq_url = environment.get("RABBITMQ_URL", "").strip()
    storage_root = environment.get("CFDI_STORAGE_ROOT", "").strip()
    if artifact_coordinator is None and rabbitmq_url and storage_root:
        # Queue publication is injected into the artifact coordinator, not
        # performed by the runner.  Construction only creates adapters; no
        # connection is opened until a package is durably claimed.
        from cfdi_vault.sat_campaign_artifacts import SatCampaignArtifactCoordinator
        from cfdi_vault.sat_campaign_ledger_handoff import build_durable_handoff

        durable_handoff = None
        engine = _repository_engine(repository)
        if engine is not None:
            durable_handoff = build_durable_handoff(engine, rabbitmq_url)
        if durable_handoff is not None:
            artifact_coordinator = SatCampaignArtifactCoordinator(
                repository, storage_root, durable_handoff=durable_handoff,
            )
        else:
            # Offline/fake repositories may not expose a SQLAlchemy bind. Keep
            # their explicit reference-only publisher path intact.
            from cfdi_vault.queueing import RabbitMqQueue

            artifact_coordinator = SatCampaignArtifactCoordinator(
                repository, storage_root, job_publisher=RabbitMqQueue(rabbitmq_url).publish,
            )

    return SatCampaignRunner(
        repository,  # type: ignore[arg-type]
        verifier_factory,  # type: ignore[arg-type]
        downloader_factory=downloader_factory,
        artifact_coordinator=artifact_coordinator,
        submitter_factory=submitter_factory,  # type: ignore[arg-type]
        query_factory=query_factory,  # type: ignore[arg-type]
        grant_ref=grant_ref,
        campaign_ref=campaign_ref,
        package_kind=package_kind,
    )


def _repository_engine(repository: object) -> object | None:
    """Return a SQLAlchemy bind when a repository is DB-backed."""

    factory = getattr(repository, "_session_factory", None)
    bind = getattr(factory, "kw", {}).get("bind") if factory is not None else None
    return bind


def build_enabled_database_runner(
    repository: object,
    *,
    profile_id: str,
    campaign_ref: str,
    grant_ref: str,
    environ: Mapping[str, str] | None = None,
) -> MonitorRunner:
    """Build the guarded runtime-backed runner for one monitor campaign.

    Construction validates the explicit live-worker gate and campaign grant,
    but does not call SAT.  External effects remain inside
    :class:`SatCampaignRunner`, after PostgreSQL persists each claim.
    """

    from cfdi_vault.sat_live_worker_runtime import (
        build_cfdi_worker_factories,
        build_metadata_worker_factories,
    )

    environment = environ if environ is not None else os.environ
    if hasattr(repository, "validate_grant"):
        grant = repository.validate_grant(
            campaign_ref=campaign_ref,
            grant_ref=grant_ref,
            profile_ref=profile_id,
            commit_ref=environment.get("CFDI_VAULT_COMMIT_REF", "").strip(),
            phase=None,
        )
        lane_phase = grant.phase
        if grant.phase == "continue":
            lane_phase = str(
                repository.get_campaign_status(
                    campaign_ref,
                    profile_ref=profile_id,
                ).get("phase", "")
            )
        if lane_phase == "metadata-proof":
            build_factories = build_metadata_worker_factories
        elif lane_phase == "cfdi-proof":
            build_factories = build_cfdi_worker_factories
        else:
            raise ValueError("campaign-lane-required")
    else:
        # Narrow fake repositories used by offline composition tests default
        # to Metadata; real repositories always expose grant validation.
        build_factories = build_metadata_worker_factories
    factories = build_factories(
        profile_id,
        repository,  # type: ignore[arg-type]
        campaign_ref=campaign_ref,
        grant_ref=grant_ref,
        environ=environment,
    )
    return build_database_runner(
        repository,
        factories.verifier_factory,  # type: ignore[arg-type]
        downloader_factory=factories.downloader_factory,  # type: ignore[arg-type]
        artifact_coordinator=factories.artifact_coordinator,
        submitter_factory=factories.submitter_factory,  # type: ignore[arg-type]
        query_factory=factories.query_factory,  # type: ignore[arg-type]
        environ=environment,
        grant_ref=grant_ref,
        campaign_ref=campaign_ref,
        package_kind=factories.package_kind,
    )


def healthcheck() -> None:
    """Fail fast when the monitor cannot reach its required database."""

    from cfdi_vault.db import create_engine_from_url, ensure_tables_exist

    settings = _resolve_monitor_settings()
    engine = create_engine_from_url(settings.database_url)
    try:
        ensure_tables_exist(engine, ("sat_campaigns", "sat_requests", "sat_claims"))
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))
    finally:
        engine.dispose()


def redis_heartbeat_callback(
    redis_url: str | None | object = _REDIS_URL_UNSET,
    *,
    environ: Mapping[str, str] | None = None,
) -> Callable[[object], None]:
    """Return a best-effort heartbeat callback without making Redis durable.

    Omitting ``redis_url`` preserves the historical process-environment lookup
    for direct callers.  Passing ``None`` explicitly disables Redis, while an
    explicit ``environ`` mapping makes that lookup deterministic.
    """

    if redis_url is _REDIS_URL_UNSET:
        url = _effective_environment(environ).get("REDIS_URL", "").strip()
    elif redis_url is None:
        url = ""
    elif isinstance(redis_url, str):
        url = redis_url.strip()
    else:
        url = ""
    if not url:
        return lambda _result: None
    try:
        from cfdi_vault.cache import RedisCache
        from cfdi_vault.cache_contract import WorkerHeartbeat

        cache = RedisCache(url)
    except Exception:
        return lambda _result: None

    def heartbeat(_result: object) -> None:
        try:
            cache.record_heartbeat(
                WorkerHeartbeat(worker_id="sat-monitor", updated_at=datetime.now(timezone.utc)),
                60,
            )
        except Exception:
            # Redis is transient observability only; never fail the SAT runner.
            return

    return heartbeat


def main() -> None:
    """Run the durable monitor loop when explicitly enabled.

    Compose starts this container disabled by default.  That keeps a normal
    development stack from waking a SAT-facing process before an operator has
    supplied a campaign runner with a validated grant and adapter.  The
    injected ``DatabaseDueInspector`` remains intentionally fail-closed when
    no runner is configured.
    """

    settings = _resolve_monitor_settings()
    if not settings.sat_monitor_enabled:
        return
    if not settings.live_worker_enabled:
        # A monitor without the explicit live-worker gate is intentionally a
        # no-op.  This keeps the default Compose stack from constructing a
        # SAT-facing runtime or contacting the service by accident.
        return

    from cfdi_vault.db import create_engine_from_url, ensure_tables_exist

    engine = create_engine_from_url(settings.database_url)
    try:
        ensure_tables_exist(engine, ("sat_campaigns", "sat_requests", "sat_claims"))
        profile_id = settings.campaign_profile or ""
        campaign_ref = settings.campaign_ref or ""
        grant_ref = settings.campaign_grant or ""
        if not all((profile_id, campaign_ref, grant_ref)):
            raise RuntimeError("sat-monitor campaign configuration is incomplete")
        from cfdi_vault.db import create_session_factory
        from cfdi_vault.sat_campaign_repository import SatCampaignRepository

        repository = SatCampaignRepository(create_session_factory(engine))
        runner = build_enabled_database_runner(
            repository,
            profile_id=profile_id,
            campaign_ref=campaign_ref,
            grant_ref=grant_ref,
            environ=_effective_environment(),
        )
        SatMonitorService(
            DatabaseDueInspector(engine, runner),
            build_monitor_lease(engine, settings.redis_url),
            heartbeat=redis_heartbeat_callback(
                settings.redis_url,
                environ=_effective_environment(),
            ),
        ).run_forever()
    finally:
        engine.dispose()


def _effective_environment(environ: Mapping[str, str] | None = None) -> Mapping[str, str]:
    """Return an explicit mapping without treating an empty mapping as absent."""

    return environ if environ is not None else os.environ


def _resolve_monitor_settings(
    environ: Mapping[str, str] | None = None,
) -> "RuntimeSettings":
    """Resolve monitor settings and expose only one fixed configuration error."""

    from cfdi_vault.runtime_settings import RuntimeSettings, RuntimeSettingsError

    try:
        return RuntimeSettings.resolve(
            environment=_effective_environment(environ),
            repository_root=Path.cwd(),
        )
    except RuntimeSettingsError as exc:
        raise RuntimeError("sat-monitor-settings-invalid") from exc


if __name__ == "__main__":
    main()
