"""Host-only consumer for durable SAT campaign runs (ADR 0005).

This process, and only this process, executes the live campaign sequence that
``POST /api/campaign/{profile}/{campaign}/run`` used to run inside the HTTP
request.  It must run on the host rather than in a container: the live sequence
resolves the FIEL phrase through the platform credential store, which
:mod:`cfdi_vault.os_secret_providers` only exposes on the native platform, so no
docker-compose service can perform this work.

Process placement contract:

* Only this process may set ``CFDI_VAULT_LIVE_WORKER_ENABLED=1``,
  ``CFDI_VAULT_COMMIT_REF``, ``CFDI_STORAGE_ROOT`` and the remaining live-worker
  variables.  The control-panel API process must leave the live gate unset so
  that any accidental call to the old synchronous path fails closed through
  ``sat_campaign_db_cli.run_without_adapter`` instead of contacting SAT.
* The operator starts this process by hand (``cfdi-vault-campaign-run-worker``).
  There is deliberately no auto-start, scheduler, or panel-launched supervisor
  yet; that is a separate, explicitly out-of-scope design.

Failure contract: a live SAT run is never retried by infrastructure.  Every
outcome — including an unexpected exception — is recorded as a terminal
``sat_campaign_runs`` row and the broker delivery is always acknowledged, so the
generic retry/dead-letter machinery in :mod:`cfdi_vault.queueing` can never fire
a second live SAT sequence unattended.
"""

from __future__ import annotations

import argparse
import json
import os
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Mapping, Sequence
from urllib.parse import urlsplit

from sqlalchemy.engine import Engine, make_url

from cfdi_vault.queue_safety import validate_reason_code, validate_reference_string
from cfdi_vault.runtime_settings import campaign_run_lease_seconds

CONSUMER_NAME = "sat-campaign-run-worker"
COMMIT_REF_MISMATCH_CODE = "commit-ref-mismatch"

# ``SatRunnerReport.as_safe_dict`` statuses mapped onto the terminal run states.
# Only 'processed' and 'no_due_operations' mean the bounded sequence completed;
# everything else needs a human decision, never an automatic retry.
_RUNNER_OUTCOMES: dict[str, tuple[str, str]] = {
    "processed": ("succeeded", "processed"),
    "no_due_operations": ("succeeded", "no-due-operations"),
    "busy": ("failed", "campaign-busy"),
    "error": ("failed", "runner-error"),
}


@dataclass(frozen=True, slots=True, repr=False)
class CampaignRunReport:
    """Redacted aggregate result of one campaign-run service pass."""

    status: str
    abandoned: int = 0
    claimed: int = 0
    succeeded: int = 0
    failed: int = 0
    hints_drained: int = 0
    reason_code: str | None = None

    def __post_init__(self) -> None:
        if self.status not in {"idle", "completed", "error"}:
            raise ValueError("unsupported campaign run status")
        for name in ("abandoned", "claimed", "succeeded", "failed", "hints_drained"):
            value = getattr(self, name)
            if type(value) is not int or value < 0:
                raise ValueError(f"campaign run {name} must be non-negative")
        if self.reason_code is not None:
            validate_reason_code(self.reason_code)

    def __repr__(self) -> str:
        return (
            "CampaignRunReport(status={!r}, abandoned={}, claimed={}, succeeded={}, "
            "failed={}, hints_drained={}, reason_code={!r})"
        ).format(
            self.status, self.abandoned, self.claimed, self.succeeded,
            self.failed, self.hints_drained, self.reason_code,
        )

    def as_dict(self) -> dict[str, int | str | None]:
        """Return only operational aggregates safe for logs and status APIs."""

        return {
            "status": self.status,
            "abandoned": self.abandoned,
            "claimed": self.claimed,
            "succeeded": self.succeeded,
            "failed": self.failed,
            "hints_drained": self.hints_drained,
            "reason_code": self.reason_code,
        }


class CampaignRunService:
    """Claim one queued run per pass and execute it exactly once.

    PostgreSQL is the work list.  The broker hint is drained only to shorten the
    wait and keep the queue bounded; the claimed row is always re-read from the
    database, so a lost, duplicated, or out-of-order hint changes nothing.
    """

    def __init__(
        self,
        repository: object,
        *,
        commit_ref: str,
        worker_ref: str = CONSUMER_NAME,
        lease_seconds: int = 900,
        poll_seconds: float = 5.0,
        max_hints: int = 16,
        runner: Callable[[str, str, str], dict[str, object]] | None = None,
        hint_consumer: Callable[[], int] | None = None,
        clock: Callable[[], datetime] | None = None,
        sleep: Callable[[float], None] = time.sleep,
        status_sink: Callable[[dict[str, int | str | None]], None] | None = None,
    ) -> None:
        validate_reference_string("worker_ref", worker_ref)
        validate_reference_string("commit_ref", commit_ref)
        if type(lease_seconds) is not int or lease_seconds < 1:
            raise ValueError("campaign run lease_seconds must be positive")
        if isinstance(poll_seconds, bool) or not isinstance(poll_seconds, (int, float)) or poll_seconds <= 0:
            raise ValueError("campaign run poll_seconds must be positive")
        if type(max_hints) is not int or max_hints < 0:
            raise ValueError("campaign run max_hints must be non-negative")
        self.repository = repository
        self.commit_ref = commit_ref
        self.worker_ref = worker_ref
        self.lease_seconds = lease_seconds
        self.poll_seconds = float(poll_seconds)
        self.max_hints = max_hints
        self.runner = runner or _default_runner
        self.hint_consumer = hint_consumer
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self.sleep = sleep
        self.status_sink = status_sink or (lambda _status: None)

    def run_once(self, *, now: datetime | None = None) -> CampaignRunReport:
        """Reap expired leases, then claim and execute at most one run.

        The reaper runs on every pass rather than on a slower cadence: it is one
        bounded ``UPDATE`` over a partial index, and running it first means a
        crashed predecessor's row becomes visibly ``abandoned`` before this pass
        reports itself idle.
        """

        stamp = _stamp(now or self.clock())
        try:
            abandoned = int(self.repository.abandon_expired_campaign_runs(stamp))
        except Exception:
            report = CampaignRunReport("error", reason_code="reaper_unavailable")
            self._publish_status(report)
            return report
        hints = self._drain_hints()
        try:
            record = self.repository.claim_next_campaign_run(
                worker_ref=self.worker_ref, lease_seconds=self.lease_seconds, now=stamp,
            )
        except Exception:
            report = CampaignRunReport("error", abandoned=abandoned, hints_drained=hints,
                                       reason_code="claim_unavailable")
            self._publish_status(report)
            return report
        if record is None:
            report = CampaignRunReport("idle", abandoned=abandoned, hints_drained=hints)
            self._publish_status(report)
            return report
        succeeded, failed, reason_code = self._execute(record, stamp)
        report = CampaignRunReport(
            "completed", abandoned=abandoned, claimed=1, succeeded=succeeded,
            failed=failed, hints_drained=hints, reason_code=reason_code,
        )
        self._publish_status(report)
        return report

    def run_forever(self, *, stop: Callable[[], bool] | None = None) -> None:
        """Execute queued runs until the injected stop signal.

        Only an idle pass sleeps: a busy queue drains back-to-back so a long
        campaign is not paced by the poll interval.
        """

        should_stop = stop or (lambda: False)
        while not should_stop():
            report = self.run_once()
            if report.status != "completed":
                self.sleep(self.poll_seconds)

    def _execute(self, record: object, now: datetime) -> tuple[int, int, str | None]:
        """Run one claimed row, converting every outcome into a terminal write.

        Nothing raises out of this method.  A live SAT run that escaped into the
        broker's retry policy could be replayed unattended, which ADR 0004 and
        ADR 0005 both forbid, so the failure boundary lives here.
        """

        run_ref = str(record.run_ref)
        if str(record.commit_ref) != self.commit_ref:
            # The row was authorized against a different build of this system.
            # Running it would apply this process's code to another build's
            # grant, so it is closed without contacting SAT.
            self._finish(run_ref, "failed", COMMIT_REF_MISMATCH_CODE, {})
            return 0, 1, COMMIT_REF_MISMATCH_CODE
        try:
            campaign_ref = self.repository.campaign_ref_for_run(run_ref)
            if not campaign_ref:
                self._finish(run_ref, "failed", "campaign-not-found", {})
                return 0, 1, "campaign-not-found"
            self.repository.mark_campaign_run_running(
                run_ref, lease_seconds=self.lease_seconds, now=now,
            )
        except Exception:
            self._finish(run_ref, "failed", "run-state-unavailable", {})
            return 0, 1, "run-state-unavailable"
        try:
            result = self.runner(str(record.profile_ref), str(campaign_ref), str(record.grant_ref))
        except Exception:
            # Transport text and exception detail never reach the durable row or
            # the status line; only a fixed reason code does.
            self._finish(run_ref, "failed", "runner-unavailable", {})
            return 0, 1, "runner-unavailable"
        status, reason_code = _RUNNER_OUTCOMES.get(
            str(result.get("status", "")), ("failed", "runner-status-unknown"),
        )
        self._finish(run_ref, status, reason_code, result)
        return (1, 0, reason_code) if status == "succeeded" else (0, 1, reason_code)

    def _finish(
        self, run_ref: str, status: str, reason_code: str, result: Mapping[str, object],
    ) -> None:
        """Close the row with a fresh clock reading; a live run can take minutes."""

        try:
            self.repository.record_campaign_run_result(
                run_ref, status=status, result_code=reason_code,
                contacted_count=_count(result, "contacted_count"),
                submitted_count=_count(result, "submitted_count"),
                package_count=_count(result, "package_count"),
                now=_stamp(self.clock()),
            )
        except Exception:
            # The lease still expires, so the reaper closes the row as
            # 'abandoned' rather than leaving it claimable by a second worker.
            return

    def _drain_hints(self) -> int:
        if self.hint_consumer is None or self.max_hints < 1:
            return 0
        drained = 0
        for _ in range(self.max_hints):
            try:
                if self.hint_consumer() < 1:
                    break
            except Exception:
                # The hint is an optimization; PostgreSQL polling continues.
                break
            drained += 1
        return drained

    def _publish_status(self, report: CampaignRunReport) -> None:
        try:
            self.status_sink(report.as_dict())
        except Exception:
            return


class CampaignRunConfigError(ValueError):
    """Raised when the campaign-run consumer lacks safe non-secret settings."""

    def __init__(self, reason_code: str) -> None:
        self.reason_code = validate_reason_code(reason_code)
        super().__init__(self.reason_code)

    def __repr__(self) -> str:
        return "CampaignRunConfigError(reason_code=<redacted>)"


@dataclass(frozen=True, slots=True, repr=False)
class CampaignRunSettings:
    """Validated settings for the host-only campaign-run consumer."""

    database_url: str
    rabbitmq_url: str | None
    commit_ref: str
    worker_ref: str
    poll_seconds: float
    lease_seconds: int
    max_hints: int
    enabled: bool

    def __repr__(self) -> str:
        """Never expose URL credentials or the commit reference through logs."""

        return (
            "CampaignRunSettings(database_configured=True, "
            f"rabbitmq_configured={self.rabbitmq_url is not None!r}, "
            f"worker_ref={self.worker_ref!r}, poll_seconds={self.poll_seconds!r}, "
            f"lease_seconds={self.lease_seconds!r}, max_hints={self.max_hints!r}, "
            f"enabled={self.enabled!r})"
        )


@dataclass(slots=True, repr=False)
class CampaignRunRuntime:
    """Owned engine and consumer service; callers must close the engine."""

    engine: Engine
    service: CampaignRunService

    def __repr__(self) -> str:
        return "CampaignRunRuntime(configured=True)"

    def close(self) -> None:
        self.engine.dispose()


def resolve_campaign_run_settings(
    environment: Mapping[str, str] | None = None,
) -> CampaignRunSettings:
    """Resolve required references and bounded settings without touching the network."""

    values = environment if environment is not None else os.environ
    database_url = str(values.get("DATABASE_URL", "")).strip()
    rabbitmq_url = str(values.get("RABBITMQ_URL", "")).strip()
    commit_ref = str(values.get("CFDI_VAULT_COMMIT_REF", "")).strip()
    if not database_url:
        raise CampaignRunConfigError("database_required")
    if not commit_ref:
        raise CampaignRunConfigError("commit_ref_required")
    try:
        if not make_url(database_url).drivername.startswith("postgresql"):
            raise CampaignRunConfigError("postgresql_required")
    except CampaignRunConfigError:
        raise
    except Exception as exc:
        raise CampaignRunConfigError("database_invalid") from exc
    if rabbitmq_url:
        try:
            parts = urlsplit(rabbitmq_url)
            if (
                parts.scheme.lower() not in {"amqp", "amqps"}
                or not parts.netloc
                or not parts.hostname
                or (parts.port is not None and not 1 <= parts.port <= 65_535)
            ):
                raise CampaignRunConfigError("rabbitmq_invalid")
        except CampaignRunConfigError:
            raise
        except (TypeError, UnicodeError, ValueError) as exc:
            raise CampaignRunConfigError("rabbitmq_invalid") from exc
    try:
        validate_reference_string("commit_ref", commit_ref)
    except (TypeError, ValueError) as exc:
        raise CampaignRunConfigError("commit_ref_invalid") from exc
    try:
        lease_seconds = campaign_run_lease_seconds(values)
    except ValueError as exc:
        raise CampaignRunConfigError("lease_seconds_invalid") from exc

    enabled = _parse_bool(values.get("SAT_CAMPAIGN_RUN_WORKER_ENABLED", "0"), "enabled")
    poll_seconds = _parse_float(values.get("SAT_CAMPAIGN_RUN_POLL_SECONDS", "5"), "poll_seconds", 1, 3600)
    max_hints = _parse_int(values.get("SAT_CAMPAIGN_RUN_MAX_HINTS", "16"), "max_hints", 0, 1000)
    worker_ref = str(values.get("SAT_CAMPAIGN_RUN_WORKER_REF", CONSUMER_NAME)).strip()
    try:
        validate_reference_string("worker_ref", worker_ref)
    except (TypeError, ValueError) as exc:
        raise CampaignRunConfigError("worker_ref_invalid") from exc
    return CampaignRunSettings(
        database_url=database_url,
        rabbitmq_url=rabbitmq_url or None,
        commit_ref=commit_ref,
        worker_ref=worker_ref,
        poll_seconds=poll_seconds,
        lease_seconds=lease_seconds,
        max_hints=max_hints,
        enabled=enabled,
    )


def build_campaign_run_runtime(
    settings: CampaignRunSettings,
    *,
    engine_factory: Callable[[str], Engine] | None = None,
    status_sink: Callable[[dict[str, int | str | None]], None] | None = None,
) -> CampaignRunRuntime:
    """Build the DB-backed consumer; construction never instantiates a SAT adapter."""

    from cfdi_vault.db import create_engine_from_url, create_session_factory, ensure_tables_exist
    from cfdi_vault.sat_campaign_repository import SatCampaignRepository

    factory = engine_factory or create_engine_from_url
    engine = factory(settings.database_url)
    try:
        ensure_tables_exist(engine, ("sat_campaigns", "sat_grants", "sat_campaign_runs"))
        repository = SatCampaignRepository(create_session_factory(engine))
        service = CampaignRunService(
            repository,
            commit_ref=settings.commit_ref,
            worker_ref=settings.worker_ref,
            lease_seconds=settings.lease_seconds,
            poll_seconds=settings.poll_seconds,
            max_hints=settings.max_hints,
            hint_consumer=_build_hint_consumer(settings.rabbitmq_url),
            status_sink=status_sink,
        )
        return CampaignRunRuntime(engine, service)
    except Exception:
        engine.dispose()
        raise


def main(argv: Sequence[str] | None = None, *, environment: Mapping[str, str] | None = None) -> int:
    """Execute one queued run or loop; SAT is contacted only through the runner."""

    parser = argparse.ArgumentParser(prog="cfdi-vault-campaign-run-worker")
    parser.add_argument("--once", action="store_true", help="execute at most one queued run and exit")
    parser.add_argument("--loop", action="store_true", help="poll and execute queued runs until stopped")
    args = parser.parse_args(list(argv) if argv is not None else None)
    if args.once and args.loop:
        _emit_runtime_error("mode_conflict")
        return 2
    try:
        settings = resolve_campaign_run_settings(environment)
    except CampaignRunConfigError as exc:
        _emit_runtime_error(exc.reason_code)
        return 2
    if not settings.enabled:
        print(json.dumps({"status": "disabled", "reason_code": "feature_disabled"}, sort_keys=True))
        return 0

    def emit(status: dict[str, int | str | None]) -> None:
        print(json.dumps(status, sort_keys=True))

    runtime: CampaignRunRuntime | None = None
    try:
        runtime = build_campaign_run_runtime(settings, status_sink=emit)
        if args.once:
            runtime.service.run_once()
        else:
            runtime.service.run_forever()
        return 0
    except KeyboardInterrupt:
        return 0
    except Exception:
        _emit_runtime_error("runtime_unavailable")
        return 2
    finally:
        if runtime is not None:
            runtime.close()


def _default_runner(profile_ref: str, campaign_ref: str, grant_ref: str) -> dict[str, object]:
    """Execute the same bounded sequence the CLI runs, with no reimplementation."""

    from cfdi_vault.sat_campaign_db_cli import run_from_environment

    return run_from_environment(profile_ref, campaign_ref, grant_ref)


def _build_hint_consumer(rabbitmq_url: str | None) -> Callable[[], int] | None:
    """Return a drainer that acknowledges one wake hint and reads no payload."""

    if not rabbitmq_url:
        return None

    from cfdi_vault.domain import QueueName
    from cfdi_vault.queueing import RabbitMqQueue

    broker = RabbitMqQueue(rabbitmq_url)

    def drain() -> int:
        # The handler cannot fail, so this delivery can never reach the retry or
        # dead-letter transitions: a wake hint must never schedule SAT work.
        outcome = broker.consume_one_reliably(QueueName.SAT_CAMPAIGN_RUN.value, lambda _message: None)
        return 0 if outcome is None else 1

    return drain


def _count(result: Mapping[str, object], key: str) -> int:
    value = result.get(key, 0)
    if type(value) is not int or isinstance(value, bool) or value < 0:
        return 0
    return value


def _stamp(value: datetime) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise ValueError("campaign run timestamp must be timezone-aware")
    return value


def _emit_runtime_error(reason_code: str) -> None:
    print(json.dumps({"status": "error", "reason_code": reason_code}, sort_keys=True))


def _parse_bool(raw: object, name: str) -> bool:
    value = str(raw).strip().lower()
    if value in {"1", "true", "yes", "on"}:
        return True
    if value in {"0", "false", "no", "off"}:
        return False
    raise CampaignRunConfigError(f"{name}_invalid")


def _parse_int(raw: object, name: str, minimum: int, maximum: int) -> int:
    try:
        value = int(str(raw).strip())
    except (TypeError, ValueError) as exc:
        raise CampaignRunConfigError(f"{name}_invalid") from exc
    if not minimum <= value <= maximum:
        raise CampaignRunConfigError(f"{name}_invalid")
    return value


def _parse_float(raw: object, name: str, minimum: float, maximum: float) -> float:
    try:
        value = float(str(raw).strip())
    except (TypeError, ValueError) as exc:
        raise CampaignRunConfigError(f"{name}_invalid") from exc
    if value != value or not minimum <= value <= maximum:
        raise CampaignRunConfigError(f"{name}_invalid")
    return value


__all__ = [
    "CampaignRunConfigError",
    "CampaignRunReport",
    "CampaignRunRuntime",
    "CampaignRunService",
    "CampaignRunSettings",
    "build_campaign_run_runtime",
    "main",
    "resolve_campaign_run_settings",
]


if __name__ == "__main__":
    raise SystemExit(main())
