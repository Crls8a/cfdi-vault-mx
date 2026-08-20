# ADR 0005: Asynchronous campaign run (durable queue + host-only consumer)

## Status

Proposed.

## Decision

`POST /api/campaign/{profile_id}/{campaign_ref}/run` no longer executes the
live SAT sequence inside the HTTP request. It now:

1. runs the same synchronous pre-checks the runner has always run
   (`campaign-not-found`, `campaign-profile-mismatch`, `campaign-grant-invalid`,
   `campaign-lane-required`) and rejects a bad request with `400`;
2. commits one row in a new `sat_campaign_runs` table (Flyway `V9`);
3. publishes a `sat.campaign.run` wake hint to RabbitMQ *after* that commit;
4. returns `202 Accepted` with `{"status": "queued", "run_ref", "campaign_ref",
   "requested_at"}`.

A new host process, `cfdi_vault.sat_campaign_run_service` (console script
`cfdi-vault-campaign-run-worker`), claims the row and calls the exact same
`sat_campaign_db_cli.run_from_environment` the CLI calls. `GET .../status`
gains a `last_run` field so the request is visible even when it fails before
any VERIFY attempt.

## Why

**The panel process cannot do this work, and neither can any container.** The
live sequence resolves the FIEL phrase through the platform credential store.
`sat_live_worker_runtime._provider` selects the native provider and
`os_secret_providers` only exposes the Windows backend on `win32`; a Linux
docker-compose service has nothing to resolve. The existing `worker` container
runs a `FakeSatClient`-backed `RecoveryService` and is structurally incapable of
this work. So the consumer had to be a *new host process* — not a new compose
service, and not the existing worker.

**A live SAT run is not an HTTP-request-shaped unit of work.** The three-week
live campaign showed a run is a multi-minute submit/verify/download conversation.
Holding it open in a request means the browser owns the lifetime of a live SAT
operation: a closed tab, a proxy timeout, or a panel restart leaves durable state
advanced with no record of who advanced it and no way to observe it. The whole
point of ADR 0004 was continuous visibility; a blocking button was the one place
the panel still had none.

**A run that failed early was invisible.** `campaign_status` projects windows,
requests, packages, and verify attempts. A run that failed before reaching a
verify attempt — an expired grant, a missing credential, a lane mismatch —
touched none of those, so the panel showed exactly the same numbers as before
the button was pressed. `last_run` closes that gap.

## Design invariants

- **PostgreSQL stays the single source of truth.** The `sat.campaign.run`
  message carries no work item: `job_id`/`correlation_id` are the opaque
  `run_ref`, and the consumer always re-reads and re-claims the row from
  `sat_campaign_runs` before doing anything. This is the same "hint only, the
  database is truth" split already used by the `sat_requests_schedule_changed`
  NOTIFY introduced in `V8__sat_monitor_schedule.sql`, whose own comment states
  that consumers must recompute due work from PostgreSQL. Losing, duplicating,
  or coalescing a hint changes no outcome.
- **A queued run is never retried by broker policy.** The consumer catches every
  exception at the top of the claimed-run handling, writes a terminal row, and
  always acknowledges the delivery. The wake-hint handler cannot fail, so the
  `RetryPolicy`/dead-letter transitions in `queueing.py` can never re-fire a live
  SAT sequence. An expired lease becomes `abandoned`, not `queued`: re-running a
  campaign is always a new, human-requested row.
- **One active run per grant.** A partial unique index over
  `(campaign_id, grant_ref)` restricted to `queued|claimed|running` makes a
  double-clicked button, a retried request, and a crash-retry all resolve to the
  same `run_ref`.
- **Build fencing crosses the process boundary.** The panel writes the
  `commit_ref` it validated against into the row; the consumer compares it to
  its own `CFDI_VAULT_COMMIT_REF` and records `commit-ref-mismatch` without
  contacting SAT if they differ. Two processes can now be at different builds,
  which was not possible when the run happened in-process.
- **Only the consumer carries the live gate.** `CFDI_VAULT_LIVE_WORKER_ENABLED`,
  `CFDI_VAULT_COMMIT_REF`, and the remaining live-worker variables belong to the
  campaign-run consumer process. The panel/API process leaves the live gate
  unset, so any accidental call into the old synchronous path fails closed
  through `run_without_adapter` instead of contacting SAT.

## Explicitly unaffected

- **Docker Compose is untouched.** No new service, no edits to
  `docker-compose.yml`, and `ALLOWED_DOCKER_SERVICES` in the panel API keeps its
  existing `postgres`, `rabbitmq`, `redis`, `worker` allow-list. The `worker`
  container keeps running its unrelated `--queue all` loop; `worker.py` now
  excludes `SAT_CAMPAIGN_RUN` from that fan-out precisely so the fake-SAT
  container can never claim or acknowledge a live campaign-run hint.
- **The frontend is untouched.** Consuming `202` and `last_run` in `web/` is a
  separate change.

## Supersedes / amends ADR 0004

ADR 0004 remains in force. Three of its sentences change:

- Architecture, backend: *"process-local, imports the existing `cfdi_vault`
  package directly — no HTTP hop to anywhere else, no new persistence."*
  **Amended**: the panel API adds exactly one durable table,
  `sat_campaign_runs`, as the handoff between the panel and the campaign-run
  consumer. This is not a second source of truth — it is PostgreSQL, the same
  source of truth ADR 0002 and ADR 0004 already name — but the claim that the
  panel introduces *no* new persistence no longer holds.

- Decision: *"the API is a thin adapter over the same functions already used by
  the CLI and the Tkinter wizard."* **Amended with a clause**: the API stays a
  thin adapter, but for `run` it is now a thin *enqueueing* adapter; the same
  function the CLI calls (`run_from_environment`) is invoked unchanged by the
  new host-only consumer process, `cfdi_vault.sat_campaign_run_service`, rather
  than by the request handler. No SAT logic moved and none was reimplemented.

- Security contract: *"the 15-minute watcher already proved that 'reduce
  friction' here easily turns into 'nobody notices a live SAT authorization got
  renewed unattended.'"* **Extended**: the same reasoning now binds the queue.
  Making a run asynchronous must not make it *automatic*. A queued run must
  never be re-delivered by generic broker retry policy, re-claimed after a lease
  expires, or restarted by any supervisor. Every terminal state — including
  `abandoned` — requires a human to request a new run.

Everything else in ADR 0004 stands unchanged: loopback-only bind, the
Origin/Referer check on this `POST`, no `sat campaign create|authorize`
endpoint, redacted status output, and the scoped Docker allow-list.

## Deliberate scope boundaries

These are decisions, not oversights:

- **The CLI stays fully synchronous.** `adapters/cli/sat_campaign_run.py` is
  unchanged and gains no queue option. An operator running the CLI is already at
  a terminal on the host with the credential store available, and wants the
  result in front of them. Whether the CLI run path is eventually deprecated in
  favour of the queue is a separate future ADR.
- **The consumer is started by hand.** `cfdi-vault-campaign-run-worker` is
  launched manually by the operator, in the same spirit as `cfdi-vault-webapi`.
  No auto-start, service registration, or panel-launched supervisor is built
  here. The operational consequence is explicit: **if nobody starts the
  consumer, a queued run is never executed** — it becomes `abandoned` once its
  lease expires, and `last_run` shows that. A panel that schedules or launches
  this process is a separate future design.

## Consequences

- New Flyway migration `V9__sat_campaign_runs.sql` with a terminal-immutability
  trigger modelled on `ledger_jobs_validate_transition` (`V6`), a partial unique
  index for the active run, and partial indexes for the claim and reaper scans.
- New `QueueName.SAT_CAMPAIGN_RUN` with **no** matching `WorkerJobType`: the
  wake hint is deliberately outside the typed worker-job contract, so it cannot
  be routed through `WorkerJobEnvelope` and the generic worker pipeline.
- New `SAT_CAMPAIGN_RUN_LEASE_SECONDS` (default `900`, minimum `60`, resolved by
  `runtime_settings` alongside `SAT_MONITOR_WATCHDOG_SECONDS`) plus the
  consumer's own `SAT_CAMPAIGN_RUN_WORKER_ENABLED`, `_POLL_SECONDS`,
  `_MAX_HINTS`, and `_WORKER_REF`.
- The panel's `run` button becomes non-blocking, which means the panel must
  poll `last_run` to tell the operator what happened. Until `web/` does that,
  the operator reads it from `sat campaign status`.
