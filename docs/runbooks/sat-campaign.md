# SAT campaign runbook

The productive SAT v1.5 campaign interface is:
```text
cfdi-vault sat campaign create --profile <profile>
cfdi-vault sat campaign authorize --profile <profile> --campaign-ref <ref> ...
cfdi-vault sat campaign run --profile <profile> --campaign-ref <ref> --grant <grant>
cfdi-vault sat campaign status --profile <profile> --campaign-ref <ref>
```

These four commands are **PostgreSQL-only**. `DATABASE_URL` is required for
all four commands; `create`, `authorize`, and `run` also require the current
`CFDI_VAULT_COMMIT_REF` for commit-bound state. If PostgreSQL is unavailable,
the command fails closed instead of reading or writing the legacy private JSON
state. JSON files remain available only to the explicit legacy importer and are
never a campaign CLI source of truth.

`campaign run` is a one-shot monitor wake. With the live worker disabled it
fails closed before any SAT side effect. With the human-gated adapter enabled,
it may submit an authorized `planned` window or verify a persisted request whose
`next_check_at` is due, subject to the two-operation ceiling. It exits without
contact otherwise. A global lock returns `busy` instead of allowing concurrent
SAT calls. The scheduler wakes every five minutes, but the persisted due time
remains the only contact authority. A pending, submitted, or uncertain request
is never replaced automatically.

The runner's sanitized result contains these operator-facing fields:

| Field | Meaning |
|---|---|
| `status` | `no_due_operations`, `processed`, `busy`, or `error`. |
| `contacted_count` | Number of VERIFY calls made by this one-shot run. |
| `next_check_at` | Earliest persisted next review, or `None`; this is not the 48-hour expiry. |
| `categories` / `submission_categories` | Counts of categorized VERIFY/submission outcomes. |
| `package_count` | Packages handed to external artifact storage during this run. |

`status` is local and read-only. It does not authenticate, contact SAT, verify a
request, or download a package. It loads the persisted campaign and counts only
Metadata recoveries whose profile, work criteria, opaque recovery reference, and
campaign provenance match the manifest exactly.

The output contains the opaque `campaign_ref`, manifest counters, total VERIFY
attempts, the earliest due `next_check_at`, aggregate package, valid ZIP, and
extracted TXT counts, plus `verify_history_count`, `last_verify_result`, and
`service_window_state`. The last field is `legacy` for the currently accepted
legacy request, `active` for a new 48-hour window, and `exceeded` after the local
window closes. An empty `next_check_at` means no bound recovery has a scheduled
verification.

The Compose worker publishes only transient, redacted lifecycle observations
to Redis: `worker_started`, `worker_heartbeat`, `worker_idle`, and
`worker_stopped`. Each event is keyed by the opaque worker reference and
expires with the heartbeat TTL. Redis/heartbeat publication is best effort and
its failure does not stop queue processing or turn successful work into a
retry/dead-letter result; claims, results, inbox dedupe, and outbox state remain
in PostgreSQL. Legacy process-local recovery may appear stale while Redis is
unavailable, so its operational view must not override durable V6/V7 state.

## Durable outbox publisher

`ledger-publisher` is a separate Compose process for the producer handoff:

```text
producer transaction -> ledger_jobs + ledger_outbox -> ledger-publisher -> RabbitMQ -> worker
```

The process resolves only `DATABASE_URL`, `RABBITMQ_URL`, and bounded
`LEDGER_OUTBOX_*` settings. PostgreSQL remains the source of truth; RabbitMQ
receives the existing reference-only envelope. The publisher never constructs a
SAT adapter, reads credentials, opens artifact storage, or sends package bytes.
It depends on healthy PostgreSQL/RabbitMQ and successful Flyway completion, but
does not depend on Redis or the worker container.

The Compose gate `LEDGER_OUTBOX_ENABLED` defaults to `0`, so a normal local
stack cannot publish queued work accidentally. Set it to `1` only after the
operator has reviewed the commit and wants the service enabled. `--once` drains
one bounded batch; Compose uses `--loop`, which wakes at
`LEDGER_OUTBOX_POLL_SECONDS` and publishes at most `LEDGER_OUTBOX_MAX_EVENTS`
rows per pass. A restart simply reclaims expired durable leases; it does not
need local state and does not contact SAT.

An unconfirmed or ambiguous broker result is recorded as retryable `failed`
with the fixed reason `publish_uncertain`. The next due attempt is scheduled
after **5 seconds**, then **30 seconds**, then every **5 minutes**. It remains
retryable indefinitely because the broker may have accepted the message before
confirmation was lost; `ledger_inbox` is the durable dedupe boundary for that
at-least-once delivery.
An `invalid_reference` envelope is known-bad before broker I/O and is fenced
immediately as terminal `uncertain`; it is never retried automatically.

Runtime output is limited to `status`, counts, and fixed reason codes. Missing
or malformed configuration produces a sanitized error and no broker contact;
raw connection errors are never printed.

The RabbitMQ adapter follows the installed Pika confirm contract: an explicit
negative result or exception is a failure, while Pika's `None` return after a
successful confirmed publish is accepted. This is covered by a synthetic
broker run; it does not contact SAT.

The command never prints RFCs, SAT request/package identifiers, work or recovery
references, dates, hashes, rows, or storage paths. Missing or mismatched bound
recovery state fails closed with `campaign-status-recovery-invalid`. Correct the
private local state lineage before running the campaign again; do not replace a
pending SAT request.

## First real Metadata proof

This is the only SAT-facing sequence authorized for the first proof. It uses
two 14-day windows only: `received` and `issued`, both from `2026-01-01` to
`2026-01-14`. It is not a smoke, probe, diagnostic, or manual-recovery path.

Before the human gate, verify that the checkout is clean, the commit reference
matches the campaign, PostgreSQL/Flyway/RabbitMQ/Redis are healthy, and the
configured artifact root is external to `/app` and the repository. Keep
`SAT_MONITOR_ENABLED=0`; the operator runs one-shot commands explicitly.

The live process must set `CFDI_VAULT_LIVE_WORKER_ENABLED=1`,
`CFDI_VAULT_COMMIT_REF`, `CFDI_VAULT_SCANNER_PASSED=1`,
`CFDI_VAULT_REPO_CLEAN=1`, `DATABASE_URL`, and the exact campaign grant. The
two preflight values are written only after the local scanner and clean-tree
checks pass for the exact commit; the runtime refuses to construct a SAT
adapter when either is absent. SAT endpoint override variables must be absent
so the v1.5 canonical endpoints are used. Credentials remain in the local
profile/credential provider and are never placed in the environment, repository,
or queue message.

Run the following after explicit human authorization, replacing only opaque
local references returned by the commands:

```text
cfdi-vault sat campaign create --profile <profile>
cfdi-vault sat campaign authorize --profile <profile> --campaign-ref <campaign-ref> --phase metadata-proof --expires-days 14 --reason <reason>
cfdi-vault sat campaign run --profile <profile> --campaign-ref <campaign-ref> --grant <grant-ref>
```

Wake `campaign run` at 5 minutes, 15 minutes, 30 minutes, and 1 hour, then
only when the persisted `next_check_at` is due. A pending request remains the
same request for up to 48 hours; no replacement request is created. If a ZIP
arrives, the runner stores it once outside PostgreSQL, validates it, publishes
only an opaque parsing reference, and the worker consumes `cfdi.parse.metadata`.
Re-delivery of that reference must be acknowledged as a duplicate. Do not
create the `cfdi-proof` grant until a real TXT has been processed successfully.

The two-operation ceiling counts persisted requests in `submitted`,
`waiting_verify`, `package`, or `uncertain` state, as well as an unbound submit
claim. A later one-shot wake must stop before selecting another planned
window whenever the ceiling is occupied; an expired or uncertain request is
never replaced automatically.

## Code traceability

The runbook maps to the implementation below. This is the shortest path for a
human reviewer to follow one operation from the CLI to PostgreSQL and back:

| Runbook step | Implementation | Durable contract |
|---|---|---|
| `campaign create`, `authorize`, `status` | `src/cfdi_vault/adapters/cli/sat_campaign.py`, `sat_campaign_authorize.py` → `sat_campaign_db_cli.py` | Campaign, windows, grants, and sanitized aggregates are PostgreSQL-backed. |
| `campaign run` | `sat_campaign_run.py` → `sat_campaign_db_cli.py::run_from_environment()` | A grant and commit-bound campaign are validated before any live factory is built. |
| Select due work | `SatCampaignRepository.claim_due_operations()` | `next_check_at` must be due and `service_window_expires_at` must still be future; `FOR UPDATE SKIP LOCKED` creates the VERIFY claim. |
| Prevent replacement requests | `SatCampaignRunner._submit_windows()` + `count_open_operations()` | Persisted open requests and unbound submit claims consume the two-operation ceiling. |
| Contact and classify SAT | `SatCampaignRunner._verify_claim()` | One sanitized `sat_verify_attempts` row is appended per claim; `5000`, `5004`, expiry, timeout, and package outcomes remain categorized. |
| Schedule the next wake | `next_local_check()` and `_merge_next_check()` | The next minimum interval starts at the actual run time; a later SAT-provided time wins. Due is not the same as expired. |
| Download and hand off a package | `_download_packages()` → `sat_campaign_artifacts.py` → `sat_campaign_download_effects.py` → `ledger_outbox_publisher.py` | ZIP bytes stay in external storage; PostgreSQL V6/V7 stores job, claim, outbox, inbox, and artifact references; RabbitMQ carries only an opaque reference envelope. |
| Parse in a worker | `ledger_job_consumer.py` → `ledger_job_dispatch_store.py` → `accounting_ledger_worker.py` | The consumer hydrates metadata from PostgreSQL, fences claims, acknowledges only after durable completion, and retries in-flight/stale transitions; Redis is transient heartbeat/lease state. |

The campaign schema starts at `db/migration/V3__sat_campaign_state.sql` and
`V4__sat_claim_grants.sql`; durable worker handoff is added by
`V6__ledger_jobs_outbox.sql` and `V7__ledger_outbox_fencing.sql`. The source-policy and package-safety boundaries
are documented in `docs/sat-download/async-verify-scheduler.md` and
`docs/api/sat-v15-public-api.md`. Real SAT state and artifacts are intentionally
not copied into this repository; only sanitized aggregates may be documented.
