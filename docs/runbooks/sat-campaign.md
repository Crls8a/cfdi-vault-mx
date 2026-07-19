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

`campaign run` is a one-shot monitor wake. In the PostgreSQL migration phase it
only inspects persisted due work and returns `campaign-adapter-required` when
an external adapter would be required; it never contacts SAT. Once the
human-gated adapter is enabled, it may contact SAT only for a persisted
recovery whose `next_check_at` has expired, and exits without contact otherwise.
A global lock returns `busy` instead of allowing concurrent SAT calls. The
scheduler wakes every five minutes, but the persisted due time remains the only
contact authority.

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
| `campaign create`, `authorize`, `status` | `src/cfdi_vault/adapters/cli/sat_campaign_*.py` → `sat_campaign_db_cli.py` | Campaign, windows, grants, and sanitized aggregates are PostgreSQL-backed. |
| `campaign run` | `sat_campaign_run.py` → `run_from_environment()` | A grant and commit-bound campaign are validated before any live factory is built. |
| Select due work | `SatCampaignRepository.claim_due_operations()` | `next_check_at` must be due and `service_window_expires_at` must still be future; `FOR UPDATE SKIP LOCKED` creates the VERIFY claim. |
| Prevent replacement requests | `SatCampaignRunner._submit_windows()` + `count_open_operations()` | Persisted open requests and unbound submit claims consume the two-operation ceiling. |
| Contact and classify SAT | `SatCampaignRunner._verify_claim()` | One sanitized `sat_verify_attempts` row is appended per claim; `5000`, `5004`, expiry, timeout, and package outcomes remain categorized. |
| Schedule the next wake | `next_local_check()` and `_merge_next_check()` | The next minimum interval starts at the actual run time; a later SAT-provided time wins. Due is not the same as expired. |
| Download and hand off a package | `_download_packages()` → `sat_campaign_artifacts.py` → `sat_campaign_download_effects.py` | ZIP bytes stay in external storage; PostgreSQL stores references and validation state; RabbitMQ carries only an opaque job reference. |
| Parse in a worker | `recovery_service.process_queue_message_for_worker()` and `worker.py` | `cfdi.parse.metadata` is acknowledged idempotently and updates durable progress; Redis is only transient heartbeat/state. |

The schema that supports this path is `db/migration/V3__sat_campaign_state.sql`
plus `V4__sat_claim_grants.sql`. The source-policy and package-safety boundaries
are documented in `docs/sat-download/async-verify-scheduler.md` and
`docs/api/sat-v15-public-api.md`. Real SAT state and artifacts are intentionally
not copied into this repository; only sanitized aggregates may be documented.
