# Daily execution evidence

This file is an append-only, sanitized work log. It records implementation and
test evidence, not raw SAT data. A real SAT entry may contain only the window,
direction, attempt count, category, validation booleans, job counts, and the
commit/grant lineage needed for audit. Never add rows, identifiers, payloads,
paths, hashes, credentials, or raw errors.

## How to add an entry

Append one block after a work unit or meaningful working day. Do not rewrite an
older result; add a correction entry that points to the original observation.

```text
### YYYY-MM-DD — <evidence-id> — <work-unit>

- owner_role: <role>
- branch_commit: <short commit>
- scope: <synthetic | container | live-preflight | live-SAT>
- action: <one sentence>
- evidence: <tests, scanner, Compose, or sanitized SAT aggregate>
- result: <confirmed | refuted | inconclusive | blocked>
- status: <planned | in_progress | blocked | verified | accepted>
- blocker: <fixed category or none>
- next_step: <one action>
```

## Initial baseline

### 2026-07-21 — E-2026-07-21-001 — SAT-PLAN-001

- owner_role: QA/documentation
- branch_commit: `f97e6ae`
- scope: synthetic
- action: Reviewed the current plans, source tree, Compose services, tests, and SAT runbook against the proposed feature set.
- evidence: V1–V7 migrations, campaign CLI, worker/outbox, analysis modules, and planning documents inspected; repository tree clean.
- result: confirmed
- status: verified
- blocker: documentation status is distributed across historical plans
- next_step: publish this program matrix and assign the first work units

### 2026-07-21 — E-2026-07-21-002 — V6/V7 durable runtime

- owner_role: worker/queue + persistence/data
- branch_commit: `aee0d23`
- scope: container
- action: Ran disposable PostgreSQL/Flyway/RabbitMQ/Redis verification with synthetic references.
- evidence: Flyway V1–V7 applied; 43 focused persistence/consumer/migration tests passed; duplicate inbox delivery was deduplicated; no SAT contact.
- result: confirmed
- status: accepted
- blocker: none for the synthetic durable runtime
- next_step: keep this gate closed while preparing the human live preflight

### 2026-07-21 — E-2026-07-21-003 — repository quality baseline

- owner_role: QA/documentation
- branch_commit: `f97e6ae`
- scope: synthetic
- action: Cleared the repository Ruff baseline and reran safety gates.
- evidence: repository-wide Ruff passed; full suite `2371 passed, 88 skipped`; sensitive-fixture and SAT-context scanners passed; Compose config and diff check passed.
- result: confirmed
- status: verified
- blocker: legacy CLI wildcard imports retain ten exact per-file compatibility exceptions
- next_step: do not mix legacy-shim cleanup with the first live SAT request

## Live evidence slots

The following slots remain empty until Carlos authorizes the exact run. An
empty slot is not a failure and must not be filled with synthetic output.

| Evidence ID | Work unit | Required sanitized result | Current status |
|---|---|---|---|
| `E-LIVE-META-RECEIVED-001` | `SAT-META-REAL-001` | Window, attempts, category, `zip_valid`, `txt_valid`, package/job counts. | `planned` |
| `E-LIVE-META-ISSUED-001` | `SAT-META-REAL-001` | Window, attempts, category, `zip_valid`, `txt_valid`, package/job counts. | `planned` |
| `E-LIVE-CFDI-001` | `SAT-CFDI-REAL-001` | Window, attempts, category, `zip_valid`, `xml_valid`, package/job counts. | `planned` |

## Review rule

At each review, compare this log with [`master-plan.md`](master-plan.md),
[`workstreams.md`](workstreams.md), the current commit, and the tests. If a
plan says `implemented` but this log has no matching code/test evidence, mark
the plan `inconclusive` until corrected.
