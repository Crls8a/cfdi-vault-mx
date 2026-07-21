# SAT program workstreams and delegation board

Use this board to assign work. A row is not started until an owner, branch,
start commit, and reviewer are recorded. A row is not accepted until its exit
evidence appears in [`daily-evidence.md`](daily-evidence.md).

## Work-unit board

| ID | Owner role | Reviewer role | Depends on | Parallel lane | Deliverable | Measurable exit |
|---|---|---|---|---|---|---|
| `SAT-PLAN-001` | QA/documentation | Integration maintainer | Current branch | Control | One status matrix reconciles plans, code, tests, and gates. | All red/amber claims point to a path and a test/evidence source. |
| `SAT-ORCH-001` | QA/documentation | Integration maintainer | `SAT-PLAN-001` | Control | Requester contract for task packets, handoffs, state transitions, and parallel dispatch. | A new task can be delegated from `orchestration.md` with owner, reviewer, dependencies, gates, evidence, and stop conditions. |
| `SAT-PREFLIGHT-001` | SAT integration | QA/documentation | `SAT-PLAN-001` | A | Human-ready checklist and exact grant for the fixed first window; Carlos provides final authorization. | Clean tree, scanners, canonical endpoints, external storage, profile, and grant all verified; no SAT contact during preflight. |
| `SAT-META-REAL-001` | SAT integration | QA/documentation | `SAT-PREFLIGHT-001` | A | Two bounded Metadata operations: received and issued, first 14-day window. | Each operation has one durable claim/request; no replacement request; sanitized category recorded. |
| `SAT-META-WAIT-001` | SAT integration | Worker/queue | `SAT-META-REAL-001` | A | Due-aware verification history up to 48 hours. | No early contact; every attempt has schedule/contact/category/next review; timeout and 5004 are categorized. |
| `SAT-TXT-WORKER-001` | Storage/security | Worker/queue | `SAT-META-WAIT-001` | A | ZIP validation, TXT extraction, opaque parse job, private inventory. | At least one real TXT is extracted outside Git and consumed once by a worker, or a categorized no-data/expired result is recorded. |
| `SAT-CFDI-REAL-001` | SAT integration | Storage/security | `SAT-TXT-WORKER-001` | A | New `cfdi-proof` grant and first eligible CFDI request/download. | ZIP and XML validation pass; worker consumes XML once; no XML request is made for cancelled/ineligible metadata. |
| `LEDGER-V5-REPO-001` | Persistence/data | Analysis/accounting | `SAT-PLAN-001` | B | Atomic transaction-scoped V5 child-row write surface and exact conflict identities. | One document maps in one short transaction; rerun is idempotent; tenant/document/evidence constraints are enforced. |
| `LEDGER-V5-MAP-001` | Persistence/data | Analysis/accounting | `LEDGER-V5-REPO-001` | B | Tenant-safe mapper plus synthetic projection fixture from projection/write intent into child ledgers. | Concepts, taxes, payments, and payroll map deterministically; related identity is omitted rather than invented; worker aggregate adapter passes. |
| `LEDGER-V5-BIND-001` | Persistence/data | Analysis/accounting | `LEDGER-V5-MAP-001` | B | Durable parent/evidence UUID binding and cross-family provenance validation. | Same-tenant mismatched UUID or related-row provenance is rejected with a fixed reason; focused regression tests pass. |
| `ANALYSIS-DB-001` | Analysis/accounting | Persistence/data | `LEDGER-V5-BIND-001` | B | **Umbrella:** coordinate the bounded PostgreSQL analysis child units; no direct implementation or SAT contact. | All required child units are `verified`, the disposable-DB integration gate passes, and the parent evidence entry links each child result. |
| `ANALYSIS-DB-FIELDS-001` | Persistence/data | Analysis/accounting | `LEDGER-V5-BIND-001` | B | **Conditional:** audit missing analytical fields and decide whether an additive schema/read-model change is required; synthetic/container only. | Field-availability matrix is accepted; records `no_schema_change` or `partial_read_model_required`, or defines one bounded additive migration before any complete report claim. |
| `ANALYSIS-DB-READ-001` | Analysis/accounting | Persistence/data | `ANALYSIS-DB-FIELDS-001` | B | V5-safe PostgreSQL read statements and redacted DTOs for tax, payment, and payroll aggregates; no SAT contact. | Reads are tenant/evidence scoped, unavailable fields are explicit, and focused disposable-DB tests pass without raw rows in output. |
| `ANALYSIS-DB-QUALITY-001` | Analysis/accounting | QA/documentation | `ANALYSIS-DB-READ-001` | B | Quality/completeness projections over metadata, XML evidence, and V5 availability; no SAT contact. | Missing XML, duplicate, conflict, and unknown categories are deterministic and exposed only as approved aggregates. |
| `ANALYSIS-DB-REPORT-001` | Analysis/accounting | QA/documentation | `ANALYSIS-DB-READ-001`, `ANALYSIS-DB-QUALITY-001` | B | Monthly, tax, payment, payroll, and quality report composition over durable rows; no SAT contact. | Reports preserve currency/period boundaries and include completeness/provenance state without inferring legal or tax outcomes. |
| `ANALYSIS-DB-INTEGRATION-001` | Persistence/data | QA/documentation | `ANALYSIS-DB-REPORT-001` | B | Parent integration gate for repositories, reads, quality, and reports against disposable PostgreSQL; no SAT contact. | Reprocessing is idempotent, tenant/provenance constraints hold, full focused analysis tests pass, and the parent can be marked `verified`. |
| `ANALYSIS-CLI-001` | Analysis/accounting | QA/documentation | `ANALYSIS-DB-INTEGRATION-001` | B | Private operator report command and sanitized status projection. | Reports include provenance/completeness and never print rows, identifiers, paths, hashes, or raw payloads. |
| `API-INGEST-001` | API/queue | Persistence/data | `SAT-TXT-WORKER-001` | D | FastAPI stored-reference contract and enqueue endpoint. | Raw XML/ZIP/secrets are rejected; valid references create one durable job without inline parsing. |
| `LEGACY-CLEAN-001` | SAT library | QA/documentation | `SAT-CFDI-REAL-001` | D | Import-graph cleanup of internal smoke/probe/backfill modules. | Public help remains unchanged, offline tests pass, and no supported path depends on the retired modules. |
| `DOC-STATUS-001` | QA/documentation | Integration maintainer | `SAT-PLAN-001` | C | Daily evidence and cross-document synchronization. | Every completed unit has a sanitized record and links to code/tests/docs; it remains non-blocking for later units. |
| `RELEASE-ALPHA-001` | Release | QA/documentation | `ANALYSIS-CLI-001` | D | Public API, consumer example, build, package, and alpha release checklist; API ingestion remains a separate decision. | Wheel installs in a clean environment; claims explicitly remain alpha/fake-offline unless separately proven. |

## Owner responsibilities

### Carlos / maintainer

- Supplies and protects the real credential outside the repository.
- Approves each live grant and the exact date/direction scope.
- Decides whether a pending, no-data, uncertain, or error result closes the
  current diagnostic.
- Accepts or rejects evidence; no agent can self-authorize SAT contact.

### SAT integration owner

- Owns `SatV15Adapter`, campaign runner, VERIFY calendar, result mapping, and
  live preflight.
- Stops on identity conflicts, endpoint overrides, signature/configuration
  errors, uncertain downloads, or third pending state.
- Does not implement accounting interpretation.

### Persistence/data owner

- Owns Flyway, SQLAlchemy repositories, V5 mapper, claims, tenant boundaries,
  and exact-key idempotency.
- Keeps network calls outside transactions.
- Produces aggregate-only read models and migration rollback evidence.

### Worker/queue owner

- Owns outbox publication, RabbitMQ routing, consumer/inbox deduplication,
  worker claims, retry categories, and Redis heartbeat.
- Ensures messages contain references only and ACK occurs after durable work.

### Storage/security owner

- Owns external artifact root, atomic writes, hash verification, ZIP safety,
  streaming extraction, XML safety, and redaction scanners.
- Verifies storage is outside the repository and container `/app`.

### Analysis/accounting owner

- Owns normalization projections, monthly/tax/payment/payroll/quality reports,
  completeness, source precedence, and currency separation.
- Never infers paid, deductible, taxable, or legal status.

### QA/documentation owner

- Owns daily evidence, status vocabulary, test matrix, scanner runs, and fresh
  review of every unit.
- Rejects documentation that calls synthetic behavior SAT evidence.

### Integration maintainer

- Owns branch base (`dev`), merge order, worktree cleanup, CI evidence, and
  final synchronization of the status matrix.

## Required handoff template

Each owner reports this compact block before handing off:

```text
work_unit=<ID>
owner_role=<role>
branch=<branch>
start_commit=<short-sha>
end_commit=<short-sha-or-none>
files=<sanitized-path-list>
tests=<command-and-result>
scanners=<sensitive/sat-context/diff/ruff>
status=<planned|in_progress|blocked|verified|accepted|inconclusive>
blocker=<fixed-category-or-none>
next_step=<one-action>
```

The handoff must not include RFCs, UUIDs, SAT IDs, SOAP, credentials, absolute
local paths, artifact/data hashes, rows, totals, ZIP/TXT/XML content, or raw
exception text. Repository-relative file paths and short Git commit SHAs are
allowed for code lineage.

## Current status snapshot — 2026-07-21

This snapshot is subordinate to the append-only evidence log. A workstream is
`verified` only when its evidence entry links the implementation, tests, and
review; `pending-authorization` means the code is ready but a human live gate
is still required.

| Status | Workstreams | Evidence or next gate |
|---|---|---|
| `verified` | `SAT-PLAN-001`, `SAT-ORCH-001`, `LEDGER-V5-REPO-001`, `LEDGER-V5-MAP-001`, `LEDGER-V5-BIND-001`, `ANALYSIS-DB-*`, `ANALYSIS-CLI-001`, `WORKER-LEDGER-BIND-001`, `WORKER-LEDGER-RUNTIME-001` | Synthetic/container gates and sanitized evidence are present. |
| `verified` | `SAT-PREFLIGHT-001` | No-contact gates pass; it does not authorize SAT. |
| `accepted` | `SAT-LIVE-HARDEN-001` | Storage/handoff readiness and submission classification are fail-closed; no SAT contact. |
| `pending-authorization` | `SAT-META-REAL-001`, `SAT-META-WAIT-001`, `SAT-TXT-WORKER-001` | Require the exact human profile, external storage, directions, dates, and grant. |
| `pending` | `SAT-CFDI-REAL-001`, `API-INGEST-001`, `LEGACY-CLEAN-001`, `RELEASE-ALPHA-001` | Depend on real Metadata/TXT evidence or a separately approved scope. |

The live evidence slots remain empty until the human gate is supplied; no
synthetic result may promote them to `verified`.
