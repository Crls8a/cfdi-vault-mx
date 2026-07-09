# Architecture execution plan

This plan turns the responsibility map into tomorrow-sized and sprint-sized work units. It
keeps branches reviewable, assigns a worktree per isolated stream, and makes dependencies visible
before agents start coding.

## Decision

Use `dev` as the only integration base. Each implementation stream gets a branch and, when it is
parallel or risky, a dedicated git worktree. Dependent work waits for its base branch to merge into
`dev` unless an explicit stacked branch is approved.

## Quick path for every work unit

1. Start from updated `dev`.
2. Create a branch named by work type: `feature/...`, `fix/...`, `docs/...`, `test/...`, or `chore/...`.
3. Use a git worktree for parallel/isolated work.
4. Keep docs and tests with the work unit.
5. Run targeted tests, full tests when runtime changes, scanners, and `git diff --check`.
6. Open/merge PR to `dev`, then remove the worktree only when safe.

Use [Implementation master plan](implementation-master-plan.md) for the detailed agent roster,
phase-by-phase sprint plan, fix lane, integration rhythm, and library/package track.

## Gantt-style dependency map

```mermaid
gantt
    title CFDI Vault MX execution map from dev
    dateFormat  YYYY-MM-DD
    axisFormat  %d/%m

    section Architecture docs
    Module responsibilities and execution map :done, docs-map, 2026-07-09, 1d

    section Infrastructure foundation
    MinIO Docker profile and docs        :done, minio-profile, after docs-map, 1d
    RabbitMQ retry and DLQ policy        :queue, after docs-map, 2d
    Worker job envelope and audit        :queue-worker, after queue db, 2d
    Redis progress locks heartbeat       :redis, after docs-map, 2d
    Durable progress read model          :redis-read, after redis queue-worker, 2d
    PostgreSQL evidence/index gaps       :db, after docs-map, 2d
    Storage object-key contract          :storage, after minio-profile, 2d
    MinIO adapter validation             :storage-minio, after storage, 2d

    section API and ingestion
    FastAPI ingestion contract           :api-contract, after storage queue redis db, 1d
    FastAPI enqueue endpoint             :api-impl, after api-contract queue-worker redis-read, 2d

    section Parsing
    Parser version matrix                :parser-plan, after docs-map, 1d
    CFDI 3.2/3.3/4.0 extractors          :parser-impl, after parser-plan, 3d

    section SAT library
    SAT v1.5 public API candidates       :lib-plan, after docs-map, 1d
    SAT facade over ports                :lib-facade, after lib-plan, 2d

    section End to end
    Fake SAT package ingestion E2E       :e2e, after queue redis db api-impl parser-impl, 3d
    CLI progress search show             :cli, after e2e, 2d
```

## Parallel vs sequential work

| Workstream | Can run in parallel with | Must wait for | Reason |
|---|---|---|---|
| RabbitMQ retry/DLQ | Redis, DB, parser plan, SAT library plan | Responsibility docs | It owns queue semantics and does not need API implementation first. |
| Redis progress/locks/heartbeat | RabbitMQ, DB, parser plan | Responsibility docs | It owns transient state and worker observability. |
| PostgreSQL evidence/index gaps | Queue, Redis, parser plan | Responsibility docs | It defines durable state needed by later API/E2E. |
| Storage object-key contract | Queue, Redis, parser plan | Responsibility docs and optional Docker MinIO profile | STOR-004A establishes filesystem parity and stable references without changing app/worker runtime. |
| Optional MinIO adapter | Queue/worker and Redis read-model work | STOR-004A contract tests | STOR-004B proves adapter parity while MinIO remains outside app/worker runtime. |
| FastAPI ingestion contract | Parser plan, SAT library plan | STOR-004A filesystem parity, QUEUE-003 reliability, DB-005 indexed evidence, CACHE-002 progress/lock/heartbeat semantics | API payload must use valid evidence references and expose only consistent processing state. |
| Parser version matrix | Queue, Redis, DB | Responsibility docs | Extractor design can progress before API implementation. |
| Parser implementation | SAT library facade | Parser matrix and evidence schema | Writes parser status and accounting payloads. |
| SAT v1.5 library facade | Queue/Redis work | Domain/results/ports promoted | Library should stay runtime-agnostic. |
| Fake SAT E2E | None, it is integration work | The same storage, queue, PostgreSQL, and Redis gates as API, plus the API and parser baseline | It proves the whole chain and should not start early. |
| CLI progress/search/show | Docs polish | Fake E2E and DB/query state | CLI should display real states, not invented placeholders. |

## Work unit backlog

| ID | Branch | Type | Owner role | Scope | Depends on | Acceptance |
|---|---|---|---|---|---|---|
| ARCH-EXEC-001 | `docs/architecture-execution-map` | docs/infra | Architecture | Module responsibilities, MinIO boundary/profile, Gantt/worktree plan. | `dev` | Docs scanners, Compose config, and markdown diff check pass. |
| PLAN-EXEC-001 | `docs/architecture-execution-map` | docs | Architecture / PM | Implementation master plan with agent roster, sprint phases, feature/fix lanes, integration gates, and library/package track. | ARCH-EXEC-001 | Plan links from planning README and can be used as the next-session execution checklist. |
| QUEUE-003 | `feature/rabbitmq-retry-dlq-worker` | feature | Queue/Worker | Exchanges/routing, retry count, DLQ, worker retry events. | ARCH-EXEC-001 | Queue tests prove retry and DLQ without raw payloads. |
| QUEUE-004 | `feature/worker-job-envelope` | feature | Queue/Worker | Typed reference-only envelope and durable queue-event state. | QUEUE-003, DB-005 | Worker tests prove retryable/non-retryable behavior and queue audit rows. |
| CACHE-002 | `feature/redis-progress-locks-heartbeat` | feature | Queue/Worker | Progress keys, locks, heartbeat, stale worker reporting. | ARCH-EXEC-001 | Redis adapter tests and worker status tests pass. |
| CACHE-003 | `feature/worker-progress-read-model` | feature | Queue/Worker | Durable progress read model backed by transient Redis observations. | CACHE-002, QUEUE-004 | API/CLI status remains queryable without treating Redis as recovery truth. |
| DB-005 | `feature/postgres-evidence-indexes` | feature | Data | Evidence metadata, parser status, search indexes as Flyway migrations. | ARCH-EXEC-001 | Migration/repository tests pass; no runtime create-all shortcut. |
| STOR-004A | `feature/storage-object-key-contract` | feature | Storage | Storage port object keys and filesystem adapter parity. | ARCH-EXEC-001 | Filesystem contract tests pass; app/worker continue using filesystem storage. |
| STOR-004B | `feature/storage-object-minio-adapter` | feature | Storage | MinIO adapter behind the optional lab profile. | STOR-004A | Adapter contract tests pass; MinIO remains optional and is not wired into app/worker runtime. |
| API-003A | `feature/api-ingestion-contract` | feature | API | Request/response contract for stored references. | STOR-004A, QUEUE-003, DB-005, CACHE-002 | Tests reject raw XML/ZIP/secrets and accept storage refs only after all Phase 1 runtime contracts are stable. |
| API-003B | `feature/api-ingestion-endpoint` | feature | API | FastAPI endpoint validates refs and enqueues `cfdi.parse.xml`. | API-003A, QUEUE-004, CACHE-003 | Endpoint tests prove no inline parser/bulk DB load. |
| PARSER-005A | `feature/parser-version-matrix` | feature | Parser | Matrix for CFDI 3.2/3.3/4.0, unknown, payments, payroll. | ARCH-EXEC-001 | Fixture matrix docs/tests define complete vs partial. |
| PARSER-005B | `feature/cfdi-version-detector` | feature | Parser | Version detector, extractors, complement registry, and partial/unknown behavior. | PARSER-005A, DB-005 | Parser tests store version/status/accounting payload. |
| LIB-001 | `feature/sat-v15-public-api-contract` | feature/docs | Library | Supported imports, errors, ports, result models. | ARCH-EXEC-001 | Import smoke and public API docs list supported names. |
| LIB-002 | `feature/sat-v15-library-facade` | feature | Library | `cfdi_vault.sat_download` facade over injected ports. | LIB-001 | Facade works with fake/offline adapters, no runtime dependency. |
| PIPE-003 | `feature/fake-sat-ingestion-e2e` | feature | Application | Fake SAT package to storage to API/queue to parser to DB to reconciliation. | STOR-004A, QUEUE-004, CACHE-003, DB-005, API-003B, PARSER-005B | E2E proves reprocessability and operator-visible status after every runtime gate is stable. |
| CLI-005 | `feature/cli-progress-search-show` | feature | CLI/UX | Progress dashboard, storage locate, search/show status. | PIPE-003 | CLI tests show status without sensitive leakage. |

## Worktree plan

Keep at most three active implementation worktrees unless a final audit justifies more.

| Wave | Worktrees allowed | Branches |
|---|---:|---|
| Wave 1 | 3 | `feature/rabbitmq-retry-dlq-worker`, `feature/redis-progress-locks-heartbeat`, `feature/postgres-evidence-indexes` |
| Wave 2 | 3 | `feature/worker-job-envelope`, `feature/storage-object-key-contract`, `feature/parser-version-matrix` |
| Wave 3 | 3 | `feature/worker-progress-read-model`, `feature/cfdi-version-detector`, `feature/sat-v15-public-api-contract` |
| Wave 4 | 2 | `feature/api-ingestion-contract`, `feature/sat-v15-library-facade` |
| Wave 5 | 1 | `feature/api-ingestion-endpoint` |
| Wave 6 | 2 | `feature/fake-sat-ingestion-e2e`, `feature/storage-object-minio-adapter` |
| Wave 7 | 1 | `feature/cli-progress-search-show` |

Each worktree report must include branch, base, files changed, tests, merge status, and cleanup recommendation.

## Merge gate

- [ ] Branch is based on `dev` or explicitly stacked with documented dependency.
- [ ] PR target is `dev`.
- [ ] No unrelated branch changes are staged.
- [ ] Targeted tests pass.
- [ ] Full pytest passes for runtime changes.
- [ ] Sensitive fixture scanner passes.
- [ ] SAT context scanner passes when SAT docs/code change.
- [ ] `git diff --check` passes.
- [ ] Worktree cleanup is documented after merge.
