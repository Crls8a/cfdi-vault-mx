# Product backlog

This backlog is the shared task source for the CFDI recovery library. Each item should become either a GitHub issue, a Linear/Jira ticket, or a small PR task, but the ID remains stable here.

## Quick path

1. Pick items from the next sprint target.
2. Check dependencies before assigning work.
3. Keep one owner role accountable for delivery.
4. Do not start implementation until the item meets Definition of Ready.

## Backlog

| ID | Sprint | Workstream | Title | Depends on | Owner role | Acceptance |
|---|---:|---|---|---|---|---|
| PM-001 | 0 | Planning | Accept sprint roadmap and workstream ownership | None | Product / PM | Roadmap, backlog, and board are reviewed by the team. |
| ARCH-001 | 0 | Architecture | Review foundation gate before new code | None | Architecture | Foundation checklist has no unknown blocker for Sprint 1. |
| QA-001 | 0 | QA | Define fixture policy and no-real-CFDI rule | ARCH-001 | QA | Test data policy blocks real taxpayer data, lists fixture categories, and links examples/tests provenance. |
| DOC-001 | 0 | Docs | Link planning docs from main documentation index | PM-001 | Docs | README and docs index point to planning workspace. |
| DOC-002 | 0 | Docs / Product | Document library versus reference-system boundary | PM-001 | Docs | README and docs explain the problem solved, the reusable Python library, the CLI/local reference system, and the current fake/offline boundary without implying PyPI or production readiness. |
| QA-002 | 1 | QA | Add fixture safety scanner | QA-001 | QA | A script or test blocks real-looking RFC values outside the allow-list, taxpayer names, secrets, certificates, keys, SAT credentials, and committed runtime evidence. |
| STOR-001 | 1 | Storage | Implement idempotent local storage model | ARCH-001 | Infrastructure | Metadata, packages, XML, normalized rows, and pipeline events have RFC/period local storage, SHA-256 tracking, and replay-safe idempotency rules. |
| STOR-002 | 1 | Storage | Implement package/XML evidence path builder | STOR-001 | Infrastructure | Paths are tenant, RFC, year, month, type, and UUID aware. |
| STOR-003 | 1 | Storage | Add storage manifest and growth metadata | STOR-002 | Infrastructure | Each package/XML registration records hash, size, path, and retention state. |
| CLI-001 | 1 | CLI/UX | Design `storage locate` and `storage status` commands | STOR-001 | CLI / UX | Help text and user stories describe how operators find local evidence. |
| INST-001 | 1 | Installer | Desktop onboarding for storage and e.firma references | STOR-001, INF-001 | Infrastructure | Onboarding creates/writes safe profile config, validates writable storage, validates local certificate/key shape, records certificate fingerprint and credential references only, and never stores plaintext secrets. |
| INF-001 | 1 | Infrastructure | Define safe RFC profile configuration | QA-002 | Infrastructure | Config schema supports multiple RFC profiles, storage roots, metadata-first downloads, ranges/lookback, concurrency, scheduling, certificate fingerprints, and external credential references without plaintext secrets. |
| DB-001 | 2 | Data | Introduce Flyway migration framework | STOR-003 | Data / Accounting | Database schema can be created, upgraded, and inspected repeatably from `db/migration/`. |
| DB-002 | 2 | Data | Implement operational tables | DB-001 | Data / Accounting | Tenants, credential profiles, jobs, requests, packages, queue events, signer audit, and reconciliation tables exist. |
| DB-003 | 2 | Data | Implement CFDI accounting tables | DB-001 | Data / Accounting | Documents, parties, concepts, taxes, payments, payroll, related docs, metadata ledger, and XML evidence exist. |
| DB-004 | 2 | Search | Add PostgreSQL search indexes | DB-003 | Data / Accounting | UUID, RFC, date, total, status, type, text, trigram, and JSONB indexes support v1 search. |
| QUEUE-001 | 3 | Queue/Worker | Define RabbitMQ exchanges and routing keys | ARCH-001 | Queue / Worker | Queue names, routing keys, payload contract, and DLQ are documented and implemented. |
| QUEUE-002 | 3 | Queue/Worker | Implement retry and DLQ policy | QUEUE-001 | Queue / Worker | Failed jobs retry with bounded attempts and land in dead-letter state with reason. |
| CACHE-001 | 3 | Cache | Implement Redis progress and locks | QUEUE-001 | Queue / Worker | Progress, criteria locks, rate limit state, token cache, and heartbeat keys are observable. |
| WORKER-001 | 3 | Queue/Worker | Add worker heartbeat and status reporting | CACHE-001 | Queue / Worker | CLI can show active workers and stale worker warnings. |
| API-001 | 3 | API / Ingestion | Define FastAPI ingestion boundary | STOR-003, DB-001, QUEUE-001 | API / Architecture | API contract accepts stored XML/package references, tenant/job correlation, and idempotency keys; payloads never carry raw XML, ZIP bytes, secrets, or e.firma material. |
| API-002 | 4 | API / Ingestion | Implement queued XML ingestion endpoint | API-001, QUEUE-002, DB-002 | API / Queue / Data | FastAPI validates storage references, records short PostgreSQL state, publishes ingestion jobs, and returns a correlation id without doing bulk parser/database work inline. |
| PARSER-001 | 5 | Parser | Build CFDI version detector | QA-001 | Parser | 3.2, 3.3, 4.0, and unknown XML are classified deterministically. |
| PARSER-002 | 5 | Parser | Add core CFDI parsers | PARSER-001 | Parser | Common accounting fields parse from 3.2, 3.3, and 4.0 fixtures. |
| PARSER-003 | 5 | Parser | Add complement registry baseline | PARSER-002 | Parser | Payments and payroll parse when known; unknown complements are stored raw with partial status. |
| PARSER-004 | 5 | Parser | Add retroactive fixture matrix | PARSER-003 | QA | Fixtures cover income, expense, payment, payroll, cancellation metadata, and unknown complement paths. |
| SAT-001 | 4 | SAT Integration | Expand fake SAT scenarios | QUEUE-002, PARSER-001 | SAT Integration | Fake SAT covers accepted, processing, finished, multiple packages, SAT errors, expiration, and duplicates. |
| PIPE-001 | 4 | Recovery Pipeline | Implement unified recovery orchestration | DB-003, QUEUE-002, STOR-003, SAT-001, API-001 | Architecture | One job tracks request, verify, package download, extraction, queued ingestion, PostgreSQL load, and reconciliation. |
| PIPE-002 | 4 | Recovery Pipeline | Register package and XML evidence during sync | PIPE-001 | Infrastructure | Every file has durable path, hash, size, source job, and extraction metadata. |
| REC-001 | 4 | Reconciliation | Implement metadata/XML reconciliation events | PIPE-002 | Data / Accounting | Missing XML, duplicate UUID, partial parser, and status mismatch are visible. |
| CLI-002 | 6 | CLI/UX | Add progress dashboard | WORKER-001, PIPE-001 | CLI / UX | CLI shows job progress, package counts, XML pending, errors, and worker state. |
| CLI-003 | 6 | CLI/UX | Implement search filters | DB-004 | CLI / UX | Search by UUID, RFC, name, date, total, type, status, concept text, and complement. |
| CLI-004 | 6 | CLI/UX | Implement `show`, `print`, and export polish | CLI-003 | CLI / UX | Operators can inspect, print/export, and see partial-parse warnings. |
| ERR-001 | 6 | UX / Errors | Normalize actionable error messages | CLI-002 | CLI / UX | Every common error explains what failed, why it matters, and next action. |
| SEC-001 | 7 | Security | Define credential custody and signer policy | ARCH-001 | Security | No password/e.firma is stored by default; local-secure path is explicitly designed. |
| SAT-002 | 7 | SAT Integration | Implement signer port and SOAP client boundary | SEC-001 | SAT Integration | Live SAT code is opt-in, typed, tested with fakes, and disabled in CI. |
| SAT-003 | 7 | SAT Integration | Add manual live SAT verification runbook | SAT-002 | SAT Integration | A maintainer can run live checks safely outside CI with documented prerequisites. |
| REL-001 | 8 | Release | Prepare open-source contribution guide | Sprints 1-7 | Docs | Contributors know setup, tests, fixture policy, security boundaries, and review rules. |
| REL-002 | 8 | Release | Build release candidate checklist | Sprints 1-7 | Product / PM | Installer, Docker Compose, docs, tests, examples, and known limits are verified. |
| REL-003 | 8 | Release / Packaging | Prepare PyPI package metadata and public API contract | REL-002 | Release | `pyproject.toml`, README, license, classifiers, URLs, supported imports, and unsupported/internal modules are release-reviewed. |
| REL-004 | 8 | Release / Packaging | Publish alpha through TestPyPI and PyPI Trusted Publishing | REL-003 | Release | Build artifacts pass scanner, tests, `twine check`, clean-wheel install, TestPyPI smoke, and PyPI Trusted Publishing without long-lived tokens. |
| GOV-001 | Follow-up | Governance | Clarify solo-maintainer lightweight governance policy | None | Product / PM | Documentation explains when issues are required, when Sprint Packets are enough, and which PR/CI/security gates are always mandatory. |
| DEVX-001 | Follow-up | DevEx | Normalize repository line endings | None | DevEx | CRLF/LF warnings are resolved with a dedicated `.gitattributes`/formatting pass, without mixing into feature commits. |
| ARCH-EXEC-001 | Next | Architecture | Document module responsibilities and execution map | None | Architecture | Module responsibilities, Gantt/worktree execution plan, optional MinIO Docker profile, parser ownership, and merge gates are documented. |
| PLAN-EXEC-001 | Next | Planning | Publish implementation master plan | ARCH-EXEC-001 | Architecture / PM | Agent roles, sprint phases, feature branches, fix lane, integration gates, and library/package tasks are documented in one execution presentation. |
| STOR-004A | Next | Storage | Define object-key storage contract and filesystem parity | ARCH-EXEC-001 | Storage | Storage port supports deterministic object keys and the filesystem adapter retains parity; MinIO is not wired into app/worker runtime. |
| STOR-004B | Phase 2 | Storage | Implement optional MinIO storage adapter | STOR-004A | Storage | MinIO adapter passes the storage contract tests but remains optional and disconnected from app/worker runtime. |
| QUEUE-003 | Next | Queue/Worker | Implement RabbitMQ retry and DLQ policy | ARCH-EXEC-001 | Queue / Worker | Retry attempts, routing, dead-letter state, and PostgreSQL audit events are tested. |
| CACHE-002 | Next | Cache / Worker | Implement Redis progress, locks, and heartbeat | ARCH-EXEC-001 | Queue / Worker | Progress, lock, heartbeat, and stale-worker behavior are observable and tested. |
| DB-005 | Next | Data | Add PostgreSQL evidence metadata and indexes | ARCH-EXEC-001 | Data / Accounting | Stored evidence references, parser status, and reconciliation/search state are durably queryable. |
| QUEUE-004 | Next | Queue/Worker | Implement typed worker job envelope | QUEUE-003, DB-005 | Queue / Worker | Worker retry semantics and durable queue-event state use a reference-only envelope. |
| CACHE-003 | Next | Cache / Worker | Add durable progress read model | CACHE-002, QUEUE-004 | Queue / Worker | API/CLI can query progress while Redis remains transient and stale workers remain observable. |
| API-003A | Next | API / Ingestion | Define stored-reference ingestion API contract | STOR-004A, QUEUE-003, DB-005, CACHE-002 | API / Architecture | Contract accepts storage references only after filesystem parity, queue reliability, indexed evidence, and progress/lock/heartbeat semantics are proven. |
| API-003B | Next | API / Ingestion | Implement queued XML ingestion endpoint | API-003A, QUEUE-004, CACHE-003 | API / Queue | FastAPI rejects raw XML/ZIP/secrets, enqueues `cfdi.parse.xml`, and does no parser/database bulk work inline. |
| PARSER-005 | Next | Parser | Implement version-specific CFDI extraction plan | ARCH-EXEC-001 | Parser | CFDI 3.2, 3.3, 4.0, unknown, payments, payroll, and partial parser behavior are covered by fixtures/tests. |
| LIB-005 | Next | Release / Library | Define SAT v1.5 Python library facade plan | ARCH-EXEC-001 | Release / SAT | Supported imports, errors, ports, fake adapters, and future `cfdi_vault.sat_download` facade are documented and import-smoked. |
| PIPE-003 | Next | Recovery Pipeline | Prove fake SAT package-to-ingestion E2E | STOR-004B, QUEUE-004, CACHE-003, DB-005, API-003B, PARSER-005 | Architecture | Fake SAT flow starts only after storage, queue, PostgreSQL evidence, and Redis progress gates; it stores evidence, enqueues parsing, loads PostgreSQL, reconciles, and exposes operator status. |

## Backlog hygiene

- Keep backlog IDs stable.
- Split items that cannot be reviewed in one focused PR.
- Do not mark an item Accepted without evidence.
- Add new ambiguity to `docs/foundation/open-questions.md` before coding around it.

## Next step

Move selected items into [Team board](team-board.md) at sprint planning.
