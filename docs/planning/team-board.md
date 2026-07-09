# Team board

This board is the lightweight sprint tracker. It can be edited directly in Markdown or mirrored into GitHub Projects, Linear, Jira, or Notion.

## Quick path

1. Copy selected backlog items into the active sprint board.
2. Keep each item in one status column.
3. Add owner initials only when the person accepts the work.
4. Move blocked items with a short blocker note.

## Board columns

| Column | Meaning |
|---|---|
| Ready | Meets Definition of Ready and can be started. |
| In progress | An owner is actively working on it. |
| In review | Awaiting doc, code, architecture, or QA review. |
| Blocked | Cannot progress without a decision, dependency, or environment fix. |
| Accepted | Meets Definition of Done and sprint acceptance. |

## Active sprint template

| Status | ID | Title | Owner | Blocker / next action |
|---|---|---|---|---|
| Ready |  |  |  |  |
| In progress |  |  |  |  |
| In review |  |  |  |  |
| Blocked |  |  |  |  |
| Accepted |  |  |  |  |

## Active sprint: Sprint 0

| Status | ID | Title | Owner | Blocker / next action |
|---|---|---|---|---|
| In review | PM-001 | Accept sprint roadmap and workstream ownership | Sprint lead / Product | Review agent findings and decide Sprint 0 outcome. |
| In review | ARCH-001 | Review foundation gate before new code | Architecture reviewer | No Sprint 1 architecture blocker found; review missing decisions for Sprint 1 scope. |
| In review | QA-001 | Define fixture policy and no-real-CFDI rule | QA / fixture reviewer | Fixture policy added; review before accepting. |
| In review | DOC-001 | Link planning docs from main documentation index | PM / docs reviewer | Verify navigation from README and docs index. |

## Sprint 0 candidate board

| Status | ID | Title | Owner role | Blocker / next action |
|---|---|---|---|---|
| Ready | PM-001 | Accept sprint roadmap and workstream ownership | Product / PM | Review planning docs with team. |
| Ready | ARCH-001 | Review foundation gate before new code | Architecture | Confirm no Sprint 1 blocker remains. |
| Ready | QA-001 | Define fixture policy and no-real-CFDI rule | QA | Align with security model and examples folder. |
| Ready | DOC-001 | Link planning docs from main documentation index | Docs | Verify README links after this planning change. |

## Sprint 1 candidate board

| Status | ID | Title | Owner role | Blocker / next action |
|---|---|---|---|---|
| Accepted | STOR-001 | Implement idempotent local storage model | Infrastructure | Accepted after deterministic package paths, RFC/period layout, storage env precedence, tests, scanner, and fresh review passed. |
| Accepted | QA-002 | Add fixture safety scanner | QA | Accepted after scanner, focused tests, full tests, and fresh QA review passed. |
| Ready | CLI-001 | Design `storage locate` and `storage status` commands | CLI / UX | Depends on storage root resolver decision. |
| Accepted | INST-001 | Desktop onboarding for storage and e.firma references | Infrastructure | Accepted after ignored local configs, safe credential refs, onboarding tests, scanner, full suite, and fresh review passed. |
| Accepted | INF-001 | Define safe RFC profile configuration | Infrastructure | Accepted after closed schema, secret-reference validation, CLI validation, scanner, tests, and fresh review passed. |

## External tracker mapping

If the team mirrors this board into another tool, use this format:

| Field | Value |
|---|---|
| Issue title | `[BACKLOG-ID] Backlog title` |
| Labels | `workstream:<name>`, `sprint:<number>`, `type:<docs/code/test/infra>` |
| Link back | URL or path to `docs/planning/backlog.md` |
| Done evidence | PR, test output, screenshot, or sprint review note |

## Next step

During sprint planning, replace candidate rows with the actual committed sprint scope.


## Next execution candidate board

| Status | ID | Title | Owner role | Blocker / next action |
|---|---|---|---|---|
| In review | ARCH-EXEC-001 | Document module responsibilities and execution map | Architecture | Review docs plus optional MinIO Docker profile before accepting. |
| In review | PLAN-EXEC-001 | Publish implementation master plan | Architecture / PM | Review agent roster, sprint phases, integration rhythm, and library/package track. |
| Ready | QUEUE-003 | Implement RabbitMQ retry and DLQ policy | Queue / Worker | Start after ARCH-EXEC-001 is accepted. |
| Ready | CACHE-002 | Implement Redis progress, locks, and heartbeat | Queue / Worker | Can run in parallel with QUEUE-003 after architecture docs. |
| Ready | DB-005 | Add PostgreSQL evidence metadata and indexes | Data | Can run in parallel after architecture docs; evidence references must be queryable before API ingestion. |
| Ready | STOR-004A | Define object-key storage contract | Storage | Prove filesystem adapter parity before API ingestion; MinIO remains outside app/worker runtime. |
| Ready | PARSER-005A | Define CFDI parser version matrix | Parser | Can run in parallel after architecture docs; PARSER-005B rollout waits for this matrix. |
| Ready | LIB-005 | Define SAT v1.5 Python library facade plan | Release / SAT | Can run in parallel after architecture docs; do not promote live modules. |
| Blocked | STOR-004B | Implement optional MinIO storage adapter | Storage | Phase 2: wait for STOR-004A contract tests; do not wire MinIO into app/worker runtime. |
| Blocked | PARSER-005B | Implement version-specific CFDI parser rollout | Parser | Wait for PARSER-005A and DB-005; cover detector, extractors, complements, and partial/unknown behavior. |
| Blocked | API-003A | Define stored-reference ingestion API contract | API / Queue | Wait for STOR-004A filesystem parity, QUEUE-003 reliability, DB-005 evidence indexes, and CACHE-002 progress/lock/heartbeat semantics. |
| Blocked | PIPE-003 | Prove fake SAT package-to-ingestion E2E | Architecture | Wait for STOR-004A, queue, PostgreSQL, Redis, API-003B, and PARSER-005B; optional MinIO is not a prerequisite. |
