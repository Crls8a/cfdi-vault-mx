# Wave 3 Plan

Wave 3 is a planning-only proposal for two small offline access surfaces. It
does not authorize implementation, feature branches, agents, publication, or
remote changes.

## Goal

Make already-integrated offline contracts easier to consume without expanding
the runtime: expose the SAT v1.5 offline contract through an import-first facade
and expose safe filesystem evidence discovery through focused CLI commands.

## Non-goals

- No SAT live access, signing, e.firma use, or network calls.
- No real XML, PDF, ZIP, metadata, RFC, credentials, or local operator paths.
- No Docker services or service-backed CI.
- No worker, queue, parser, database, migration, object-storage runtime, or API work.
- No `main`, remote PR per local feature, push, or remote merge.
- No implementation until a separate explicit human approval.

## Operating model

1. Keep this plan and both candidate features in `planned` state.
2. After explicit approval, create each local feature branch from the approved
   local `dev`; use no more than two proposed agents in parallel.
3. Require focused tests, Ruff, scanners, `git diff --check`, and fresh review
   before local integration into `dev`.
4. Publish only one final integration cut after both features are locally
   integrated and independently reviewed.

Local feature work requires no issue, PR, or label. The final integration cut
retains the approved issue, exactly one canonical `type:*` label, PR to `dev`,
and lightweight CI evidence defined by [work orchestration](../work-orchestration.md).

## Candidate features

| id | module | title | branch local | owner/agent | dependencies | gates | risk |
|---|---|---|---|---|---|---|---|
| `LIB-005C` | SAT download library | Import-first offline facade over injected contracts and fakes | `feature/sat-v15-facade` | Unassigned; proposal only | `LIB-005B` | SAT contract/public API tests, focused Ruff, both scanners, fresh review, diff check | Medium: accidental import of runtime or live adapters |
| `CLI-001` | CLI / storage | Safe `storage status` and `storage locate` over filesystem evidence references | `feature/storage-observability-cli` | Unassigned; proposal only | `STOR-004B` integration record; filesystem remains active | Future hermetic `tests/test_cli_storage_commands.py`, focused Ruff, sensitive scanner, fresh review, diff check | Medium: leaking identifiers or absolute paths |

### Evidence and exclusions

- `LIB-005C` is an existing backlog item in
  [`docs/planning/backlog.md`](../planning/backlog.md). `LIB-005B` is recorded as
  `integrated_remote`, while `src/cfdi_vault/sat_download.py` does not exist;
  the facade is therefore a verified gap rather than repeated work.
- `CLI-001` is still `Ready` in
  [`docs/planning/team-board.md`](../planning/team-board.md). The open storage
  tasks in [`docs/foundation/storage-and-retention.md`](../foundation/storage-and-retention.md)
  call for `storage status` and `storage locate`, and the current CLI parity
  report lists no `storage` command family.
- `CACHE-003`, `PARSER-005B`, and `STOR-004B` are already integrated and are not
  candidates. The two related worktrees have no commits unique from `dev`.
- `WORKER-002`, `API-003B`, `DB-006`, and `PIPE-003` remain dependency-heavy
  runtime work in [`docs/planning/backlog.md`](../planning/backlog.md); including
  them would violate this wave's small, service-free boundary.
- Deep payments/payroll parsing remains a real documented gap in
  [`docs/parser-version-matrix.md`](../parser-version-matrix.md), but it is
  deferred because it needs a separately bounded parser backlog item.

## Execution order

1. Human approves Wave 3 implementation explicitly.
2. `LIB-005C` and `CLI-001` may run in parallel, with at most two proposed
   agents total and no cross-branch dependency.
3. Each feature receives a fresh-context review and passes its local gates.
4. Merge reviewed feature commits into local `dev` one at a time and rerun
   focused gates after each merge.
5. Assemble one final integration cut only after both features are
   `local_integrated`.

## Gates per feature

### `LIB-005C`

- Targeted pytest: `tests/test_sat_contract.py` and
  `tests/test_sat_public_api_contract.py`, plus facade-specific tests.
- Focused Ruff on modified SAT library and test files.
- Sensitive fixture and SAT context scanners.
- Fresh review proving imports stay service-free, injected, offline, and live-disabled.
- `git diff --check`.

### `CLI-001`

- Required offline command gate and feature deliverable: create
  `tests/test_cli_storage_commands.py` with injected fake application/storage
  services. It must cover both commands without PostgreSQL, `DATABASE_URL`,
  Docker, network access, or any external service.
- Existing offline support checks may include `tests/test_cli_help.py`,
  `tests/test_storage.py`, and `tests/test_storage_contract.py` as affected.
- Existing `tests/test_cli_storage.py` is marked `integration` and uses the
  `reset_postgres_database` fixture. It is optional Tier 3 local PostgreSQL
  evidence, never a default-CI requirement or the offline CLI-001 feature gate.
- Focused Ruff on the new CLI family and modified tests.
- Sensitive fixture scanner and SAT context scanner if SAT-facing text changes.
- Fresh review proving output is redacted and contains no absolute adapter path.
- `git diff --check`.

Docker or Compose execution is not a feature gate. Both features use offline
fakes/contracts and the active filesystem boundary.

## Final integration cut

Expected branch: `integration/dev-wave3-offline-access`.

The cut is the only remote publication unit and targets `dev`. Before
publication it must pass:

- `work_orchestrator.py validate`, `status`, `blocked`, and `next`;
- `check_ci_policy.py --strict`;
- sensitive fixture and SAT context scanners;
- the offline CI pytest subset and both features' targeted tests, including the
  future hermetic `tests/test_cli_storage_commands.py` CLI-001 gate;
- focused Ruff for changed Python files;
- `git diff --check`;
- Compose config-only checks only if Compose configuration is actually changed.

No Docker service start, `docker compose up`, `docker compose run`, or SAT live
gate belongs to this cut.

## Human approvals required

- Approval to change `wave3.human_approval` from `required` to `approved` and
  start either feature.
- Approval to create and publish the final integration cut.
- Approval to merge the remote integration PR into `dev`.

Planning approval alone grants none of these permissions.

## Risks

| Risk | Mitigation |
|---|---|
| The facade imports CLI, database, broker, storage adapter, or live SAT code | Import-smoke in a minimal environment; dependency injection; fresh architecture review. |
| Storage commands expose RFCs, UUIDs, hashes, or absolute paths | Tenant-scoped queries, redacted fixtures, safe aggregate output, snapshot assertions. |
| Optional MinIO becomes a hidden prerequisite | Keep filesystem as the active adapter; no MinIO configuration or service gate. |
| Planning is mistaken for authorization | Keep both items `planned`, Wave 3 `started: false`, human approval `required`, and owners unassigned. |
| Remote ceremony spreads to subfeatures | Keep branches local and publish only the single final integration cut. |
