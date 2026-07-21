# SAT-PROGRAM-001 — Orchestration contract

This document defines how the maintainer requests, delegates, verifies, and
accepts work for the SAT-to-accounting program. It is the operating contract
between the requester, an executor, and a reviewer; it is not a second product
roadmap.

## Objective

Close and demonstrate, with auditable evidence, the durable path:

```text
SAT v1.5 Metadata → ZIP/TXT → worker inventory → CFDI/XML
→ V5 child ledgers → monthly/accounting/quality analysis
```

The path must use PostgreSQL as the durable source of truth, idempotent claims
and jobs, external artifact storage, due-aware SAT waiting, and an append-only
sanitized evidence log. Every stage must have an owner, dependency, measurable
exit condition, and categorized result.

The objective is complete only when:

1. The live preflight and human authorization gates pass.
2. Metadata produces a real processed ZIP/TXT, or closes as `no_data` or
   `service_window_exceeded` without a blind replacement request.
3. A worker consumes the metadata job exactly once and creates the private
   inventory.
4. CFDI/XML runs only after eligible metadata and a new `cfdi-proof` grant; a
   real ZIP/XML is processed when SAT returns eligible data.
5. V5 concepts, taxes, payments, payroll, and related rows are durable,
   tenant-safe, evidence-bound, and idempotent.
6. Monthly, accounting, and quality reports read PostgreSQL and expose only
   approved aggregates with completeness/provenance state.
7. Every result is recorded in `daily-evidence.md`; no feature is called
   complete from synthetic tests alone.

## What the requester owns

The requester/orchestrator owns the **why, order, boundary, and acceptance**:

- selects the next ready work unit from [`workstreams.md`](workstreams.md);
- states the expected outcome and why it matters;
- confirms dependencies, owner role, reviewer, and permitted branch/worktree;
- sets tests, scanners, evidence, and stop conditions before work starts;
- keeps SAT live work behind Carlos's explicit grant and credential gate;
- resolves blockers or escalates decisions; never asks an executor to guess;
- accepts or rejects the handoff based on evidence, not on a plausible summary;
- updates the workstream status and appends the daily evidence entry.

The requester does **not**:

- approve SAT contact on behalf of Carlos;
- accept a synthetic fixture as SAT evidence;
- widen dates, directions, budgets, or concurrency without a new decision;
- combine unrelated code changes into an existing work unit;
- close a pending or uncertain request by creating a replacement.

## Roles

| Role | Owns | Must hand off |
|---|---|---|
| Requester/orchestrator | Scope, priority, dependencies, gates, acceptance | A complete task packet and a recorded decision |
| Executor | The assigned bounded implementation or run | Code/docs, tests, result, blocker, and next step |
| Reviewer | Fresh-context challenge of scope and evidence | Findings, gate result, and accept/reject recommendation |
| Carlos/maintainer | Live authorization and final acceptance | Grant decision and categorized live outcome |
| Integration maintainer | Merge order, clean `dev`, worktree hygiene | Integrated commit and synchronized status |

## Ready-to-delegate rule

A work unit is `ready` only when all of these are known:

- stable `TASK_ID` and one-sentence objective;
- one owner role and one reviewer;
- predecessor IDs are complete or explicitly waived;
- exact files, interfaces, or operational boundary in scope;
- explicit out-of-scope list;
- expected tests and scanners;
- evidence format and acceptance threshold;
- stop conditions and escalation owner;
- a start commit or clean base reference.

If one item is missing, the requester keeps the unit `planned` or marks it
`blocked`; the executor must not invent the missing decision.

## Task request template

Copy this block into the assignment message and keep the same ID in the
workstream board and daily evidence log:

```text
TASK_ID:
OBJECTIVE:
WHY_NOW:
OWNER_ROLE:
REVIEWER_ROLE:
DEPENDS_ON:
START_BASE:
IN_SCOPE:
OUT_OF_SCOPE:
DELIVERABLES:
TESTS_AND_GATES:
ACCEPTANCE_CRITERIA:
EVIDENCE_REQUIRED:
STOP_CONDITIONS:
NEXT_TASK:
```

The request must describe outcomes, not a list of implementation guesses. The
executor may choose the internal design only within the stated boundaries.

## Handoff template

The executor returns this compact record. It must contain no fiscal rows,
identifiers, SOAP, secrets, raw payloads, absolute local paths, artifact/data
hashes, or real artifact names. Repository-relative file paths and short Git
commit SHAs are allowed for code lineage:

```text
work_unit=<TASK_ID>
owner_role=<role>
branch=<sanitized-branch>
start_commit=<short-sha>
end_commit=<short-sha-or-none>
files=<sanitized-path-list>
tests=<command-and-result>
scanners=<ruff/sensitive/sat-context/diff/compose-as-applicable>
result=<confirmed|refuted|inconclusive|blocked>
status=<planned|in_progress|blocked|verified|accepted|inconclusive>
blocker=<fixed-category-or-none>
next_step=<one-action>
```

The reviewer records whether the handoff proves the acceptance criteria. A
green test suite without the required runtime or SAT evidence remains
`verified`, not `accepted`.

## State transitions

```text
planned → in_progress → verified → accepted
                    ↘ blocked
                    ↘ inconclusive
```

- `planned`: defined and waiting for a ready dependency.
- `in_progress`: one owner has claimed the unit; no second writer starts it.
- `verified`: implementation/run and local gates pass; reviewer has checked it.
- `accepted`: Carlos or the maintainer accepts the recorded evidence.
- `blocked`: an external decision, credential, environment, or safety gate is
  required; the blocker category is recorded.
- `inconclusive`: the run completed but cannot prove the hypothesis; preserve
  state and define the next bounded observation.

Never move directly from `in_progress` to `accepted` without a reviewer
handoff and a daily evidence entry.

## Parallel execution policy

| Lane | Allowed parallelism | Rule |
|---|---:|---|
| SAT live | 1 sequential chain | Never overlap replacement requests; max two SAT operations globally. |
| Accounting/data | 1 writer plus 1 fresh reviewer | Synthetic data may proceed while SAT waits. |
| Worker/storage | 1 writer per worktree | Jobs and artifact rules must be tested before live use. |
| Documentation/control | Continuous | Update evidence after every completed unit or working day. |
| FastAPI/release/cleanup | Deferred | Cannot be used to claim SAT or accounting completion. |

The requester may dispatch parallel work only when the dependency graph permits
it and no two writers touch the same worktree or migration surface.

## Daily orchestration loop

1. Read the current commit, workstream board, and latest evidence entry.
2. Mark stale or unsupported claims `inconclusive` rather than assuming they
   are complete.
3. Select the next ready unit in the SAT lane and one independent accounting
   unit, if available.
4. Send each executor a complete task packet.
5. Review returned tests, scanners, diff, and evidence against the acceptance
   criteria.
6. Record the outcome in `daily-evidence.md` and update the board in the same
   commit as the related docs/code.
7. Issue the next task only after the predecessor's state is `verified`, or
   after documenting an explicit dependency waiver.

## First dispatch order

This is a priority order for the initial dispatch, not a requirement that the
items run serially. `DOC-STATUS-001` is intentionally continuous and may run
in parallel with the first two units.

1. `SAT-PREFLIGHT-001` — prepare the first live Metadata run without contacting
   SAT; requires Carlos's profile and exact grant before the next unit.
2. `LEDGER-V5-MAP-001` — implement and verify the synthetic, idempotent V5
   child-ledger mapper while SAT waits.
3. `DOC-STATUS-001` — append the handoffs and reconcile plan/code/test status.
4. `SAT-META-REAL-001` — start only after preflight is `accepted`.

## Completion audit

Before declaring the program complete, the requester checks every requirement
in [`master-plan.md`](master-plan.md) against a concrete file, test result,
runtime result, or sanitized SAT observation. Missing, indirect, or synthetic-
only evidence is recorded as incomplete; it is never upgraded by interpretation.
