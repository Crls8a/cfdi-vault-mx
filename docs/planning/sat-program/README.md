# SAT program execution workspace

This folder is the operational planning source for closing the remaining SAT,
accounting, worker, and evidence milestones. It turns the current repository
state into dated work units that can be delegated, verified, and recorded
without putting fiscal data in Git, logs, issues, or chat.

## Quick path

1. Read [`objective-and-task-orchestrator.md`](objective-and-task-orchestrator.md)
   for the single measurable objective, delegation contract, task templates,
   and status transitions.
2. Read [`master-plan.md`](master-plan.md) for the sequence, dates, gates, and
   parallel lanes.
3. Read [`workstreams.md`](workstreams.md) before assigning a task; every unit
   has one owner, one reviewer, dependencies, and a measurable exit condition.
4. Read [`orchestration.md`](orchestration.md) for the requester contract,
   task packet, handoff, and state-transition rules.
5. Append one sanitized record to [`daily-evidence.md`](daily-evidence.md)
   after each working day or completed unit.
6. Update the status in the same commit as the code or documentation it
   describes.
7. Append a code-grounded entry to [`known-gaps.md`](known-gaps.md) whenever
   operating the pipeline surfaces a defect that is not blocking today but
   should be fixed before it causes a silent failure later.

## Scope

The program closes this path:

```text
preflight → real Metadata request → ZIP/TXT → worker inventory
→ cfdi-proof → ZIP/XML → V5 ledgers → financial analysis
```

FastAPI, public package release, and cleanup of internal legacy SAT modules are
tracked as later work. They must not delay the first real Metadata and XML
proofs unless a dependency or safety gate requires it.

## Status vocabulary

| Status | Meaning |
|---|---|
| `planned` | Defined but not started. |
| `in_progress` | An owner is actively working it. |
| `blocked` | Cannot proceed without an external decision or dependency. |
| `verified` | Code/docs and required local gates pass. |
| `accepted` | Carlos reviewed the evidence and accepted the outcome. |
| `inconclusive` | The run produced no safe conclusion; keep the request/state and document why. |

`verified` does not mean SAT behavior is proven. A real SAT claim requires a
sanitized entry in the daily evidence log and the exact live gate result.

## Safety rules

- PostgreSQL remains the durable source of truth.
- ZIP/TXT/XML remain in external storage only.
- RabbitMQ receives opaque references, never fiscal rows or payloads.
- No RFC, UUID, SAT identifier, SOAP, credential, absolute local path,
  artifact/data hash, or real artifact may appear in this folder. A short Git
  commit SHA may appear only as code-lineage evidence.
- Synthetic tests prove implementation contracts; only the human-gated SAT
  run proves SAT behavior.
- A pending request is never replaced automatically.

## Ownership model

Roles are deliberately used instead of naming an agent before the unit is
accepted. The delegation record names the concrete branch/agent at start time.

| Role | Accountable for |
|---|---|
| Carlos / maintainer | Human SAT authorization, credentials, grants, final acceptance, and stop decisions. |
| SAT integration owner | v1.5 adapter, campaign runner, due VERIFY, download classification, and live runbook execution. |
| Persistence/data owner | Flyway, PostgreSQL claims, V5 mapper, tenant isolation, and durable reports. |
| Worker/queue owner | RabbitMQ outbox, consumer/inbox idempotency, parsing jobs, leases, and heartbeat. |
| Storage/security owner | External artifact roots, ZIP/TXT/XML validation, atomic writes, redaction, and scanners. |
| Analysis/accounting owner | Monthly, tax, payment, payroll, quality, and contextual reports over durable rows. |
| QA/documentation owner | Daily evidence, tests, scanners, cross-document consistency, and fresh review. |
| Integration maintainer | Branch base, merge order, worktree cleanup, and final `dev` integration. |

## Current baseline (2026-07-21)

- V1–V7 PostgreSQL schema, V6/V7 jobs/outbox, worker, RabbitMQ, Redis, and
  Compose synthetic gates pass.
- Repository-wide Ruff now passes.
- Public SAT CLI is the four-command `sat campaign` family.
- No real SAT ZIP/TXT/XML has been processed.
- V5 child-ledger mapping is synthetically verified; durable financial database
  ingestion and the financial operator CLI remain open.

The dated plan in [`master-plan.md`](master-plan.md) is the authority for what
starts next; older sprint documents remain historical references until they are
explicitly synchronized.
