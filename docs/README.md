# Documentation index

This repository is split into two documentation areas: the current local-first CFDI data lab, and the SAT Web Service recovery library being implemented behind a fake SAT boundary.

## Quick path

1. Start with [the main README](../README.md) to run the current CLI.
2. Read [Developer CLI invocation](devx.md) before documenting local commands or `PYTHONPATH=src` fallbacks.
3. Read [Architecture](architecture.md) to understand the existing local parser/storage boundaries.
4. Read [CLI family refactor plan](planning/cli-family-refactor-plan.md) before changing CLI adapter ownership or resolving CLI merge conflicts.
5. Read [Security model](security-model.md) before touching real CFDI data or certificates.
6. Read [Foundation-first plan](foundation/README.md) before adding more recovery features.
7. Read [Agile planning workspace](planning/README.md) and [Lightweight governance policy](planning/governance.md) before assigning sprint work.
8. Read [Safe RFC profile configuration](config/README.md) before adding local profile settings.
9. Read [Local RFC setup and credential intake](setup.md) before changing AppData setup or credential import.
10. Read [First-run onboarding](installer/onboarding.md) before changing installer or profile setup.
11. Read [Local installer alpha](installer/local-installer-alpha.md) before changing editable install or bootstrap behavior.
12. Read [Idempotent local storage](storage-design.md) before writing package, metadata, or XML evidence.
13. Read [Recovery v2](recovery-v2.md) for the current RabbitMQ/Redis/PostgreSQL implementation slice.
14. Read [SAT download documentation](sat-download/README.md) before implementing any SAT Web Service client.
15. Read [Offline/local SAT download operations](sat-download/offline-local-operations.md) before validating issue #51.
16. Read [MANUAL-SAT-001](sat-download/manual-sat-runbook.md) before requesting any human-gated live SAT smoke.

## Documentation map

| Area | Document | Purpose |
|---|---|---|
| Current repo | [Architecture](architecture.md) | Existing CLI, parser, service, and SQLite model. |
| Current repo | [CLI family refactor plan](planning/cli-family-refactor-plan.md) | CLI adapter ownership, merge-conflict source of truth, and follow-up slices. |
| Current repo | [Case study](case-study.md) | Why phase one is local-first and synthetic-only. |
| Current repo | [Developer CLI invocation](devx.md) | Editable install path, installed CLI usage, and dev-only `PYTHONPATH=src` fallback. |
| Current repo | [Security model](security-model.md) | Current safety boundaries and forbidden data. |
| Current repo | [Fixture and fake-data policy](testing/fixture-policy.md) | Allowed fixture categories, fake RFC strategy, and no-real-CFDI rules. |
| Current repo | [Safe RFC profile configuration](config/README.md) | Local multi-RFC config schema and credential-reference rules. |
| Current repo | [Local RFC setup and credential intake](setup.md) | AppData profile creation, credential import guards, redacted status, and cleanup. |
| Current repo | [First-run onboarding](installer/onboarding.md) | CLI setup flow for storage, RFC profile, schedule, and non-secret e.firma references. |
| Current repo | [Local installer alpha](installer/local-installer-alpha.md) | Windows editable install, bootstrap script, installed CLI validation, and fake/offline first-use flow. |
| Current repo | [Idempotent local storage](storage-design.md) | RFC/period storage layout, metadata-first index, idempotency rules, and pipeline states. |
| Current repo | [SDD](sdd.md) | Initial implemented requirements. |
| Foundation | [Foundation-first plan](foundation/README.md) | Gate before more code: scope, stories, CLI/UX, installer, unified recovery pipeline, storage, architecture, data model, ambiguity, ownership, delegation. |
| Planning | [Agile planning workspace](planning/README.md) | Sprint roadmap, backlog, team board, delegation model, and agile operating rules. |
| Planning | [Lightweight governance policy](planning/governance.md) | Solo-maintainer issue policy, PR/CI expectations, and mandatory security gates. |
| Recovery v2 | [Recovery v2](recovery-v2.md) | Implemented fake SAT, queue/cache/storage ports, Docker, CLI, and next steps. |
| Recovery v2 | [ADR 0002](adr/0002-recovery-v2-rabbitmq-redis-postgres.md) | Decision record for RabbitMQ, Redis, PostgreSQL, JSON payloads, and search. |
| Planned library | [SAT download overview](sat-download/README.md) | Entry point for the future download client. |
| Planned library | [Official vs observed behavior](sat-download/official-vs-observed.md) | What is SAT-official vs community-observed. |
| Planned library | [Initial requirements](sat-download/requirements.md) | What developers/operators need before live SAT use. |
| Planned library | [Service flow](sat-download/service-flow.md) | SOAP flow, endpoints, operations, and package lifecycle. |
| Planned library | [Authentication and security](sat-download/auth-security.md) | e.firma, WS-Security, secrets, and legal boundaries. |
| Planned library | [Request model](sat-download/request-model.md) | Query parameters and validation rules. |
| Planned library | [Metadata-led reconciliation architecture](sat-download/reconciliation-architecture.md) | Product architecture for metadata inventory, XML evidence, retries, and operator review. |
| Planned library | [Statuses, limits, and errors](sat-download/statuses-limits-errors.md) | State machine, quotas, and error handling. |
| Planned library | [User-facing errors and edge cases](sat-download/user-facing-errors.md) | Error payload contract, user messages, and edge cases. |
| Planned library | [Offline/local SAT download operations](sat-download/offline-local-operations.md) | Fake/offline runbook for issue #51: demo path, backup/restore, observability, and #50 boundary. |
| Planned library | [MANUAL-SAT-001 live smoke runbook](sat-download/manual-sat-runbook.md) | Human-gated live SAT smoke approval, evidence, and redaction rules. |
| Planned library | [Implementation plan](sat-download/implementation-plan.md) | Proposed library modules, persistence, and roadmap. |
| Planned library | [Examples](sat-download/examples.md) | Transport examples and payload templates. |
| Planned library | [Sources](sat-download/sources.md) | Official and community references. |

## Rule for contributors

Do not implement SAT network access until the relevant design document has been reviewed and the security model has been updated.
