# Documentation index

This repository is split into the current PostgreSQL-backed CFDI recovery reference system and the SAT Web Service library design being implemented behind a fake SAT boundary.

## Quick path

1. Start with [the main README](../README.md) to run the current CLI.
2. Read [Product split](product-archetype.md) to understand the library-versus-reference-system boundary.
3. Read [Library scope](release/library-scope.md) and [Reference system scope](foundation/reference-system-scope.md) when deciding what belongs in the package versus the case study.
4. Read [Repository public API plan](release/public-api.md) before promoting an import as stable.
5. Read [SAT download public API research and contract](api/sat-download-public-api.md) before changing SAT SOAP library boundaries.
6. Read [Python package release plan](release/python-package-plan.md) before changing package metadata or release automation.
7. Read [Library quality contract](release/library-quality-contract.md) before promoting modules, classes, functions, methods, or CLI commands as public API.
8. Read [Developer CLI invocation](devx.md) before documenting local commands or `PYTHONPATH=src` fallbacks.
9. Read [Architecture](architecture.md) to understand the PostgreSQL-backed parser/storage boundaries.
10. Read [CFDI parser compatibility matrix](parser-version-matrix.md) before claiming version or complement support.
11. Read [CLI family refactor plan](planning/cli-family-refactor-plan.md) before changing CLI adapter ownership or resolving CLI merge conflicts.
12. Read [Security model](security-model.md) before touching real CFDI data or certificates.
13. Read [Foundation-first plan](foundation/README.md) before adding more recovery features.
14. Read [Living system plan](planning/living-system-plan.md) before changing objectives, architecture, security, source-of-truth docs, or release promises.
15. Read [Agile planning workspace](planning/README.md) and [Lightweight governance policy](planning/governance.md) before assigning sprint work.
16. Read [Safe RFC profile configuration](config/README.md) before adding local profile settings.
17. Read [Local RFC setup and credential intake](setup.md) before changing AppData setup or credential import.
18. Read [First-run onboarding](installer/onboarding.md) before changing installer or profile setup.
19. Read [Local installer alpha](installer/local-installer-alpha.md) before changing editable install or bootstrap behavior.
20. Read [Idempotent local storage](storage-design.md) before writing package, metadata, or XML evidence.
21. Read [Infrastructure boundary](foundation/infrastructure-boundary.md) before changing PostgreSQL, RabbitMQ, Redis, Docker, workers, or future FastAPI ingestion behavior.
22. Read [Database, queue, and API contract](foundation/database-queue-api-contract.md) before changing Flyway migrations, queue names, or ingestion event flow.
23. Read [Recovery v2](recovery-v2.md) for the current RabbitMQ/Redis/PostgreSQL implementation slice.
24. Read [SAT download documentation](sat-download/README.md) before implementing any SAT Web Service client.
25. Read [Offline/local SAT download operations](sat-download/offline-local-operations.md) before validating issue #51.
26. Read [MANUAL-SAT-001](sat-download/manual-sat-runbook.md) before requesting any human-gated live SAT smoke.

## Documentation map

| Area | Document | Purpose |
|---|---|---|
| Current repo | [Architecture](architecture.md) | PostgreSQL-backed CLI, parser, service, and recovery model. |
| Current repo | [Case study](case-study.md) | Why fake/offline examples stay synthetic-only while using the PostgreSQL runtime. |
| Current repo | [Product split](product-archetype.md) | Separates the reusable Python library from the CLI/local reference system and case study. |
| Release | [Library scope](release/library-scope.md) | Defines what belongs in the importable package and what must stay outside the library contract. |
| Foundation | [Reference system scope](foundation/reference-system-scope.md) | Defines the repository-level CLI/runtime/case-study boundary. |
| API | [SAT download public API research and contract](api/sat-download-public-api.md) | Summarizes verified SAT SOAP evidence and the import-first API boundary. |
| Release | [Repository public API plan](release/public-api.md) | Lists current public imports, candidate surfaces, internal surfaces, and promotion gates. |
| Current repo | [CLI family refactor plan](planning/cli-family-refactor-plan.md) | CLI adapter ownership, merge-conflict source of truth, and follow-up slices. |
| Release | [Python package release plan](release/python-package-plan.md) | PyPI/TestPyPI plan, public API gates, and Trusted Publishing checklist. |
| Release | [Library quality contract](release/library-quality-contract.md) | Public API responsibilities, tests, docstrings, safety gates, and release readiness for `cfdi_vault`. |
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
| Foundation | [Infrastructure boundary](foundation/infrastructure-boundary.md) | PostgreSQL-first recovery runtime, RabbitMQ queue boundary, Redis transient state, Docker services, and future FastAPI ingestion boundary. |
| Foundation | [Database, queue, and API contract](foundation/database-queue-api-contract.md) | Flyway baseline, PostgreSQL table ownership, queue order/purpose, and planned FastAPI event handoff. |
| Planning | [Agile planning workspace](planning/README.md) | Sprint roadmap, backlog, team board, delegation model, and agile operating rules. |
| Planning | [Living system plan](planning/living-system-plan.md) | Source-of-truth hierarchy, security workstream, architecture/doc gaps, and next work units for the case study. |
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
