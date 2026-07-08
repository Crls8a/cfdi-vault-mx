# SAT CFDI download library documentation

Target contract:
SAT Descarga Masiva CFDI y CFDI de Retenciones v1.5, mayo 2025.

Allowed sources:
- V1_5_CONTRACT
- RUNTIME_WSDL
- COMMUNITY_ORACLE as implementation oracle only

Forbidden as operational contract:
- v1.2
- 2023 manuals
- legacy endpoints
- forums/blogs/snippets
- old prompts

This folder turns SAT Descarga Masiva work into small, reviewable documents. The goal is to keep source policy, SOAP mechanics, security decisions, and implementation work separated so agents do not mix old manuals with the current v1.5 contract.

> Status: guarded SAT integration documentation. Default tests remain offline and must not call live SAT.

## Quick path

1. Start with [Source Policy](source-policy.md).
2. Read [SAT download public API research and contract](../api/sat-download-public-api.md) before changing the reusable Python boundary.
3. Use [SAT Download v1.5 Checklist](v1_5_checklist.md) before changing SAT Download behavior.
4. Understand the service shape in [Service flow](service-flow.md).
5. Check source confidence in [Contract, runtime, and oracle behavior](official-vs-observed.md).
6. Confirm initial setup in [Initial requirements](requirements.md).
7. Review e.firma and secret-handling rules in [Authentication and security](auth-security.md).
8. Model valid queries with [Request model](request-model.md).
9. Design the recovery product with [Metadata-led reconciliation architecture](reconciliation-architecture.md).
10. Implement around [Statuses, limits, and errors](statuses-limits-errors.md).
11. Run the fake/offline local path with [Offline/local SAT download operations](offline-local-operations.md).
12. Use [SAT async verify scheduler](async-verify-scheduler.md) for one-shot persisted verification work.
13. Review [MANUAL-SAT-001](manual-sat-runbook.md) before requesting any human-gated live smoke.
14. Use [Implementation plan](implementation-plan.md) to split future work into reviewable units.

## What the library is expected to do

| Capability | Meaning |
|---|---|
| Authenticate | Build and sign the WS-Security authentication request with a valid e.firma. |
| Request | Ask SAT to prepare CFDI or metadata packages for issued, received, or folio-based queries. |
| Verify | Poll the asynchronous request until SAT returns package identifiers or a terminal state. |
| Download | Download package ZIP content and decode the base64 SOAP response. |
| Persist | Track requests, packages, hashes, attempts, and source files idempotently. |
| Parse | Read downloaded XML or metadata TXT packages after safe storage. |
| Reconcile | Compare metadata inventory against XML evidence and explain pending, terminal, and retryable UUIDs. |
| Explain | Return actionable user-facing messages for missing requirements, SAT errors, and edge cases. |

## Non-goals for the first SAT integration slices

- No web dashboard.
- No credential upload endpoint.
- No multi-tenant SaaS custody of e.firma files.
- No legal delegation model beyond the documented emitter/receiver/representative use case.
- No use of legacy references as current contract.
- No use of forums, blogs, snippets, or old prompts as contract.
- No conversion of community repositories into runtime dependencies.
- No blind XML retry loop that ignores metadata, cancellation state, request status, or package limits.

## Reader promise

Each document separates five source levels deliberately:

1. `V1_5_CONTRACT`.
2. `RUNTIME_WSDL`.
3. `COMMUNITY_ORACLE`.
4. `LEGACY_REFERENCE`.
5. `REJECTED_AS_CONTRACT`.

That separation matters. Without it, contributors debug the wrong problem and agents turn evidence into sopa instantánea.
