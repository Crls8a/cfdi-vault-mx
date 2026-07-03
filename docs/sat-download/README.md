# SAT CFDI download library documentation

This folder turns the research note about SAT massive CFDI downloads into small, reviewable documents. The goal is to prepare the repository for an open-source library without mixing legal context, SOAP mechanics, security decisions, and implementation work in one long document.

> Status: design documentation only. The current code still imports and analyzes synthetic/local CFDI-like XML files; it does not call SAT services.

## Quick path

1. Understand the service shape in [Service flow](service-flow.md).
2. Check source confidence in [Official vs observed behavior](official-vs-observed.md).
3. Confirm initial setup in [Initial requirements](requirements.md).
4. Review e.firma and secret-handling rules in [Authentication and security](auth-security.md).
5. Model valid queries with [Request model](request-model.md).
6. Design the recovery product with [Metadata-led reconciliation architecture](reconciliation-architecture.md).
7. Review the Sprint 2 behavior in [Metadata-first reconciliation slice](metadata-first-reconciliation.md).
8. Implement around [Statuses, limits, and errors](statuses-limits-errors.md).
9. Define user communication with [User-facing errors and edge cases](user-facing-errors.md).
10. Review [MANUAL-SAT-001](manual-sat-runbook.md) before requesting any human-gated live smoke.
11. Use [Implementation plan](implementation-plan.md) to split the future library into reviewable work units.

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

## Non-goals for the first SAT integration slice

- No web dashboard.
- No credential upload endpoint.
- No multi-tenant SaaS custody of e.firma files.
- No legal delegation model beyond the documented emitter/receiver/representative use case.
- No claim that community-observed behavior is official SAT documentation.
- No blind XML retry loop that ignores metadata, cancellation state, request status, or package limits.

## Reader promise

Each document separates three things deliberately:

1. **Official SAT documentation**: the strongest source for public, auditable behavior.
2. **Observed community behavior**: practical compatibility notes from maintained libraries and providers.
3. **Repository decision**: how this project should model that information in code.

That separation matters. Without it, contributors will confuse production behavior with official specification and then debug the wrong problem.
