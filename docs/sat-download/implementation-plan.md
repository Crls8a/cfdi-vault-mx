# Implementation plan for the SAT download library

This plan turns the research into reviewable implementation slices. The first production-ready library should be boring, explicit, heavily tested, and reconciliation-led.

## Target architecture

```mermaid
flowchart TD
    A[CLI or application job] --> B[Download orchestration service]
    B --> C[Credential provider interface]
    B --> D[Authentication client]
    B --> E[Request client]
    B --> F[Verification client]
    B --> G[Download client]
    B --> H[Persistence repository]
    G --> I[Package storage]
    I --> J[Metadata and CFDI package readers]
    J --> K[Metadata ledger]
    K --> L[Reconciliation engine]
    L --> M[Existing parser/import service]
```

## Proposed modules

| Module | Responsibility | Notes |
|---|---|---|
| `credentials` | Load or receive e.firma material through interfaces. | No built-in secret vault in the library core. |
| `signing` | XMLDSig and WS-Security builders. | Highest-risk module; needs fixture-heavy tests. |
| `soap` | Transport, headers, SOAPAction, error capture. | Keep independent from business orchestration. |
| `requests` | Domain query objects and validation. | Must be deterministic and hashable. |
| `sat_auth` | Authentication operation. | Returns token with metadata. |
| `sat_request` | Submit download requests. | Supports official baseline and observed v1.5 variants separately. |
| `sat_verify` | Verify request status and package ids. | Pure parser plus transport call. |
| `sat_download` | Download package by id. | Stores raw package before extraction. |
| `packages` | Read ZIP, XML, and metadata TXT packages. | Should support streaming metadata. |
| `ledger` | Store metadata inventory and XML evidence state. | This is the control plane for retries. |
| `reconciliation` | Classify UUIDs as downloaded, pending, cancelled, quota-limited, retryable, or manual-review. | Avoids blind redownload loops. |
| `errors` | Map SAT/transport/domain failures to typed internal codes and user messages. | Keeps support and CLI/API behavior consistent. |
| `repository` | Idempotent request/package persistence. | SQLite first, but avoid hard-coding storage in domain logic. |
| `audit` | Structured events and redaction. | Never log secrets or full real XML by default. |

## Data model for the first integration slice

| Table | Key | Purpose |
|---|---|---|
| `sat_requests` | `id_solicitud` plus local `query_hash` | Track submitted queries, SAT status, and criteria. |
| `sat_packages` | `id_paquete` | Track package download attempts, SHA-256, storage key, and expiry risk. |
| `sat_events` | `event_id` | Append-only operational audit. |
| `metadata_ledger` | `uuid`, direction, source package | Expected document inventory from metadata packages. |
| `xml_evidence` | `uuid`, source package | Stored XML evidence and checksums. |
| `reconciliation_events` | `event_id` | Why a UUID changed reconciliation state. |
| `cfdi_documents` | `uuid` | Reuse or evolve the current normalized CFDI store. |
| `cfdi_metadata_rows` | `uuid`, `source_package` | Store parsed metadata rows when requested. |

## Work slices

| Slice | Outcome | Acceptance checks |
|---|---|---|
| 1. Documentation and source matrix | Contributors understand official vs observed behavior. | Docs reviewed, no network code. |
| 2. Domain request model | Queries can be built, validated, and hashed. | Unit tests for valid/invalid combinations. |
| 3. XML builders | SOAP and XMLDSig builders produce deterministic XML. | Golden tests with synthetic credentials. |
| 4. Transport abstraction | SOAP requests can be sent through an injectable client. | Fake transport tests; no live SAT in CI. |
| 5. Response parsers | Authentication, request, verification, and download responses parse safely. | Fixture tests for success and common errors. |
| 6. Persistence | Requests/packages are resumable and idempotent. | SQLite tests for duplicate query and package attempts. |
| 7. Metadata ledger | Metadata packages become canonical expected-document rows. | Tests for TXT metadata parsing, dedupe, and status updates. |
| 8. Reconciliation engine | UUIDs are classified before XML retries. | Tests for pending, downloaded, cancelled, expired, quota-limited, and manual-review states. |
| 9. User-facing error contract | Every failure explains what happened, what is missing, and whether retry is automatic. | Snapshot tests for CLI/API error messages. |
| 10. Orchestrator | End-to-end job state machine works against fake SAT. | Contract tests with fake async states. |
| 11. Optional live adapter | Manual integration path for maintainers with lawful credentials. | Explicit opt-in, skipped by default in CI. |

## Design decisions

| Decision | Tradeoff |
|---|---|
| Keep signing isolated from transport. | More interfaces, but easier to test and audit. |
| Use fake SAT transport in automated tests. | Less production certainty, but no secret exposure in CI. |
| Persist before parsing. | More disk/storage usage, but preserves scarce package download attempts. |
| Metadata is the control plane. | More tables and reconciliation logic, but fewer blind retries and better auditability. |
| Support observed v1.5 as compatibility behavior. | More version branching, but honest source attribution. |
| Keep docs source-linked. | More maintenance, but contributors can verify claims. |

## Minimum definition of done

- [ ] No real SAT calls in default tests.
- [ ] No real credentials or taxpayer XML in fixtures.
- [ ] Query validation is complete before signing.
- [ ] XML building is deterministic.
- [ ] All SAT responses preserve raw code/message in typed errors.
- [ ] Package bytes are stored and hashed before extraction.
- [ ] Metadata ledger can explain what exists, what is missing, and why.
- [ ] Credential custody mode is explicit during setup.
- [ ] User-facing errors redact secrets and include next action.
- [ ] README states clearly whether SAT integration is implemented, experimental, or planned.
