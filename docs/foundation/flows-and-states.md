# Flows and states

This document defines the operational flows before deeper implementation.

The user-facing behavior is one recovery pipeline. See [Recovery pipeline contract](recovery-pipeline.md) for the rule that download, extraction, database loading, and local evidence registration belong to one auditable job.

## Metadata sync flow

```mermaid
sequenceDiagram
    participant CLI
    participant App as Application service
    participant MQ as RabbitMQ
    participant Worker
    participant SAT as SAT/Fake SAT
    participant PG as PostgreSQL
    participant Redis
    participant Storage

    CLI->>App: sync metadata(criteria)
    App->>PG: create download_job + criteria_hash
    App->>MQ: publish sat.request
    Worker->>MQ: consume sat.request
    Worker->>SAT: authenticate/submit request
    Worker->>PG: persist sat_request
    Worker->>SAT: verify request
    SAT-->>Worker: package ids
    Worker->>SAT: download metadata package
    Worker->>Storage: store raw package + hash
    Worker->>PG: upsert metadata ledger
    Worker->>PG: write reconciliation events
    Worker->>Redis: update progress
```

## XML sync flow

```mermaid
flowchart TD
    A["Find pending XML from metadata ledger"] --> B["Create XML request job"]
    B --> C["Submit SAT request"]
    C --> D["Verify until finished or terminal"]
    D --> E["Download ZIP package"]
    E --> F["Store raw ZIP with SHA-256"]
    F --> G["Extract XML files"]
    G --> H["Store XML evidence with SHA-256"]
    H --> I["Detect CFDI version"]
    I --> J["Parse known common fields"]
    J --> K{"Known complement?"}
    K -->|Yes| L["Normalize complement"]
    K -->|No| M["Preserve raw payload and mark parser_status=partial"]
    L --> N["Update cfdi_documents"]
    M --> N
    N --> O["Mark reconciliation downloaded_xml"]
```

## Unified recovery flow

```mermaid
sequenceDiagram
    participant User
    participant CLI
    participant Worker
    participant Storage
    participant DB as PostgreSQL

    User->>CLI: recover/sync criteria
    CLI->>DB: create job
    Worker->>Storage: store package ZIP
    Worker->>DB: register package path
    Worker->>Storage: store extracted XML
    Worker->>DB: register XML path and hash
    Worker->>DB: load normalized accounting data
    Worker->>DB: update reconciliation state
    User->>CLI: storage locate UUID / search / show
    CLI-->>User: local XML path + loaded data status
```

## Queue state machine

```mermaid
stateDiagram-v2
    [*] --> pending
    pending --> running: worker picked job
    running --> succeeded: completed
    running --> retry_scheduled: retryable failure
    retry_scheduled --> pending: delay elapsed
    running --> manual_review: ambiguous domain state
    running --> failed: non-retryable failure
    retry_scheduled --> dead_letter: attempts exhausted
    failed --> [*]
    succeeded --> [*]
    manual_review --> [*]
    dead_letter --> [*]
```

## Reconciliation states

| State | Meaning | User/operator message |
|---|---|---|
| `metadata_seen` | Metadata exists but XML need is not classified. | "Metadata found; XML classification pending." |
| `pending_xml` | XML is expected and missing. | "XML is pending; a recovery job can be scheduled." |
| `downloaded_xml` | XML evidence exists with hash. | "XML evidence is stored." |
| `cancelled_no_xml_expected` | Cancelled document should not trigger blind XML retries. | "Cancelled CFDI; no automatic XML retry." |
| `expired_package_retryable` | Package expired before evidence was stored. | "Package expired; create a recovery request." |
| `quota_limited` | SAT quota/limits prevent progress. | "SAT limit reached; retry later." |
| `manual_review` | Evidence/status conflict. | "Manual review required; inspect request/package history." |

## Error contract

Every error shown to a user should include:

- internal code;
- SAT code/message when available;
- user message;
- developer detail;
- next action;
- retryability;
- correlation id;
- job/request/package identifiers when available.
