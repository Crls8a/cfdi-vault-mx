# Architecture blueprint

The system uses Clean Architecture: domain rules do not know about RabbitMQ, Redis, PostgreSQL, FastAPI, Typer, or SAT SOAP. Infrastructure adapters satisfy ports.

For concrete module obligations, data ownership, MinIO/storage tradeoffs, parser responsibilities, and worktree execution rules, read [Module responsibilities and execution boundaries](module-responsibilities.md).

## System context

```mermaid
flowchart TD
    Operator["Operator / Developer"] --> CLI["CLI: Typer + terminal UI"]
    Operator --> API["FastAPI ingestion API (planned)"]
    CLI --> App["Application services"]
    API --> App
    App --> Domain["Domain rules and state machines"]
    App --> Ports["Ports / interfaces"]
    Ports --> PG["PostgreSQL"]
    Ports --> MQ["RabbitMQ"]
    Ports --> Redis["Redis"]
    Ports --> Storage["Package/XML/export storage"]
    Storage -. optional lab .-> MinIO["MinIO object storage"]
    Ports --> SAT["SAT SOAP services"]
    SAT -. fake mode .-> FakeSAT["Fake SAT fixtures"]
```

## Container view

```mermaid
flowchart LR
    CLI["app container / local CLI"] --> PG["postgres"]
    API["api container / planned FastAPI"] -. planned .-> PG
    API -. planned .-> MQ["rabbitmq"]
    API -. planned .-> Redis["redis"]
    API -. planned .-> Storage["./storage volume"]
    API -. future adapter .-> MinIO["minio (optional profile)"]
    CLI --> MQ
    CLI --> Redis
    CLI --> Storage
    MQ --> Worker["worker container"]
    Worker --> SAT["SAT SOAP or Fake SAT"]
    Worker --> PG
    Worker --> Redis
    Worker --> Storage
    Worker -. future adapter .-> MinIO
```

## Code boundaries

| Layer | Owns | Must not own |
|---|---|---|
| `domain` | Value objects, request criteria, states, hashes, invariants. | SQLAlchemy, RabbitMQ, Redis, Typer, network calls. |
| `application` | Use cases: sync, verify, download, parse, reconcile, search, print/export. | Credential storage details or concrete broker clients. |
| `ports` | Interfaces for SAT, signer, queue, cache, storage, repository, search, printer. | Business decisions. |
| `infrastructure` | PostgreSQL, RabbitMQ, Redis, SOAP, filesystem, Docker. | Domain rules. |
| `api` | FastAPI request/response boundary for ingestion and orchestration. | Long-running parsing loops, raw XML persistence, or secret custody. |
| `cli` | User commands, progress, formatting, exit codes. | SAT protocol logic or persistence rules. |

## Dependency rule

```mermaid
flowchart BT
    Infra["Infrastructure adapters"] --> Ports["Ports"]
    API["FastAPI API"] --> App["Application"]
    CLI["CLI"] --> App["Application"]
    App --> Ports
    App --> Domain["Domain"]
    Ports --> Domain
```

Outer layers depend inward. Inner layers never import outer adapters.

## Architectural decisions already accepted

| Topic | Decision |
|---|---|
| Queue | RabbitMQ for durable jobs and workers. |
| Cache | Redis for progress, locks, rate limits, token cache, and worker heartbeats. |
| Database | PostgreSQL as source of truth. |
| API boundary | FastAPI will mediate ingestion requests once API code exists; Docker Compose should only add an API service with that implementation. |
| XML ingestion | Stored XML/package references move through API/queue/worker before normalized PostgreSQL loading. |
| Storage adapter path | Filesystem remains the default reference-system store; Docker Compose exposes optional MinIO for adapter practice behind the storage port. |
| Flexible CFDI data | PostgreSQL JSONB-compatible payloads, not MongoDB. |
| Search | PostgreSQL full-text/trigram first; OpenSearch later only if volume requires it. |
| Local/dev | Docker Compose. |
| Live SAT | Explicit opt-in only. |
