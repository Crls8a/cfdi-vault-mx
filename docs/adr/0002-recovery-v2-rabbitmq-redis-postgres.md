# ADR 0002: RabbitMQ, Redis, and PostgreSQL recovery architecture

## Status

Accepted.

## Decision

CFDI Vault MX v2 uses:

- RabbitMQ for durable recovery jobs and worker handoff;
- Redis for transient progress, locks, token cache, and local rate-limit state;
- PostgreSQL as the durable source of truth;
- PostgreSQL JSON/JSONB-style payload columns for CFDI version and complement variability;
- PostgreSQL search in v1 before adding OpenSearch/Elasticsearch;
- a future FastAPI ingestion boundary for stored XML/package references before gradual worker loading into PostgreSQL.

## Why

CFDI recovery is not a simple download. It needs request tracking, package lifecycle, reconciliation, retry visibility, accounting search, and audit evidence. Splitting responsibilities avoids turning one CLI command into a fragile God object.

The heavy XML ingestion path must not be "download package, parse everything, and bulk write directly from one CLI/SAT process." Raw evidence is stored first; ingestion work is queued; workers load normalized PostgreSQL rows in controlled transactions.

## Consequences

- The application layer depends on ports, not concrete infrastructure.
- Local and CI tests should use a PostgreSQL test database, in-memory queue/cache where appropriate, and fake SAT.
- Recovery runtime documentation and Docker Compose must stay PostgreSQL-first.
- Docker Compose is the recommended local/dev path.
- Live SAT remains opt-in and blocked until the signing/security slice is reviewed.
- FastAPI should not be added to Docker Compose until the API implementation exists.
