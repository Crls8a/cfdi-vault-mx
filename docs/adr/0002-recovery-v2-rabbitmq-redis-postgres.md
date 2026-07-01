# ADR 0002: RabbitMQ, Redis, and PostgreSQL recovery architecture

## Status

Accepted.

## Decision

CFDI Vault MX v2 uses:

- RabbitMQ for durable recovery jobs and worker handoff;
- Redis for transient progress, locks, token cache, and local rate-limit state;
- PostgreSQL as the durable source of truth;
- PostgreSQL JSON/JSONB-style payload columns for CFDI version and complement variability;
- PostgreSQL search in v1 before adding OpenSearch/Elasticsearch.

## Why

CFDI recovery is not a simple download. It needs request tracking, package lifecycle, reconciliation, retry visibility, accounting search, and audit evidence. Splitting responsibilities avoids turning one CLI command into a fragile God object.

## Consequences

- The application layer depends on ports, not concrete infrastructure.
- Local tests can use SQLite, in-memory queue/cache, and fake SAT.
- Docker Compose is the recommended local/dev path.
- Live SAT remains opt-in and blocked until the signing/security slice is reviewed.
