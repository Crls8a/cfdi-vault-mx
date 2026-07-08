# Architecture

CFDI Vault MX uses a PostgreSQL-backed architecture: CLI and future API entrypoints call application services, services use parser/reconciliation modules, and PostgreSQL stores durable import, recovery, audit, and accounting state.

## Quick path

```text
CLI / future FastAPI -> Application services -> Parser / Reconciliation
                                       \-> SQLAlchemy -> PostgreSQL
                                       \-> RabbitMQ / Redis / Storage ports
                                       \-> CSV / HTML / PDF export
```

## Components

| Component | Responsibility | Boundary |
|---|---|---|
| `cli.py` | User commands and output formatting. | No SAT protocol logic or persistence rules. |
| `service.py` | Synthetic import, dedupe, summary, and export use cases. | Uses PostgreSQL through `DATABASE_URL`. |
| `recovery_service.py` | Fake SAT recovery, package/XML evidence registration, search, print/export, and reconciliation. | Uses ports for queue, cache, SAT, and storage. |
| `parser.py` / `cfdi_parser.py` | XML-to-domain-field extraction. | No database or CLI concerns. |
| `db.py` | PostgreSQL engine and base model setup. | Requires explicit `DATABASE_URL`. |
| `recovery_db.py` | Recovery/accounting tables. | PostgreSQL runtime schema. |
| `queueing.py` | In-memory test queue and RabbitMQ adapter. | Queue messages carry IDs/references, not raw XML or secrets. |
| `cache.py` | In-memory test cache and Redis adapter. | Transient state only. |
| `tests/` | Regression contract. | Synthetic data only; database tests use PostgreSQL. |

## Data model

| Field group | Stored values |
|---|---|
| Identity | tenant, UUID, issuer RFC/name, receiver RFC/name. |
| Document | issue date, subtotal, total, currency, comprobante type. |
| Recovery | job, SAT request, package, XML evidence, reconciliation state. |
| Audit | XML/package SHA-256, storage key, source name, imported timestamp, queue events. |
| Flexible payload | JSONB-compatible CFDI/complement payloads. |

## Design decisions

| Decision | Why |
|---|---|
| PostgreSQL only | Avoids a mixed runtime and keeps Flyway migrations, indexes, JSONB payloads, audit, and search in one durable database. |
| UUID dedupe | CFDI UUID is the stable document identity. |
| SHA-256 per XML/package | Gives repeatable file-level traceability without trusting parser output alone. |
| Typer CLI | Keeps workflows scriptable and testable before UI concerns. |
| FastAPI boundary planned | Stored XML/package references should enter gradual ingestion through an API/queue/worker boundary. |
| Parser is namespace-tolerant | CFDI prefixes can vary while local element names remain meaningful. |

## Next step

For persistence work, add Flyway migrations and PostgreSQL-specific indexes deliberately. Do not add another database runtime.
