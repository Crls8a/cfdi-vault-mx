# Architecture

CFDI Vault MX uses a PostgreSQL-backed architecture: CLI and future API entrypoints call application services, services use parser/reconciliation modules, and PostgreSQL stores durable import, recovery, audit, and accounting state.

## Quick path

```text
CLI shim -> CLI family adapters -> Application services -> Parser / Reconciliation
                                               \-> SQLAlchemy -> PostgreSQL
                                               \-> RabbitMQ / Redis / Storage ports
                                               \-> CSV / HTML / PDF export
Future FastAPI boundary -----------------------^
```

## Components

| Component | Responsibility | Boundary |
|---|---|---|
| `cli.py` | Compatibility shim for `cfdi_vault.cli:app`. | No command logic. |
| `adapters/cli/` | Typer command families, app composition, input parsing, and output formatting. | No business rules beyond adapter-level validation and exit codes. |
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
| CLI adapter family split | Keeps command ownership explicit and prevents a root `cli.py` God object. |
| FastAPI boundary planned | Stored XML/package references should enter gradual ingestion through an API/queue/worker boundary. |
| Parser is namespace-tolerant | CFDI prefixes can vary while local element names remain meaningful. |

## Next step

For persistence work, keep Flyway migrations and PostgreSQL-specific indexes as the source of truth. Do not add another database runtime.
