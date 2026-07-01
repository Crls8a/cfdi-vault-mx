# Architecture

CFDI Vault MX uses a small local-first architecture: CLI commands call an application service, the service uses a parser and repository model, and SQLite stores normalized synthetic invoice records.

## Quick path

```text
CLI -> VaultService -> Parser
                  \-> SQLAlchemy -> SQLite
                  \-> CSV export
```

## Components

| Component | Responsibility | Boundary |
|---|---|---|
| `cli.py` | User commands and output formatting. | No business rules beyond exit codes. |
| `service.py` | Import, dedupe, summary, export use cases. | Owns workflow decisions. |
| `parser.py` | XML-to-domain-field extraction. | No persistence or CLI concerns. |
| `db.py` | SQLAlchemy model and engine setup. | Local SQLite only. |
| `tests/` | Regression contract. | Synthetic data only. |

## Data model

| Field group | Stored values |
|---|---|
| Identity | UUID, issuer RFC/name, receiver RFC/name. |
| Document | issue date, subtotal, total, currency, comprobante type. |
| Payment | payment method and payment form when present. |
| Audit | XML SHA-256, source name, imported timestamp. |

## Design decisions

| Decision | Why |
|---|---|
| SQLite default | Keeps the lab local, easy to inspect, and dependency-light. |
| UUID dedupe | CFDI UUID is the stable document identity for this phase. |
| SHA-256 per XML | Gives repeatable file-level traceability without storing raw XML. |
| Typer CLI | Keeps workflows scriptable and testable before UI concerns. |
| Parser is namespace-tolerant | CFDI prefixes can vary while local element names remain meaningful. |

## Next step

If the project adds migrations, introduce Alembic deliberately instead of hiding schema changes behind ad-hoc SQL.
