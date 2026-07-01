# Product scope

CFDI Vault MX v2 is a recovery and reconciliation library for Mexican CFDI data. It is not just a downloader: it must prove what was requested, what SAT returned, what was stored, what could not be recovered, and why.

## Problem

Accounting teams need a repeatable way to recover CFDI metadata and XML evidence from SAT while keeping an audit trail. A simple "download everything" command is not enough because SAT requests are asynchronous, packages expire, documents can be cancelled, and parser support varies by CFDI version/complement.

## Users

| User | Needs |
|---|---|
| Developer | A Python library and CLI with clear ports, fake SAT, tests, and no forced credential storage. |
| Accountant/operator | Searchable CFDI records, download status, actionable errors, and export/print outputs. |
| Maintainer | Source-linked docs, isolated modules, safe fake fixtures, and reviewable work units. |

## Core capabilities

| Capability | v1 target |
|---|---|
| Metadata recovery | Submit request, verify, download packages, parse metadata ledger. |
| XML recovery | Download package, store raw ZIP/XML evidence, parse known fields. |
| Reconciliation | Explain whether each UUID is pending, downloaded, cancelled, expired, quota-limited, or manual-review. |
| Search | PostgreSQL-backed search by UUID, RFC, name, date, total, type, status, and concept text. |
| CLI UX | Start sync, inspect queue/progress, search/show/print/export, and run workers. |
| Local/dev install | Docker Compose with PostgreSQL, RabbitMQ, Redis, app, worker, storage, and logs. |

## Explicit non-goals for current slice

| Non-goal | Reason |
|---|---|
| Live SAT by default | Requires signing, lawful credentials, security review, and manual opt-in. |
| Storing e.firma password by default | Credential custody must be explicit and auditable. |
| Perfect official PDF recreation | v1 output should be clear and auditable first. |
| MongoDB | PostgreSQL JSONB covers variable CFDI/complement payloads for v1. |
| OpenSearch/Elasticsearch | PostgreSQL full-text/trigram search is enough until volume proves otherwise. |
| Full Carta Porte normalization | High complexity; should be a later scoped parser work unit. |

## Definition of done for a feature

- Has a documented flow.
- Has typed domain states.
- Has tests with fake SAT or fixtures.
- Does not require live SAT in CI.
- Preserves raw evidence before parsing.
- Emits user-facing errors or operator states.
- Updates this foundation folder if it changes architecture.
