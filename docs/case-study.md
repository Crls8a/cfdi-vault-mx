# Case study: local-first CFDI data lab

CFDI Vault MX demonstrates how to build a backend/data product around sensitive document formats without starting from real taxpayer data. The case study prioritizes boundaries, repeatability, and auditability over feature volume.

## Quick path

1. Start with fake CFDI-like XML.
2. Normalize only the required fields.
3. Store and query the data in PostgreSQL.
4. Prove behavior with tests.
5. Expand only after security boundaries are explicit.

## Learning goals

| Audience | What they learn |
|---|---|
| Backend engineers | CLI use cases, parser boundaries, persistence, dedupe. |
| Data engineers | Normalized facts, aggregate summaries, CSV export. |
| Security reviewers | Local-first threat model and explicit phase-one exclusions. |
| Architects | How to preserve future options without overbuilding. |

## Narrative

Phase one treats CFDI/XML as a data-ingestion problem, not as a tax authority integration problem. That distinction matters. Importing XML, computing a hash, and summarizing totals are local operations. Validating with SAT, handling e.firma, or uploading certificates are trust-boundary changes and must be designed separately.

## Review checklist

- [ ] Examples are synthetic and clearly labeled.
- [ ] UUID is the dedupe key.
- [ ] Raw XML hash is computed before persistence.
- [ ] Summary output can be reproduced from the local DB.
- [ ] No code path requires secrets or external SAT access.

## Next step

Use this repository to discuss phase-two tradeoffs: richer validation, schema migrations, encrypted storage, or a UI. Do not mix those concerns into phase one. The system uses PostgreSQL/RabbitMQ/Redis for its runtime infrastructure; see `foundation/infrastructure-boundary.md`.
