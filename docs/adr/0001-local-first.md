# ADR 0001: Start with a local synthetic architecture

Accepted: 2026-07-01

CFDI Vault MX started as a local CLI using synthetic data only. This kept the architecture reviewable while avoiding premature trust-boundary and compliance risks.

## Context

CFDI data can be sensitive. A public case study must teach import, parsing, storage, summaries, and export without encouraging people to upload real taxpayer documents or credentials.

## Decision

Build phase one as:

- Python 3.12-compatible package.
- Typer CLI named `cfdi-vault`.
- SQLAlchemy persistence behind an explicit database boundary.
- Synthetic XML fixtures only.
- No SAT integration, no e.firma upload, no dashboard.

## Consequences

| Outcome | Tradeoff |
|---|---|
| Easy local setup | No multi-user collaboration yet. |
| Safer public examples | Cannot prove real SAT validation behavior. |
| Clear use-case boundaries | Some production concerns are intentionally deferred. |
| Testable CLI workflows | UI learning is out of scope for now. |

## Review checklist

- [ ] Local commands work without network access.
- [ ] No real taxpayer data is required.
- [ ] Future real-data features require a new ADR.

## Next step

Use this ADR as the guardrail for phase-one reviews.
