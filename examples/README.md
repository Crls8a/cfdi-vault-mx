# Examples

All examples in this folder must be synthetic. They are designed to exercise parser and CLI behavior without exposing real taxpayer data.

## Fixture provenance

| Path | Provenance |
|---|---|
| `synthetic-cfdi/` | Handwritten CFDI-like XML using fake names, fake UUIDs, and `SYN-*` RFC placeholders. |
| `config/` | Dummy local configuration examples using generic RFC placeholders and `local-dev-dummy://` credential references. |

## Rules

- Do not commit real CFDI XML.
- Do not commit redacted real invoices.
- Do not commit `.cer`, `.key`, passwords, SAT tokens, or credentials.
- Follow `docs/testing/fixture-policy.md`.
