# Tests

Tests must use synthetic data only. Inline XML, builders, and fake SAT payloads must be generated or handwritten for this repository.

## Fixture provenance

| Source | Provenance |
|---|---|
| `tests/conftest.py` | Generated CFDI-like XML fixtures using synthetic names and RFC placeholders. |
| `tests/test_cfdi_parser.py` | Inline XML parser fixture with temporary synthetic RFC-like tokens. |
| `tests/test_config.py` | Safe RFC profile configuration validation using dummy references only. |
| `tests/test_domain.py` | Domain normalization tests using temporary synthetic RFC-like tokens and fake/generic requester values. |
| `tests/test_recovery_service.py` | Fake SAT recovery flow using fake/generic requester values. |

## Rules

- Do not copy real XML into tests.
- Do not use real taxpayer names.
- Do not add certificates, keys, passwords, tokens, or SAT credentials.
- Follow `docs/testing/fixture-policy.md`.
