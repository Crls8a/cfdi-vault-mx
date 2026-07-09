# Tests

Tests must use synthetic data only. Inline XML, builders, and fake SAT payloads must be generated or handwritten for this repository.

## Fixture provenance

| Source | Provenance |
|---|---|
| `tests/conftest.py` | Generated CFDI-like XML fixtures using synthetic names and RFC placeholders. |
| `tests/test_cfdi_parser.py` | Inline XML parser fixture with temporary synthetic RFC-like tokens. |
| `tests/test_parser_version_matrix.py` | Declarative matrix checks plus generated synthetic income, expense, payments, payroll, and unknown-complement shapes; no runtime extractor claim. |
| `tests/test_config.py` | Safe RFC profile configuration validation using dummy references only. |
| `tests/test_domain.py` | Domain normalization tests using temporary synthetic RFC-like tokens and fake/generic requester values. |
| `tests/test_recovery_service.py` | Fake SAT recovery flow using fake/generic requester values. |
| `tests/test_sat_contract.py` | SAT code/state classification tests using synthetic codes and no real payloads. |
| `tests/test_sat_orchestration.py` | Metadata-first simulated orchestration tests using fake SAT scenarios and allow-listed RFC-like placeholders. |
| `tests/test_sat_simulator.py` | Fake SAT scenario tests with handcrafted synthetic SOAP/XML-like strings and package bytes. |
| `tests/test_secret_provider.py` | SecretProvider boundary tests using synthetic in-memory credential values and redacted audit records. |
| `tests/test_windows_secret_adapter.py` | Windows Credential Manager adapter tests using an injected in-memory backend and no OS credential store. |

## Rules

- Do not copy real XML into tests.
- Do not use real taxpayer names.
- Do not add certificates, keys, passwords, tokens, or SAT credentials.
- Follow `docs/testing/fixture-policy.md`.
