# Fixture and fake-data policy

This policy defines which test data is allowed in CFDI Vault MX. The goal is simple: contributors must be able to test SAT/CFDI behavior without committing real taxpayer data.

## Decision

Only synthetic, generated, or fake SAT data is allowed in this repository. Real CFDI XML, real taxpayer names, real RFCs, certificates, keys, passwords, SAT tokens, and real SAT responses are forbidden.

## Quick path

1. Use `SYN-*` placeholders for examples whenever a parser does not require an RFC-shaped value.
2. Use documented fake/generic placeholders only when a test specifically needs an RFC-shaped value.
3. Document fixture provenance in the folder that stores the fixture.
4. Add a safety scan before accepting production-facing fixture work.

## Allowed fixture categories

| Category | Allowed? | Requirements |
|---|---:|---|
| Synthetic CFDI-like XML | Yes | Must use fake names, fake UUIDs, fake RFC placeholders, and no real business data. |
| Generated unit-test XML | Yes | Must be built from constants or factories, not copied from real invoices. |
| Fake SAT metadata/responses | Yes | Must be deterministic and clearly labeled as fake SAT. |
| Malformed XML fixtures | Yes | Must be handcrafted or generated. |
| Public documentation snippets | Review required | Must be minimal, attributed when needed, and must not include taxpayer data. |
| Redacted real CFDI | No | Redaction is easy to get wrong; do not commit it. |
| Real CFDI XML | No | Forbidden. |
| `.cer`, `.key`, passwords, tokens, secrets | No | Forbidden. |

## RFC strategy

| Use case | Preferred value |
|---|---|
| XML examples where exact RFC validation is not required | `SYN-ISSUER-001`, `SYN-RECEIVER-001`, or similar `SYN-*` placeholders. |
| Fake SAT/domain flows that need an RFC-shaped requester | `XAXX010101000` as a documented fake/generic placeholder. |
| Existing parser unit tests with RFC-like tokens | `AAA010101AAA` and `BBB010101BBB` are temporary synthetic test tokens; new tests should prefer `SYN-*` unless RFC shape is required. |

## Folder rules

| Path | Rule |
|---|---|
| `examples/` | Must contain only synthetic examples and a README explaining provenance. |
| `tests/` | Must contain generated fixtures, inline synthetic XML, or fake SAT payloads only. |
| `storage/` | Local runtime output only; never commit real packages or XML. |
| `logs/` | Local runtime output only; never commit logs with taxpayer or credential data. |

## Review checklist

- [ ] Fixture provenance is documented.
- [ ] No real XML was copied into the repo.
- [ ] No real taxpayer name or business data appears.
- [ ] No `.cer`, `.key`, password, token, or secret appears.
- [ ] RFC-like values are either `SYN-*`, documented fake/generic values, or existing temporary synthetic test tokens.
- [ ] Any new fixture category is added to this policy before use.

## Automation requirement

Sprint 0 defines this policy. A follow-up backlog item must add a fixture safety scanner that checks for:

- committed `.cer` or `.key` files;
- common secret variable names;
- real-looking RFC values outside the allow-list;
- SAT credential/token indicators;
- accidentally committed `storage/` or `logs/` runtime evidence.

## Next step

Track the scanner implementation through `QA-002` in `docs/planning/backlog.md`.
