---
name: cfdi-library-quality
description: "Trigger: cfdi_vault library, public API, PyPI, package release. Enforce library quality gates before code changes."
license: Apache-2.0
metadata:
  author: gentleman-programming
  version: "1.0"
---

## Activation Contract

Use this skill before creating or changing reusable `cfdi_vault` library behavior, public APIs, package metadata, release gates, SAT download modules, parsers, ports, or CLI commands intended for package users.

## Hard Rules

- Load `docs/release/library-quality-contract.md` before designing or changing public behavior.
- Preserve the library vs reference-system boundary from `docs/product-archetype.md`.
- Public API requires type hints, docstrings, tests, documented errors/side effects, and release-safe claims.
- Private helpers need docstrings only when behavior is non-obvious or security/SAT/persistence-sensitive.
- Never introduce live SAT, e.firma, secrets, real CFDI, real SAT metadata, ZIPs, RFCs, or local paths without the human/security gate.
- Do not promote probes, live gates, or internal modules to public API by convenience.

## Decision Gates

| Situation | Required action |
|---|---|
| New public API | Define contract, tests, docs, and export policy first. |
| SAT download behavior | Classify the source using `docs/sat-download/source-policy.md`. |
| Security or credential behavior | Stop unless the security model and human gate allow it. |
| Existing code audit | Classify public, internal, and reference-system surfaces before fixing. |
| Release/package change | Follow `docs/release/python-package-plan.md`. |

## Execution Steps

1. Identify whether the work is library/package or reference-system/case-study.
2. Read the library quality contract and relevant source/security docs.
3. Define the smallest work unit and expected public contract.
4. Add or verify tests and docs in the same unit.
5. Run the scanner and required tests/checks before commit.
6. Report non-compliant existing behavior as audit findings before broad refactors.

## Output Contract

Return:
- API surface changed or audited.
- Tests/checks run.
- Docs updated.
- Security/source gates considered.
- Known gaps before release.

## References

- `docs/release/library-quality-contract.md`
- `docs/release/python-package-plan.md`
- `docs/product-archetype.md`
- `docs/planning/living-system-plan.md`
- `docs/security-model.md`
- `docs/sat-download/source-policy.md`
