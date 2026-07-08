# Library compliance audit plan

This audit turns the package quality rules into an execution path. The goal is to prove that `cfdi_vault` is cleanly separated from the reference system before any PyPI/TestPyPI release claim.

## Decision

Audit first, then refactor. Do not broaden the public API, publish the package, or promise production SAT behavior until the audit report maps each current surface to the library quality contract.

## Quick path

1. Load `skills/cfdi-library-quality/SKILL.md` before assigning any agent to library work.
2. Inventory `src/cfdi_vault` and classify each surface as public library, internal library, reference-system/CLI, or experimental/live-gate.
3. Compare public candidates against `library-quality-contract.md`.
4. Record findings in `docs/release/library-compliance-audit-report.md`.
5. Convert findings into small work-unit commits before release validation.

## Audit scope

| Area | Verify |
|---|---|
| Product boundary | The package and the reference system are described as different deliverables. |
| Public API | Stable exports are explicit, narrow, typed, documented, and tested. |
| Internal modules | Probes, live gates, and case-study helpers are not accidentally promised as semver-stable API. |
| CLI | Documented commands have tests, redacted errors, and fake/offline defaults where required. |
| SAT/source behavior | Every SAT behavior has source classification and opt-in gates. |
| Security | No real CFDI, SAT metadata, ZIPs, RFCs, local paths, e.firma material, passwords, tokens, or secrets are added. |
| Packaging | Build, artifact checks, clean install smoke, TestPyPI, and PyPI steps remain separate gates. |

## Required evidence

| Evidence | Minimum output |
|---|---|
| Source inventory | Table of modules/packages with owner, stability, tests, and docs. |
| Public API review | List of names allowed from `cfdi_vault.__init__` or public docs. |
| Test review | Passing targeted tests or a documented blocker with exact command and reason. |
| Documentation review | Links to README, release plan, API docs, limitations, and disclaimers. |
| Security review | Scanner result plus review of redaction, fake data, live SAT, and credential boundaries. |

## Finding levels

| Level | Meaning |
|---|---|
| CRITICAL | Blocks packaging or release because it can leak sensitive data, misrepresent maturity, or expose unsafe public API. |
| WARNING | Blocks promotion of a module or command to supported public API. |
| SUGGESTION | Improves maintainability, examples, or contributor experience without blocking alpha packaging. |

## Execution plan

### Phase 1: Separation audit

- Confirm docs distinguish the installable library from the reference system/case study.
- Mark any mixed wording that makes the reference system sound like a certified product.
- Check that package docs do not promise live SAT, e.firma custody, tax/accounting certification, or complete parser coverage.

### Phase 2: Current implementation audit

- Inventory `src/cfdi_vault` modules.
- Identify accidental public surfaces caused by importability, CLI help, README examples, or package metadata.
- Compare public candidates against type hints, docstrings, tests, documented errors, and side-effect rules.

### Phase 3: Remediation plan

- Split findings into reviewable work units.
- Keep docs/tests with the code behavior they validate.
- Require human gate for security, schema/storage, live SAT, e.firma, or irreversible architecture changes.

### Phase 4: Release-readiness check

- Build source distribution and wheel.
- Run artifact checks.
- Run clean install smoke.
- Publish only to TestPyPI first.
- Promote to PyPI only after TestPyPI smoke passes and release disclaimers match the actual supported surface.

## Acceptance checklist

- [ ] Project skill is registered for future agents.
- [ ] Library vs reference-system separation is audited.
- [ ] Public API list exists and excludes internal/probe/live-gate modules.
- [ ] Public API candidates satisfy tests, docstrings, docs, and typed error expectations.
- [ ] Security/source gates are reviewed before any release claim.
- [ ] A remediation plan exists before implementation begins.

## Related sources

- `skills/cfdi-library-quality/SKILL.md`
- `docs/release/library-quality-contract.md`
- `docs/release/python-package-plan.md`
- `docs/product-archetype.md`
- `docs/planning/living-system-plan.md`
- `docs/security-model.md`
- `docs/sat-download/source-policy.md`
