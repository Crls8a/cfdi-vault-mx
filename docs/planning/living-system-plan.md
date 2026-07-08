# Living system plan

CFDI Vault MX should grow as a living case study: the reusable Python library and the reference system evolve together, but each change must preserve clear product boundaries, security gates, source-of-truth documents, and reviewable work units.

## Decision

The repository will use Markdown docs, ADRs, tests, and release gates as the source of truth for what the project promises. Code should follow those contracts instead of inventing behavior from scattered notes, old prompts, or assumptions.

## Quick path

1. Keep the library/package track and the reference-system track visibly separate.
2. Keep the security model current before expanding SAT, credential, storage, or release behavior.
3. Keep diagrams and flows aligned with implemented boundaries.
4. Keep source policies explicit: official, runtime, community oracle, historical, or rejected.
5. Commit completed objective/planning/doc changes as reviewable work units.

## What must be true before the case study feels complete

| Area | Outcome | Current source | Gap to close |
|---|---|---|---|
| Product boundary | Readers understand library vs reference system. | `docs/product-archetype.md` | Keep package docs from implying full system readiness. |
| System objective | Readers understand the problem, non-goals, and value. | `README.md`, `docs/foundation/product-scope.md` | Add a concise case-study narrative after architecture gates stabilize. |
| Architecture | Diagrams show context, containers, ports, adapters, and trust boundaries. | `docs/foundation/architecture-blueprint.md` | Add explicit trust-boundary and package-vs-system annotations. |
| Flows | Metadata, XML, recovery, retry, and reconciliation flows are diagrammed. | `docs/foundation/flows-and-states.md` | Add release/API consumer flow for the library track. |
| Data model | Durable truth, transient state, evidence storage, and search are justified. | `docs/foundation/data-and-accounting-model.md` | Keep PostgreSQL-only decisions synced with ADRs and tests. |
| Security | Sensitive data, e.firma, credentials, logs, fixtures, and live SAT gates are clear. | `docs/security-model.md`, `docs/security/e-firma-custody-threat-model.md` | Promote security model from legacy phase-one wording to v2 living threat model. |
| Source truth | SAT v1.5 claims identify evidence levels and rejected sources. | `docs/sat-download/source-policy.md`, `docs/sat-download/sources.md` | Add a traceability table from claims to tests/docs before release. |
| Library contract | PyPI users know supported imports, internal modules, and maturity. | `docs/release/python-package-plan.md` | Define public API contract and external consumer example. |
| Verification | Reviewers can prove docs, scanner, tests, packaging, and security gates passed. | CI, scanner, test docs, release plan | Add a single release-readiness checklist. |

## Security workstream

Security is not a final checklist; it is a design input. The project handles fiscal workflows and e.firma references, so every expansion must answer:

| Question | Required answer |
|---|---|
| What data enters the system? | Classify it as synthetic, public, operational, sensitive, secret, credential, or real fiscal data. |
| Where is durable truth? | PostgreSQL for state; filesystem/object storage for raw evidence references and hashes. |
| What must never be committed? | Real CFDI, real SAT metadata, ZIPs, certificates, keys, passwords, tokens, private keys, local profiles, and runtime databases. |
| What crosses a trust boundary? | Live SAT, e.firma, secret providers, external storage, package downloads, and public package publishing. |
| What proves safety? | Scanner, tests, redaction rules, fixture policy, documented opt-ins, and human gates for real SAT/e.firma. |

## Source-of-truth hierarchy

| Source | Wins for |
|---|---|
| `AGENTS.md` | Repository operating rules, gates, and forbidden data. |
| `docs/product-archetype.md` | Library vs reference-system positioning. |
| `docs/security-model.md` | Sensitive data and safety boundaries until a newer security ADR replaces it. |
| `docs/security/e-firma-custody-threat-model.md` | Local e.firma custody assumptions and non-goals. |
| `docs/sat-download/source-policy.md` | SAT v1.5 contract source classification. |
| ADRs under `docs/adr/` | Irreversible or high-impact architecture decisions. |
| Tests and scanner | Executable proof that claims still hold. |

If two documents conflict, update the source-of-truth document first, then update dependent docs and code.

## Next work units

| Priority | Work unit | Acceptance |
|---:|---|---|
| 1 | Security model v2 refresh | `docs/security-model.md` reflects PostgreSQL-first recovery, library/reference split, fixture policy, e.firma custody, logging/redaction, and live SAT gates. |
| 2 | Architecture diagram audit | Context/container/component/data-flow diagrams show library package, reference CLI/runtime, trust boundaries, and planned API/worker flow. |
| 3 | Source traceability matrix | Public SAT v1.5 claims link to `V1_5_CONTRACT`, `RUNTIME_WSDL`, `COMMUNITY_ORACLE`, tests, or explicit uncertainty. |
| 4 | Public API contract | Supported `cfdi_vault` imports, internal modules, semantic versioning policy, and examples are documented before PyPI. |
| 5 | Case-study narrative | A reader can understand why the system exists, what it teaches, what is fake/offline, and how to contribute safely. |
| 6 | Release-readiness checklist | One checklist proves scanner, tests, package build, TestPyPI, docs, security gates, and disclaimer review. |

## Operating rule

When a planning, objective, architecture, or security work unit is complete, commit it with a Conventional Commit message and leave unrelated dirty files unstaged.
