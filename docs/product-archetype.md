# Product split: library and reference system for SAT CFDI recovery

CFDI Vault MX has two related but different goals: a reusable Python library and a reference system/case study. Keeping both in one repository is acceptable while the architecture matures, but the documentation must make the boundary obvious so users know what is published, what is reusable, and what is only an example system.

## Decision

| Track | Primary audience | Deliverable | Success means |
|---|---|---|---|
| Library / package | Python developers and maintainers | `cfdi-vault-mx` distribution with supported `cfdi_vault` APIs. | Another repo can install the package and reuse stable building blocks without cloning this repo. |
| Reference system / case study | Operators, accountants, contributors, and learners | CLI, Docker/local runtime, docs, examples, and architecture walkthrough. | A person can understand how to manage, inspect, and reconcile CFDI recovery in a safe fake/offline-first system. |

The library may include a CLI entrypoint for developer ergonomics, but the package release must not imply that the complete reference system is installed or production-ready.

## Status disclaimer

This is a development-stage case study and reference implementation. It should teach a safe architecture and provide reusable building blocks, but it must not overstate maturity.

| We can claim | We must not claim yet |
|---|---|
| The repo demonstrates a fake/offline-first CFDI recovery architecture. | The project is a certified or production-ready tax solution. |
| The library code is being prepared as an installable Python package. | The package is already available from PyPI before publication happens. |
| The library can become a reusable integration surface. | Every internal module is stable public API. |
| The reference system is a case study for the architecture. | The case study is a certified accounting/tax product. |
| Live SAT work is gated and explicit. | Live SAT automation works by default. |

If someone wants to use it beyond the documented fake/offline case-study boundary, they should open a GitHub issue first so expectations, risks, and missing gates are clear.

## Quick path

1. Treat the Python package as the reusable library track.
2. Treat this repository's CLI/runtime/docs as the reference-system track.
3. Use the CLI to prove the operator flow: setup, doctor, sync, queue status, search, show, print, and export.
4. Use fake/offline SAT adapters to test request, verify, package, storage, parser, and reconciliation behavior without live credentials.
5. Publish the package only after the API, security, fixture, and release gates are explicit.

## Problem

The user problem is not merely "download my invoices." The real problem is that SAT CFDI recovery has no simple, current, developer-friendly flow for Descarga Masiva v1.5. Teams need to know:

- what was requested;
- what SAT accepted, rejected, or delayed;
- which packages were downloaded before they expired;
- which XML files were stored and parsed;
- which UUIDs remain pending, cancelled, unavailable, or manual-review;
- which errors are retryable and which need a human.

Without that model, projects become one-off scripts with hidden credential risk, duplicate SAT requests, weak audit evidence, and hard-to-review parser logic.

## Solution shape

| Artifact | What it solves | Current boundary |
|---|---|---|
| Python library | Lets other repositories reuse request models, ports, parsers, storage, queue, cache, and reconciliation logic. | Public API still needs a stable contract before PyPI release. |
| Reference system | Gives operators and contributors a visible workflow for a personal/local CFDI vault. | Fake/offline first; live SAT remains explicitly gated. |
| Fake SAT and fixtures | Makes CI and examples safe without real taxpayer data or credentials. | Must stay synthetic and scanner-protected. |
| Foundation docs | Explain architecture, storage, queues, worker boundaries, errors, and release sequencing. | Must be kept ahead of implementation. |
| SAT v1.5 source policy | Prevents old manuals, forum snippets, or stale prompts from becoming implementation truth. | v1.5 contract wins; WSDL/oracle conflicts are documented, not guessed. |

## Design principles

- **Metadata first**: metadata is the control plane for deciding what XML recovery is needed.
- **Evidence before parsing**: store and hash raw packages/XML before normalization.
- **Ports before adapters**: domain and application code should not know RabbitMQ, Redis, PostgreSQL, Typer, or SAT SOAP details.
- **CLI as first UI**: commands must be scriptable, explicit, and safe under failure.
- **No silent live SAT**: live access needs lawful credentials, redacted evidence, explicit opt-in, and human gate approval.
- **Reference over magic**: the project should teach the flow clearly enough that another team can reproduce the architecture.

## Current fit

| Area | Status |
|---|---|
| Library package | Distribution name is `cfdi-vault-mx`; import package is `cfdi_vault`. |
| Reference CLI | `cfdi-vault` exists through `pyproject.toml` scripts and demonstrates the system workflow. |
| Fake/offline recovery | Implemented enough for local examples, tests, and recovery-v2 docs. |
| Durable runtime target | PostgreSQL for recovery data, RabbitMQ for jobs, Redis for transient state. |
| Local reference runtime | PostgreSQL remains the single database for synthetic import, recovery demos, tests, and future production-oriented paths. |
| Live SAT | Not default; gated until signing, credential custody, and compliance work are accepted. |

## Areas of opportunity

| Gap | Why it matters | Next document |
|---|---|---|
| Public API contract | PyPI users need stable imports, not accidental internal modules. | `docs/release/python-package-plan.md` |
| Package release workflow | Users should install with `pip`, not clone the repository. | `docs/release/python-package-plan.md` |
| Example consumer project | The reference system should show how another repo imports the library. | Future `examples/library-consumer/` |
| API stability markers | Internal SAT probing code should not look like supported API. | Future API reference docs |
| Release claims | The first release must be honest: fake/offline alpha, not live SAT production promise. | Release checklist |

## Acceptance checklist

- [ ] README states the problem, the reference system, and the library separately.
- [ ] Package docs do not imply the full reference system is installed or production-ready.
- [ ] Docs show the intended CLI flow and the reusable Python integration surface.
- [ ] Backlog includes package release tasks.
- [ ] PyPI plan uses Trusted Publishing, TestPyPI, build checks, scanner, and tests.
- [ ] Public release notes clearly state live SAT limitations.
