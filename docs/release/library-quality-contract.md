# Library quality contract

The `cfdi-vault-mx` package must behave like a small, explicit Python library before it behaves like a large system. Every public API should have one responsibility, tests, documentation, and a release promise that matches the current maturity.

## Decision

Only documented public APIs are stable. Everything else is internal, experimental, or part of the reference system until promoted through this contract.

## Quick path

1. Define the public API before exporting a module, class, function, or CLI behavior.
2. Keep SAT download responsibilities split into request planning, signing/auth boundaries, request, verify, package download, parsing, storage, and reconciliation.
3. Add tests for behavior, edge cases, safety gates, and regression risks.
4. Add docstrings to public modules, classes, functions, and methods.
5. Update user docs or API docs when behavior becomes public.
6. Run scanner, tests, build, and artifact checks before release.

## Public API rule

| Surface | Rule |
|---|---|
| `cfdi_vault.__init__` | Export only stable names. Do not re-export internal/probe modules by convenience. |
| Public API docs | Every stable import must appear in [Repository public API plan](public-api.md). |
| Public module | Has a module docstring that says what the module owns and what it does not own. |
| Public class/function/method | Has type hints, a docstring, tests, and documented errors/side effects. |
| Private helper | Uses `_name`; docstring optional unless security, SAT behavior, parsing, persistence, or non-obvious side effects are involved. |
| Experimental SAT probe/live gate | Must remain internal or explicitly marked experimental; not part of semver stability. |
| CLI command | Public only when listed in help/docs and covered by CLI tests. |

## Responsibility split

| Responsibility | Library owns | Library must not do silently |
|---|---|---|
| Request model | Build, validate, normalize, and hash SAT criteria. | Submit duplicate or invalid criteria. |
| Signing/auth boundary | Define ports and safe in-memory behavior. | Store e.firma, passwords, keys, tokens, or raw secrets by default. |
| SAT request/verify/download | Provide typed clients/results and fake/offline adapters. | Call live SAT without explicit opt-in and human gate. |
| Package processing | Store/hash raw package bytes before extraction; parse metadata/XML safely. | Trust unvalidated ZIP/XML or skip evidence preservation. |
| Persistence boundary | Expose repository/service contracts for PostgreSQL-backed state. | Hide durable truth in process memory or Redis. |
| Queue/cache boundary | Define work messages and transient progress semantics. | Put raw XML, ZIP bytes, e.firma material, or secrets on queues/cache. |
| Reconciliation | Explain pending, downloaded, cancelled, unavailable, retryable, and manual-review states. | Blindly redownload without metadata/state reasoning. |
| User-facing errors | Return typed, redacted, actionable errors. | Leak RFCs, full SAT ids, raw SOAP, credentials, paths, or secrets. |

## Test gate

Every public library change needs the smallest meaningful tests in the same work unit.

| Change type | Required tests |
|---|---|
| Domain model or validation | Unit tests for valid, invalid, boundary, and serialization/hash behavior. |
| Parser | Fixture tests with synthetic data, malformed input, unknown complement/version, and no real taxpayer data. |
| SAT transport/client | Fake transport tests, header/action/body shape tests, typed error tests, no-live-CI guard. |
| Storage/persistence | Idempotency, duplicate handling, hash/path metadata, rollback/error behavior, PostgreSQL-backed tests. |
| Queue/cache | Message contract, retry/DLQ/progress behavior, no raw sensitive payloads. |
| CLI wrapper | Typer runner tests for success, errors, redaction, and help text. |
| Security-sensitive change | Scanner plus explicit tests for forbidden data, redaction, and opt-in gates. |
| Packaging/release | Build, `twine check`, clean install smoke, README/package metadata check. |

## Documentation gate

Do not document every private line of code. Do document every public contract.

| Target | Documentation requirement |
|---|---|
| Public module | Module docstring plus API/reference docs when promoted. |
| Public class | Purpose, invariants, important attributes, and subclassing expectations when relevant. |
| Public function/method | Summary, arguments, return value, side effects, exceptions, and restrictions when applicable. |
| Public errors | What happened, why it matters, and next action. |
| Public CLI command | Help text, example, safety boundary, and expected output shape. |
| Security or SAT behavior | Source classification, redaction policy, opt-in gate, and tests. |

PEP 257 and PEP 8 are the baseline for docstrings: public modules, functions, classes, and methods need docstrings; non-public methods do not need docstrings unless they are non-obvious, but they should have comments when needed.

## Release gate

Before a package release candidate:

- [ ] Public API list exists.
- [ ] SAT SOAP public surfaces link to [SAT download public API research and contract](../api/sat-download-public-api.md).
- [ ] Internal/probe/live modules are marked internal or excluded from public docs.
- [ ] `pyproject.toml` metadata is accurate.
- [ ] README states alpha/case-study limitations.
- [ ] Sensitive fixture scanner passes.
- [ ] Tests pass in the supported environment.
- [ ] Package builds source distribution and wheel.
- [ ] `twine check dist/*` passes.
- [ ] Clean install smoke proves imports and `cfdi-vault help`.
- [ ] TestPyPI smoke passes before PyPI.

## Official references

- [Python Packaging User Guide: Packaging Python Projects](https://packaging.python.org/en/latest/tutorials/packaging-projects/)
- [Python Packaging User Guide: Writing your `pyproject.toml`](https://packaging.python.org/en/latest/guides/writing-pyproject-toml/)
- [PEP 257: Docstring Conventions](https://peps.python.org/pep-0257/)
- [PEP 8: Documentation Strings](https://peps.python.org/pep-0008/#documentation-strings)
