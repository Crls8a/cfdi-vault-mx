# Library compliance audit report

This report audits the current `cfdi_vault` package boundary against the library quality contract. The result is: **not release-ready yet**, but the separation direction is sound and the safest next move is a narrow public API definition before any PyPI/TestPyPI claim.

## Audit decision

Do not publish or promote the current package as a supported public library yet.

The repository now documents the library vs reference-system split correctly, tests pass, and the root package only exports `__version__`. However, the stable public API list, license file, API docs, and public docstring cleanup are still incomplete.

## Evidence run

| Check | Result |
|---|---|
| Sensitive fixture scanner | Passed: `Sensitive fixture scan passed: no forbidden files or content found.` |
| Full tests | Passed: `372 passed, 23 skipped` |
| Targeted package/library tests | Passed: `50 passed, 3 skipped` |
| Installed CLI help smoke | Passed: `cfdi-vault --help` renders commands. |
| Source inventory | 53 Python modules under `src/cfdi_vault`. |
| Baseline | Branch `test/sat-v15-verify-live-gate` working tree on 2026-07-08; unrelated WIP files were present. |

Commands used:

```powershell
.\.venv\Scripts\python.exe scripts\scan_sensitive_fixtures.py
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe -m pytest tests/test_packaging_alpha.py tests/test_import.py tests/test_domain.py tests/test_cfdi_parser.py tests/test_parser.py tests/test_metadata_parser.py tests/test_package_processor.py tests/test_reconciliation.py tests/test_sat_simulator.py tests/test_sensitive_fixture_scanner.py -q
.\.venv\Scripts\cfdi-vault.exe --help
```

## What is already healthy

| Area | Evidence | Decision |
|---|---|---|
| Product boundary | `README.md`, `docs/product-archetype.md`, and `docs/release/python-package-plan.md` distinguish package vs reference system. | Keep. This is the right framing. |
| Root package export | `src/cfdi_vault/__init__.py` exports only `__version__`. | Good. No accidental broad public API through `__all__`. |
| Tests | Full suite and targeted package/library suite pass. | Good baseline for audit. |
| Safety scanner | Sensitive fixture scanner passes. | Good baseline, still required before every release/commit. |
| SAT source policy | `docs/sat-download/source-policy.md` exists and defines v1.5 source levels. | Keep using it before SAT behavior changes. |
| CLI entrypoint | `pyproject.toml` declares `cfdi-vault = "cfdi_vault.cli:app"`; installed help works. | Valid package entrypoint, but public support scope must be narrowed. |

## Source inventory

| Classification | Count | Modules |
|---|---:|---|
| Public root | 1 | `cfdi_vault` |
| Public candidates | 9 | `cfdi_vault.domain`, `cfdi_vault.ports`, `cfdi_vault.fake_sat`, `cfdi_vault.sat_simulator`, `cfdi_vault.parser`, `cfdi_vault.cfdi_parser`, `cfdi_vault.metadata_parser`, `cfdi_vault.package_processor`, `cfdi_vault.reconciliation` |
| Reference-system / CLI | 16 | `cfdi_vault.cli`, `cfdi_vault.db`, `cfdi_vault.recovery_db`, `cfdi_vault.recovery_service`, `cfdi_vault.service`, `cfdi_vault.storage`, `cfdi_vault.onboarding`, `cfdi_vault.setup*`, `cfdi_vault.queueing`, `cfdi_vault.cache`, `cfdi_vault.worker` |
| Experimental / live-gate | 10 | `cfdi_vault.live_permit`, `cfdi_vault.sat_live_smoke`, `cfdi_vault.sat_live_request_state`, `cfdi_vault.sat_verify_live_gate`, `cfdi_vault.sat_*_probe`, `cfdi_vault.sat_*_lint` |
| Internal SAT candidates | 13 | `cfdi_vault.sat_auth*`, `cfdi_vault.sat_contract`, `cfdi_vault.sat_orchestration`, `cfdi_vault.sat_transport`, `cfdi_vault.sat_soap*`, `cfdi_vault.sat_backfill`, `cfdi_vault.sat_async_verify` |
| Other internal support | 4 | `cfdi_vault.config`, `cfdi_vault.secrets`, `cfdi_vault.windows_secrets`, `cfdi_vault.xmlsig` |

## Public candidate review

| Module | Current evidence | Release decision |
|---|---|---|
| `cfdi_vault.parser` | Module docstring, public docstrings/type hints, tests pass. | Strong public candidate. |
| `cfdi_vault.ports` | Module docstring, protocols documented, tests reference status/ports. | Strong public candidate, but imports internal SAT/secret types; check dependency stability first. |
| `cfdi_vault.reconciliation` | Module docstring, public docstrings/type hints, tests pass. | Strong public candidate. |
| `cfdi_vault.sat_simulator` | Module docstring, public docstrings/type hints, tests pass. | Strong fake/offline public candidate. |
| `cfdi_vault.domain` | Tests pass and types exist; public methods such as `DownloadQuery.validate` and `QueueMessage.as_dict/from_dict` lack docstrings. | Candidate, but docstring cleanup required before support promise. |
| `cfdi_vault.fake_sat` | Tests pass and types exist; public client methods lack docstrings. | Candidate, but method contract docs required. |
| `cfdi_vault.cfdi_parser` | Tests pass and types exist; version parser classes and registry methods lack public docstrings. | Candidate, but needs contract docs before release. |
| `cfdi_vault.metadata_parser` | Tests pass; computed properties lack docstrings. | Candidate, minor docs cleanup required. |
| `cfdi_vault.package_processor` | Tests pass; storage method contract needs docstring. | Candidate, minor docs cleanup required. |

## Findings

### CRITICAL: No supported public API list exists yet

The release plan proposes candidates, but there is no final source of truth that says exactly which imports are supported. This blocks PyPI/TestPyPI promotion because users would not know what is semver-stable.

Required remediation:

- Create `docs/release/public-api.md` or equivalent.
- Keep `cfdi_vault.__all__` narrow.
- Promote only the smallest stable set first.
- Add import examples that use only supported names.

### CRITICAL: License file is missing

`pyproject.toml` declares MIT, but no `LICENSE*` file was found in the repository root during this audit. This blocks release packaging quality because package metadata and repository contents must agree.

Required remediation:

- Add the actual MIT license file if MIT is the intended license.
- Confirm `pyproject.toml` license metadata matches that file.
- Include the license check in release validation.

### WARNING: Public candidates do not all satisfy the docstring gate

All modules have module docstrings, and type hints are mostly present. The gap is public class/function/method documentation for several candidate APIs.

Required remediation:

- Fix docstrings in public candidates before promotion.
- Prefer documenting contract, errors, side effects, and safety boundaries over adding noisy comments.
- Keep private helpers private unless promoted deliberately.

### WARNING: CLI is package-installed but not all CLI commands should be public support promises

`cfdi-vault --help` works and lists reference-system commands plus SAT/live/probe commands. That is useful for the case study, but dangerous if every command is implied to be stable package behavior.

Required remediation:

- Define supported CLI commands for the first alpha package.
- Mark SAT live/probe commands as experimental/human-gated in release notes and CLI docs.
- Keep fake/offline commands as the default supported path.

### WARNING: Experimental/live-gate modules are importable

Python users can import internal modules even when `__all__` is narrow. That is acceptable only if docs and release notes explicitly exclude them from public support.

Required remediation:

- Mark live/probe/lint modules internal or experimental in public docs.
- Avoid using them in library consumer examples.
- Do not add them to `cfdi_vault.__all__` before a security review.

### SUGGESTION: Add a minimal external consumer example

The repository explains the intent, but there is no small consumer example proving how another repo should use only the supported API.

Recommended remediation:

- Add `examples/library-consumer/` or a short docs example after `public-api.md` exists.
- Keep it fake/offline and synthetic-only.

## Release readiness checklist

| Gate | Status | Notes |
|---|---|---|
| Public API list exists | Blocked | Needed before release. |
| Internal/probe/live modules excluded from support promise | Partial | Intent exists; needs public API doc/release notes. |
| `pyproject.toml` metadata accurate | Partial | Metadata mostly aligned; license file missing. |
| README states alpha/case-study limitations | Passed | Current README is careful and honest. |
| Sensitive fixture scanner passes | Passed | Scanner passed in this audit. |
| Tests pass in supported environment | Passed | Full suite passed locally. |
| Package builds sdist/wheel | Not checked | Run during release candidate validation. |
| `twine check dist/*` passes | Not checked | Run during release candidate validation. |
| Clean install smoke | Not checked | Installed editable CLI help passed, but wheel smoke still needed. |
| TestPyPI smoke before PyPI | Not checked | Not applicable until package candidate exists. |

## Remediation plan

1. Add `docs/release/public-api.md` with the first supported import surface.
2. Add the missing license file and verify package metadata.
3. Add docstrings only to promoted public candidates, starting with `domain`, `fake_sat`, `cfdi_parser`, `metadata_parser`, and `package_processor`.
4. Add or update API examples that import only supported names.
5. Define first-alpha supported CLI commands and mark live/probe commands experimental.
6. Run build, `twine check`, wheel install smoke, and TestPyPI only after the above is complete.

## Final assessment

The design direction is correct: library and reference system are now separated in documentation, the codebase has tests, and the root package does not accidentally export everything. The missing piece is discipline at the publication boundary: define the public API, document it, clean docstrings for promoted names, add the license file, and only then run package release validation.
