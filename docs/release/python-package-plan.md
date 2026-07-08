# Python package release plan

The reusable library track should become installable without cloning the repository. It is not published to PyPI yet. The target user experience is `pip install cfdi-vault-mx`, then either import the supported Python API from another project or run the packaged CLI entrypoint for documented fake/offline workflows.

Publishing the package is not the same as publishing or certifying the full reference system. The repository-level system remains a case study with Docker/local runtime, docs, and examples.

## Publication disclaimer

Until a release is actually published, every install command in this document is a target or local validation command, not a promise that the package exists on PyPI.

The first public package must be described as:

> Development-stage alpha and case-study reference implementation for fake/offline-first SAT CFDI recovery architecture.

The package page, README, and release notes must invite users to open a GitHub issue before relying on unsupported live SAT, e.firma, parser, or fiscal/accounting behavior.

## What gets published

| Published package includes | Repository case study includes |
|---|---|
| Supported `cfdi_vault` import APIs. | Architecture docs, planning docs, and implementation history. |
| Stable fake/offline adapters and domain models selected for release. | Docker/local runtime used to demonstrate a personal CFDI vault workflow. |
| The `cfdi-vault` CLI entrypoint for documented commands. | Broader examples, release planning, and operational runbooks. |
| Package metadata, README, license, and release notes. | Experimental/probing modules until promoted to public API. |

The package release must say which modules are supported public API and which modules are internal, experimental, or case-study-only.

## Quick path

1. Keep `pyproject.toml` as the package metadata source.
2. Build a source distribution and wheel locally.
3. Validate the built artifacts in a clean environment.
4. Publish to TestPyPI first.
5. Publish to PyPI through Trusted Publishing after the release gates pass.

## Current package state

| Topic | Current value | Release implication |
|---|---|---|
| Distribution name | `cfdi-vault-mx` | This is the name users will install with `pip`. |
| Import package | `cfdi_vault` | This is the Python namespace users import. |
| CLI command | `cfdi-vault` | This is already declared in `[project.scripts]`. |
| Build backend | Hatchling | Keep using `pyproject.toml`; no `setup.py` needed. |
| Version | `0.1.0` | First public release should be clearly marked alpha. |
| PyPI name check | `https://pypi.org/pypi/cfdi-vault-mx/json` returned 404 on 2026-07-08 and was rechecked as 404 during this planning pass | Name appears unused now, but it is not reserved until publication. |

Before promoting any module or command to public package behavior, apply the [Library quality contract](library-quality-contract.md).

## Release positioning

The first library/package release should be positioned as:

> An alpha CLI and Python reference library for safe, fake/offline-first SAT CFDI recovery architecture.

It must not claim:

- live SAT production readiness;
- automatic e.firma custody;
- complete parser coverage for every CFDI complement;
- legal, tax, or accounting certification.

It must explicitly claim:

- fake/offline-first behavior;
- synthetic-fixture safety;
- alpha maturity;
- case-study/reference-system intent;
- GitHub Issues as the contact path for questions, collaboration, and risk review.

## PyPI readiness checklist

- [ ] Add or confirm a license file that matches the `pyproject.toml` license.
- [ ] Confirm package metadata: description, keywords, classifiers, authors, URLs, and Python version.
- [ ] Define the supported public API modules.
- [ ] Confirm every public API satisfies the library quality contract.
- [ ] Mark probing, live-gate, and experimental modules as internal or document them as unsupported.
- [ ] Add a minimal "library consumer" example that imports the package outside this repo.
- [ ] Run the sensitive fixture scanner.
- [ ] Run the full test suite.
- [ ] Build source distribution and wheel.
- [ ] Run artifact checks.
- [ ] Install from the built wheel in a clean virtual environment.
- [ ] Run `cfdi-vault help` from the installed wheel.
- [ ] Publish to TestPyPI.
- [ ] Install from TestPyPI in a clean environment.
- [ ] Publish to PyPI only after the TestPyPI smoke passes.

## Build and validation commands

```powershell
python -m pip install --upgrade pip
python -m pip install --upgrade build twine
python -m build
python -m twine check dist/*
python scripts/scan_sensitive_fixtures.py
python -m pytest
```

Clean install smoke:

```powershell
python -m venv .venv-package-smoke
.\.venv-package-smoke\Scripts\python.exe -m pip install --upgrade pip
.\.venv-package-smoke\Scripts\python.exe -m pip install .\dist\cfdi_vault_mx-0.1.0-py3-none-any.whl
.\.venv-package-smoke\Scripts\cfdi-vault.exe help
```

## Trusted Publishing plan

Use PyPI Trusted Publishing instead of storing a long-lived PyPI token in GitHub secrets.

| Step | Decision |
|---|---|
| Test index | Configure a pending Trusted Publisher on TestPyPI first. |
| Production index | Configure PyPI only after TestPyPI install smoke passes. |
| GitHub environment | Use a protected `pypi` environment for production publishing. |
| Workflow permission | Grant the GitHub Actions OIDC identity permission required by PyPI only at the publishing job level. |
| Upload action | Use `pypa/gh-action-pypi-publish@release/v1`. |
| Trigger | Prefer GitHub Releases or version tags after CI passes. |

## Public API proposal

Start narrow. A small stable API is better than exporting the whole repository and regretting it later.

| Surface | Candidate modules | Stability target |
|---|---|---|
| Domain models | `cfdi_vault.domain` | Stable first. |
| Architecture ports | `cfdi_vault.ports` | Stable first. |
| Fake/offline SAT | `cfdi_vault.fake_sat`, `cfdi_vault.sat_simulator` | Stable enough for tests/examples. |
| Recovery orchestration | A future facade over `cfdi_vault.recovery_service` | Stabilize before release. |
| CLI | `cfdi-vault` command | Stable for documented commands only. |
| Probes/live gates | `sat_*_probe`, `sat_*_live_*` modules | Internal/experimental until explicitly promoted. |

## Documentation required before publishing

- README quickstart for `pip install cfdi-vault-mx`.
- A library usage example that imports a supported API.
- A CLI usage example that stays fake/offline by default.
- A release limitations section.
- A security warning that real CFDI, SAT metadata, ZIPs, e.firma files, passwords, tokens, and private keys must never be committed.

## Official references

- [Python Packaging User Guide: Packaging Python Projects](https://packaging.python.org/en/latest/tutorials/packaging-projects/)
- [Python Packaging User Guide: Writing your `pyproject.toml`](https://packaging.python.org/en/latest/guides/writing-pyproject-toml/)
- [PyPI Docs: Publishing with a Trusted Publisher](https://docs.pypi.org/trusted-publishers/using-a-publisher/)
