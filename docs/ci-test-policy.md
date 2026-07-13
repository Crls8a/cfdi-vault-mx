# Lightweight GitHub CI test boundary

GitHub CI is intentionally cheap, fast, and safe for a solo-maintainer project. The default workflow proves policy, scanner, hermetic test, and configuration correctness without starting infrastructure or reaching live fiscal systems.

## Quick path

Run the same boundary locally without starting services:

```powershell
.\.venv\Scripts\python.exe scripts/check_ci_policy.py --strict
.\.venv\Scripts\python.exe -m pytest -m "not integration and not container and not external and not live and not slow"
docker compose config
docker compose --profile object-storage config
```

Real-service and live checks are separate, explicit local activities. They are not hidden inside the default pull-request workflow.

## Test tiers

| Tier | Default GitHub CI | Scope | Infrastructure boundary |
| --- | --- | --- | --- |
| 0 — Static / policy | Yes | Branch policy, work-orchestrator validation/status, focused Ruff lint, both safety scanners, base-to-HEAD `git diff --check`, and CI-policy audit | No services, network credentials, or runtime containers |
| 1 — Unit / offline | Yes | Fakes, mocks, in-memory adapters, synthetic parser fixtures, offline SAT envelopes, and loopback/hermetic tests | Excludes `integration`, `container`, `external`, `live`, and `slow` |
| 2 — Config only | Yes | `docker compose config` and the object-storage profile config | Parses configuration only; never starts or runs a service |
| 3 — Local integration | No | Real PostgreSQL, Redis, RabbitMQ, MinIO, and adapter-to-service behavior | Run locally only when the change requires integration evidence |
| 4 — External / live | Never | SAT live, production-signed operations, real e.firma, real downloads, or real fiscal artifacts | Manual opt-in, human approval, permits, and the applicable runbook are mandatory |

## Default workflow rules

The default workflow may:

- install the package with the small `dev` dependency set;
- run Tier 0 checks and Tier 1 tests on Python 3.12;
- validate Compose syntax with `docker compose ... config`;
- keep hermetic loopback and fake-adapter tests in the default selection.

The default workflow must not:

- declare GitHub Actions `services:` containers;
- declare job-level `container:` images or use `docker://` container actions;
- use flow mappings for `run`, `services`, `container`, or `uses`, numeric block indentation indicators, or multiline plain `run:` continuations;
- interpolate GitHub context expressions directly inside `run:`; map them through step `env` and quote the shell variable instead;
- run any Compose subcommand other than `config` (including `up`, `run`, `start`, `pull`, or `build`) or run `docker run`;
- start PostgreSQL, Redis, RabbitMQ, or MinIO;
- enable `CFDI_VAULT_SAT_LIVE=1` or `CFDI_VAULT_SAT_PRODUCTION_SIGNED=1`;
- reference SAT/e.firma secrets or real fiscal artifacts;
- execute pytest without excluding every heavy marker.

`scripts/check_ci_policy.py --strict` enforces these rules for default workflows. A future workflow whose only trigger is `workflow_dispatch` is outside the default boundary, but it still requires focused human review before it may host a manual integration check.

## Marker ownership

| Marker | Use it when |
| --- | --- |
| `integration` | A test requires a real local service, including PostgreSQL, Redis, or RabbitMQ |
| `container` | A test specifically requires Docker or Compose services |
| `external` | A test calls a non-local network service |
| `live` | A test calls a real live system such as SAT |
| `slow` | Runtime cost makes the test unsuitable for every pull request |
| `ci` | A focused test is explicitly intended for default GitHub CI |

Apply markers to the smallest honest scope. Do not mark fake Redis/S3/RabbitMQ adapters or SAT live-guard tests as integration merely because their production counterpart is external. Conversely, do not leave a real-service test unmarked to make CI appear green.

## Local integration and live evidence

Run Tier 3 only when a change touches the corresponding adapter or contract, using disposable local infrastructure and synthetic data. Record the exact service, command, and result in the PR.

Tier 4 remains human-gated. Follow the SAT/e.firma runbook, use explicit permits, keep output redacted, and never move credentials or fiscal artifacts into GitHub Actions.

## Policy checker modes

```powershell
python scripts/check_ci_policy.py            # advisory report
python scripts/check_ci_policy.py --strict   # non-zero on any finding
python scripts/check_ci_policy.py --explain  # show the boundary and report
```

The checker is dependency-free and reads only repository policy/configuration files. It does not call GitHub, Docker, the network, or secret stores.
