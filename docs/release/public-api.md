# Repository public API plan

The public API is the set of imports and behaviors this project is willing to support
for package users. Everything else can exist in the repository, but it is not stable
until it is promoted through the library quality contract.

## Decision

The first public API should be import-first and small. The CLI remains valuable for the
reference system, demos, and packaging smoke checks, but the library promise is the
Python contract documented here and in [SAT download public API research and contract](../api/sat-download-public-api.md).

The exact SAT module classification, supported LIB-005B names, LIB-005C
facade, error semantics, and promotion gates live in
[SAT v1.5 public API contract](../api/sat-v15-public-api.md).

## Public today

| Import | Stability | Notes |
|---|---|---|
| `cfdi_vault.__version__` | Stable | Exported from `cfdi_vault.__init__`. |
| `cfdi_vault.domain.DateTimePeriod`, `DownloadDirection`, `DownloadQuery`, `RequestType`, `SatRequestState` | LIB-005B supported | Typed request criteria and state values for injected SAT ports. |
| `cfdi_vault.ports.SatAuthenticatorPort`, `SatRequestPort`, `SatVerificationPort`, `SatDownloadPort` | LIB-005B supported | Runtime-agnostic split SAT boundaries. |
| `cfdi_vault.sat_contract.SatAuthResult`, `SatRequestResult`, `SatVerificationResult`, `SatDownloadResult` | LIB-005B supported | Redacted result models for auth/request/verify/download operations. |
| `cfdi_vault.sat_contract.SatError`, `SatAuthenticationError`, `SatRequestError`, `SatVerificationError`, `SatPackageDownloadError` | LIB-005B supported | Redacted typed SAT error hierarchy. |
| `cfdi_vault.fake_sat.FakeSatStore`, `FakeSatAuthenticator`, `FakeSatRequester`, `FakeSatVerifier`, `FakeSatDownloader` | LIB-005B supported | Deterministic offline adapters for tests and examples. |
| `cfdi_vault.sat_download.SatDownloadFacade`, `create_offline_facade` | LIB-005C supported | Injection-only operation facade plus an explicit deterministic offline factory; no live adapter selection. |

No SAT live/probe module is public API today.

The `cfdi_vault.sat_download` facade is public with exactly the two names above.
Its import and offline factory require no environment, credentials, services,
or network. Results keep identifiers and package bytes caller-owned while their
diagnostic representations remain redacted.

## Candidate public surfaces

| Surface | Candidate modules | Why it belongs |
|---|---|---|
| Domain models | `cfdi_vault.domain` | Request criteria, state, metadata inventory, and user-facing payloads are reusable outside the reference system. |
| Ports | `cfdi_vault.ports` | Applications can plug in their own SAT, storage, queue, cache, secret, and signing adapters. |
| SAT result policy | `cfdi_vault.sat_contract` | Normalized auth/request/verify/download results and outcome classification are reusable and testable. |
| Offline/fake SAT | fake SAT and simulator modules | Safe consumer tests and examples need deterministic behavior without credentials or network. |
| Package processing/parsing | package processor, metadata parser, XML parser | Evidence-first parsing is useful outside the CLI when fixtures remain synthetic. |

## Internal or reference-only surfaces

| Surface | Boundary |
|---|---|
| `sat_*_probe.py`, `sat_*_oracle.py`, WSDL probes, envelope linters | Research and verification helpers; not semver-stable API. |
| `sat_live_smoke.py`, live gates, one-time permits | Human-gated reference-system tools; not default library behavior. |
| `cli.py` and `cfdi_vault.adapters.cli` | Reference-system operator interface. Package smoke can call it, but library consumers should not build against CLI internals. |
| PostgreSQL/RabbitMQ/Redis adapters and Docker runtime | Reference-system implementation choices behind ports. |
| Recovery workers/services | System orchestration until a narrower facade is intentionally promoted. |

## Promotion checklist

A name can become public only when all items are true:

- [ ] It has a clear responsibility and no hidden live SAT side effects.
- [ ] Public module/class/function/method docstrings explain arguments, returns,
      exceptions, side effects, and restrictions.
- [ ] Type hints are complete enough for consumer projects.
- [ ] Unit tests cover valid, invalid, boundary, and redaction behavior.
- [ ] The clean-wheel import smoke imports the exact public name.
- [ ] API docs list stability and semver expectations.
- [ ] Security/source classification exists for SAT behavior.

## Consumer shape

A consumer should look like this, not like an import of internal probe modules.
This offline example uses the deterministic in-memory adapters; callers that
need another implementation construct `SatDownloadFacade` with four explicit
ports.

```python
from datetime import datetime, timezone

from cfdi_vault.domain import (
    DateTimePeriod,
    DownloadDirection,
    DownloadQuery,
    RequestType,
)
from cfdi_vault.sat_download import create_offline_facade

start = datetime(2024, 1, 1, tzinfo=timezone.utc)
end = datetime(2024, 1, 2, tzinfo=timezone.utc)
query = DownloadQuery(
    tenant_id="demo-tenant",
    requester_rfc="XAXX010101000",
    direction=DownloadDirection.RECEIVED,
    request_type=RequestType.METADATA,
    period=DateTimePeriod(start=start, end=end),
)

sat = create_offline_facade()
request_result = sat.submit_request(query)
verification_result = sat.verify_request(request_result.request_id)
```

The facade never selects a live implementation. The library does not require
the consumer to copy the reference-system CLI, Docker stack, AppData layout, or
live smoke commands.

## Next release gates

- Add `docs/api/` links to the README and documentation index.
- Preserve the LIB-005B result/error/port/fake contracts while the LIB-005C
  facade remains limited to injection and the explicit offline factory.
- Extend import smoke tests whenever another name is proposed for promotion.
- Keep live SAT support internal until the security gate is approved.
