# Repository public API plan

The public API is the set of imports and behaviors this project is willing to support
for package users. Everything else can exist in the repository, but it is not stable
until it is promoted through the library quality contract.

## Decision

The first public API should be import-first and small. The CLI remains valuable for the
reference system, demos, and packaging smoke checks, but the library promise is the
Python contract documented here and in [SAT download public API research and contract](../api/sat-download-public-api.md).

## Public today

| Import | Stability | Notes |
|---|---|---|
| `cfdi_vault.__version__` | Stable | Exported from `cfdi_vault.__init__`. |

No SAT live/probe module is public API today.

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

A future consumer should look like this, not like an import of internal probe modules.
This snippet is illustrative; real code must provide `start`, `end`, and concrete
clients implementing the ports.

```python
from cfdi_vault.domain import DateTimePeriod, DownloadDirection, DownloadQuery, RequestType
from cfdi_vault.ports import SatRequestPort, SatVerificationPort

query = DownloadQuery(
    tenant_id="demo-tenant",
    requester_rfc="XAXX010101000",
    direction=DownloadDirection.RECEIVED,
    request_type=RequestType.METADATA,
    period=DateTimePeriod(start=start, end=end),
)

request_result = sat_request_client.submit_request(query)
verification_result = sat_verify_client.verify_request(request_result.request_id)
```

The example intentionally uses injected ports. The library should not require the
consumer to copy the reference-system CLI, Docker stack, AppData layout, or live smoke
commands.

## Next release gates

- Add `docs/api/` links to the README and documentation index.
- Add import smoke tests for every promoted public name.
- Decide whether to introduce a single `cfdi_vault.sat_download` facade.
- Keep live SAT support internal until the security gate is approved.
