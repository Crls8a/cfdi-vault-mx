# Library scope

The library is the reusable Python part of CFDI Vault MX. Its job is to make SAT CFDI
recovery concepts safe to import from another repository without cloning this one.

## Decision

`cfdi-vault-mx` should publish only the supported `cfdi_vault` Python API as the
library contract. The reference CLI and runtime can be packaged for demos or smoke
checks, but they do not define the reusable API by themselves.

## Library owns

| Area | Responsibility |
|---|---|
| Domain | Request criteria, periods, states, metadata entries, result objects, and user-facing error payloads. |
| Ports | Signing, secrets, SAT auth/request/verify/download, storage, queue, cache, search, and error mapping contracts. |
| Offline/fake SAT | Deterministic adapters and examples that do not need live credentials. |
| Parsing/package processing | Synthetic-safe XML/TXT/ZIP processing with evidence-first behavior. |
| Public errors | Typed, redacted, actionable exceptions or payloads. |
| Source traceability | SAT behavior must cite `V1_5_CONTRACT`, `RUNTIME_WSDL`, or explicitly non-normative sources. |

## Library does not own silently

| Area | Why not |
|---|---|
| Credential custody | e.firma and passwords are high-risk; the library should accept provider boundaries, not store secrets by default. |
| Live SAT execution | Requires lawful access, source traceability, redaction, and human/security gate approval. |
| PostgreSQL schema ownership | The reference system can use PostgreSQL; consumers may implement storage ports differently. |
| RabbitMQ/Redis/Docker runtime | These are system adapters, not required library dependencies. |
| CLI workflows | Useful as the reference-system UI, but not the import contract. |
| Accounting/legal certification | The package is a development-stage reference, not a certified tax product. |

## Release promise

Before PyPI publication, every public name must pass the
[Library quality contract](library-quality-contract.md) and be listed in
[Repository public API plan](public-api.md). Anything not listed there is internal,
experimental, or reference-system-only.

## Related docs

- [Product split](../product-archetype.md)
- [SAT download public API research and contract](../api/sat-download-public-api.md)
- [Python package release plan](python-package-plan.md)
- [Reference system scope](../foundation/reference-system-scope.md)
