# Initial requirements

This document defines what a developer or operator must have before using the future SAT CFDI download library.

## Minimum requirements

| Requirement | Needed for | Notes |
|---|---|---|
| Lawful access to the taxpayer CFDI data | Every live SAT request | The SAT service is for emitters/receivers and requires authentication. |
| Valid e.firma certificate (`.cer`) | Authentication and signing | CSD is not enough; the SAT Web Service flow uses e.firma/FIEL. |
| Matching private key (`.key`) and password | Authentication and request signatures | Can be supplied manually, stored securely, or delegated to a detached signer. |
| Requester RFC | Request validation | Must match the certificate and requested scope where SAT requires it. |
| Storage location | Packages and extracted files | Local directory or object storage; must be writable and have enough capacity. |
| Persistence database | Idempotency and reconciliation | SQLite is acceptable for local-first; production can adapt through repository interfaces. |
| Network access to SAT endpoints | SOAP calls | HTTPS egress to authentication, request, verification, and download endpoints. |
| Accurate system clock | WS-Security timestamps | Clock skew can break authentication/signature validation. |
| Query scope | Request planning | Direction, period, request type, RFC scope, and optional filters. |

## Recommended runtime baseline

| Area | Recommendation |
|---|---|
| Language/runtime | Python 3.12+ for this repository unless the project later publishes language-specific packages. |
| XML processing | Deterministic XML building, canonicalization, namespace-safe parsing, and XXE-safe parser defaults. |
| Crypto/signing | Dedicated signing module or detached signer; never spread private key handling across the app. |
| HTTP transport | Configurable timeout, retry budget, TLS verification, structured error capture. |
| Database | SQLite for local use; PostgreSQL-compatible schema for production-scale deployments. |
| Storage | Raw ZIP package storage before extraction; checksum every ZIP and XML. |
| Logs | Structured logs with tokens, passwords, private keys, and raw taxpayer XML redacted. |

## Setup decisions

The installer or application setup must collect these decisions explicitly:

| Decision | Allowed values | Default |
|---|---|---|
| Storage target | local path, object storage adapter | local path |
| Credential custody mode | `manual-local`, `local-secure`, `server-secure`, `detached-signer` | `manual-local` |
| Sync scope | issued, received, folio | none; user must choose |
| First ingestion type | metadata, CFDI/XML | metadata |
| Window size | month, day, hour, custom | day for current sync; month for historical backfill |
| Retry policy | conservative, custom | conservative |

## Preflight checklist

- [ ] The user confirms they are the emitter, receiver, legal representative, or have a valid mandate.
- [ ] The certificate is e.firma/FIEL, valid, and not expired.
- [ ] The private key matches the certificate.
- [ ] The requester RFC matches the intended download scope.
- [ ] The selected storage target is writable.
- [ ] The system clock is synchronized.
- [ ] Default tests do not require live SAT credentials.
- [ ] A credential custody mode is selected before unattended jobs are enabled.

## Not supported in the first implementation slice

- Captcha/portal automation.
- Storing raw e.firma secrets by default.
- Multi-tenant SaaS custody without a dedicated secure-custody design.
- Live SAT calls in default CI.
- Treating community-observed v1.5 behavior as official SAT documentation.

## Next step

Use [Request model](request-model.md) to construct valid requests and [Authentication and security model](auth-security.md) to choose the custody mode.
