# Security model

CFDI Vault MX is safe by design only when fake/offline behavior is the default and
real taxpayer data, credentials, certificates, and live SAT access stay behind explicit
security gates. SAT SOAP research and guarded live-gate code can exist in the
repository, but they do not make live access a default or production-ready behavior.

This document describes the legacy synthetic lab safety boundary. Recovery v2 infrastructure is PostgreSQL/RabbitMQ/Redis-first even when it still uses fake SAT and synthetic data; see `docs/foundation/infrastructure-boundary.md`.

## Quick path

1. Keep all examples fake.
2. Keep processing local.
3. Reject secrets and certificate files from the repo.
4. Treat any real-data or live-SAT request as a human-gated phase-boundary change.
5. Follow `docs/testing/fixture-policy.md` before adding examples or tests.
6. Store local profile settings separately from credential material; use references, not plaintext secrets.
7. Read `docs/api/sat-download-public-api.md` before changing SAT SOAP authentication, storage, or public API boundaries.

## Data classification

| Data | Allowed in phase one? | Notes |
|---|---:|---|
| Synthetic XML | Yes | Must use fake RFC placeholders and fake names. |
| Real CFDI XML | No | Contains taxpayer and commercial data. |
| Real RFCs | No | Even test fixtures must avoid them. |
| Taxpayer names | No | Use synthetic names only. |
| Committed `.cer` / `.key` files | No | Out of scope and high risk. Never commit certificate or key files. |
| Local `.cer` / `.key` shape validation | Yes, local only | `cfdi-vault onboard` may read local operator-selected files to compute a fingerprint and validate shape; it must not copy, upload, commit, or authenticate with them. |
| Passwords / secrets | No | No secret storage in phase one. |
| Local profile config | Yes, if non-secret | Must use external credential references and dummy values in committed examples. |
| SAT API responses | No | Real responses must not be committed. Guarded live work may keep only redacted evidence outside fixtures. |
| SAT tokens / raw SOAP | No | Never commit or log raw tokens, raw SOAP, or complete request/package identifiers. |

## Threat boundaries

| Boundary | Control |
|---|---|
| XML parsing | Extract required fields only; reject `DOCTYPE`. |
| Synthetic import persistence | PostgreSQL through the configured `DATABASE_URL`. |
| Recovery v2 persistence | PostgreSQL through Docker Compose; still fake/synthetic only until the SAT/security gates are accepted. |
| Reference-system persistence | Stores hashes, state, and storage references; it must not store credentials, tokens, or raw live evidence in committed fixtures. |
| Export | CSV written locally by explicit command. |
| Identity | Local shape validation and credential references only by default; no committed e.firma, no plaintext credential persistence, and no silent taxpayer authentication. |
| Network | Fake/offline by default. SAT network calls require explicit opt-in, human approval, source traceability, redaction, and a clean-tree safety gate. |

## Review checklist

- [ ] No real XML files were added.
- [ ] No real RFCs or taxpayer names appear in fixtures.
- [ ] New examples or tests follow `docs/testing/fixture-policy.md`.
- [ ] No `.cer`, `.key`, password, token, or secret file exists.
- [ ] Local onboarding config files such as `cfdi-vault.local.json` are ignored and not committed.
- [ ] No ungated SAT client, API URL, or credential flow exists.
- [ ] Any SAT SOAP claim cites the source level from `docs/sat-download/source-policy.md`.
- [ ] Any live-SAT evidence is redacted and excludes raw SOAP, tokens, full RFCs, full request IDs, full package IDs, certificates, keys, passwords, and local paths.
- [ ] No server endpoint accepts certificate upload.

## Next step

Before phase two, read `docs/sat-download/README.md` and write a new ADR for any feature that crosses from synthetic local data into real taxpayer data, SAT network calls, encryption, or identity material.
