# Security model

CFDI Vault MX is safe by design only because phase one is local-first and synthetic-only. The project must not process real taxpayer data, credentials, certificates, or SAT integrations until a new security design is accepted.

## Quick path

1. Keep all examples fake.
2. Keep processing local.
3. Reject secrets and certificate files from the repo.
4. Treat any real-data request as a phase-boundary change.

## Data classification

| Data | Allowed in phase one? | Notes |
|---|---:|---|
| Synthetic XML | Yes | Must use fake RFC-like values and fake names. |
| Real CFDI XML | No | Contains taxpayer and commercial data. |
| Real RFCs | No | Even test fixtures must avoid them. |
| Taxpayer names | No | Use synthetic names only. |
| `.cer` / `.key` files | No | Out of scope and high risk. |
| Passwords / secrets | No | No secret storage in phase one. |
| SAT API responses | No | No real SAT integration in phase one. |

## Threat boundaries

| Boundary | Phase-one control |
|---|---|
| XML parsing | Extract required fields only; reject `DOCTYPE`. |
| Persistence | SQLite local file; no network database. |
| Export | CSV written locally by explicit command. |
| Identity | No e.firma, certificates, or taxpayer authentication. |
| Network | No SAT or external service calls. |

## Review checklist

- [ ] No real XML files were added.
- [ ] No real RFCs or taxpayer names appear in fixtures.
- [ ] No `.cer`, `.key`, password, token, or secret file exists.
- [ ] No SAT client, API URL, or credential flow exists.
- [ ] No server endpoint accepts certificate upload.

## Next step

Before phase two, write a new ADR for any feature that crosses from synthetic local data into real taxpayer data, network calls, encryption, or identity material.
