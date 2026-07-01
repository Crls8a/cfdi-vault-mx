# Local e.firma custody threat model

The project must treat local e.firma material as high-risk credential material. Sprint 4 defines the boundary and audit model only; it does not introduce real credential handling.

## Assets

| Asset | Required protection |
|---|---|
| Certificate reference | Non-secret pointer, safe to store in config when it is not a local file path. |
| Private-key reference | Non-secret pointer, safe to store in config when it is not a local file path. |
| Passphrase reference | Non-secret pointer, safe to store in config when it is not a value. |
| Credential value | Never stored in config, logs, fixtures, database rows, or package/XML storage. |
| Credential access event | Stored only as redacted metadata: reference URI, purpose, outcome, and timestamp. |

## Trust boundaries

| Boundary | Allowed now | Forbidden now |
|---|---|---|
| Config | Reference URIs and certificate fingerprint. | Credential values or local credential file paths. |
| Secret provider | Resolve synthetic values in memory for tests. | Production credential backends. |
| Logs/audit | Redacted access metadata. | Raw values, private-key material, passphrases, tokens, or certificate blobs. |
| Storage | CFDI recovery evidence only. | Credential values or copies of e.firma files. |
| SAT adapter | Non-live fakes only. | Real authentication or real SOAP calls. |

## Threats and controls

| Threat | Control in this sprint |
|---|---|
| Accidental config persistence of credential values | Existing config schema rejects raw credential-like fields; tests assert only references are serialized. |
| Credential value leaking through repr/logging | `SecretValue` redacts string/repr output; audit records exclude the value. |
| Test fixtures becoming real credential fixtures | Dummy provider uses synthetic in-memory values and scanner-safe placeholders. |
| Storage being reused for credential custody | Tests assert credential values are absent from storage paths written during provider use. |
| Live SAT/e.firma work sneaking in | Scope stops at ports, dummy provider, and docs. Real adapters remain gated. |

## Required audit event fields

| Field | Purpose |
|---|---|
| `provider` | Which provider boundary was used. |
| `reference_uri` | Which reference was requested. |
| `kind` | Certificate, private key, passphrase, or generic credential. |
| `purpose` | Why the caller requested access. |
| `outcome` | Granted, denied, or missing. |
| `occurred_at` | UTC timestamp for traceability. |
| `reason` | Optional redacted explanation. |

## Human gates that remain

Stop before implementation if a future task requires:

- real e.firma access;
- real certificate/key files;
- a real credential store adapter;
- production Windows Credential Manager integration;
- live SAT authentication;
- irreversible storage, schema, or security changes.
