# First-run onboarding

INST-001 adds a CLI-first onboarding flow so an operator can create a safe local profile without hand-editing JSON. It validates local storage and e.firma file shape, then writes only non-secret references to config.

## Quick path

1. Choose a private local config path that is not committed.
2. Run onboarding with your storage root, RFC profile, download preferences, schedule, and local credential files.
3. Enter the private-key phrase only in the hidden prompt.
4. Validate the generated config.

```bash
cfdi-vault onboard \
  --config ./cfdi-vault.local.json \
  --profile-id local-profile \
  --rfc XAXX010101000 \
  --storage-root ./storage-local \
  --download-mode both \
  --start-date 2024-01-01 \
  --periodicity interval \
  --interval-minutes 360 \
  --max-concurrency 2 \
  --cer <path-to-certificate-file> \
  --key <path-to-private-key-file>

cfdi-vault config validate ./cfdi-vault.local.json
```

`cfdi-vault.local.json` and `*.local.json` are ignored by Git. Keep generated profile configs local because they can contain real RFC/profile metadata and certificate fingerprints even though they do not contain secrets.

## What the flow asks for

| Input | Validation |
|---|---|
| Storage root | Created if missing, then checked with a write probe. |
| RFC / profile id | Validated by the existing safe config schema. |
| Download mode | Must be `issued`, `received`, or `both`. |
| Initial range | Requires a start date; end date is optional but cannot precede start. |
| Periodicity | Supports `disabled`, `interval`, or `daily`. |
| Maximum concurrency | Must be between 1 and 10. |
| Certificate file | Must be readable, non-empty, use the expected extension, and look like DER or PEM certificate data. |
| Private key file | Must be readable, non-empty, use the expected extension, and look like DER or PEM key data. |
| Private-key phrase | Hidden input; checked only for presence; discarded before writing config. |

## What gets stored

| Stored in config | Not stored |
|---|---|
| RFC and profile id | Private-key phrase |
| Storage root | Certificate file bytes |
| Download preferences | Private key file bytes |
| Initial range and schedule | Local credential file paths |
| Maximum concurrency | SAT sessions or tokens |
| Certificate SHA-256 fingerprint | Real CFDI, SAT metadata, or packages |
| Credential reference URIs | Any plaintext credential material |

By default the command creates `windows-credential-manager://` reference URIs. They are pointers only. This slice does not implement a real credential-manager import. Custom reference prefixes must stay logical; references that look like `.cer`, `.key`, `.pem`, `.pfx`, or `.p12` file paths are rejected.

## Safety warnings

- Do not use real e.firma material in test or development fixtures.
- Do not share the private key file (`.key`).
- Do not put private-key phrases in JSON, shell scripts, `.env`, docs, tests, or committed examples.
- Do not copy credential files into this repository.

## Review checklist

- [ ] Generated config contains references and fingerprint only.
- [ ] Storage root exists and is writable.
- [ ] No credential file path appears in the config.
- [ ] `python scripts/scan_sensitive_fixtures.py` passes.
- [ ] `cfdi-vault config validate <generated-config>` passes.

## Next step

SEC-001 must define the real credential custody policy before live SAT signing is enabled.
