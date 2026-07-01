# Windows Credential Manager boundary

Windows Credential Manager is the preferred future local custody backend on Windows, but Sprint 4 does not implement the production adapter. This document defines the boundary so the future adapter can be built without leaking values into config, logs, fixtures, or storage.

## Boundary decision

| Topic | Decision |
|---|---|
| Config format | Store only provider references such as `windows-credential-manager://cfdi-vault/profile/certificate`. |
| Value resolution | Only a `SecretProvider` adapter may resolve a reference. |
| Audit | Every resolution attempt emits a redacted credential access event. |
| Logging | Logs may include provider, reference URI, purpose, and outcome; never the value. |
| Storage | Credential values and files are never copied into CFDI storage roots. |

## Future adapter responsibilities

1. Read by reference URI.
2. Return an ephemeral `SecretValue` object.
3. Emit a redacted audit event for granted, denied, or missing access.
4. Avoid logging raw values or platform error payloads that include values.
5. Refuse unsupported schemes.

## Explicit non-goals for Sprint 4

- No Windows API calls.
- No credential creation/update/delete operations.
- No production credential migration.
- No real certificate, key, or passphrase material.
- No fallback to local plaintext files.

## Safe example references

```text
windows-credential-manager://cfdi-vault/profile/certificate
windows-credential-manager://cfdi-vault/profile/private-key
windows-credential-manager://cfdi-vault/profile/private-key-phrase
```

These are references, not values. The strings above must never be replaced with credential material in config or documentation.
