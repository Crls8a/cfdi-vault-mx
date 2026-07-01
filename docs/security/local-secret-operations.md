# Safe local secret operations

Sprint 5 introduces local credential reference operations without weakening the security model: operators work with references, the adapter talks to the custody backend, and the CLI reports status without printing values.

## Operator model

| Operation | CLI behavior | Stored in config? | Printed? |
|---|---|---:|---:|
| Register reference | Accepts a reference URI and hidden value, then stores through provider. | Reference only. | Status only. |
| Verify reference | Checks whether the backend can find the reference. | No change. | Status only. |
| Delete reference | Deletes the backend entry for the reference. | No change. | Status only. |
| Resolve reference | Internal adapter operation for future signer/auth flows. | Never. | Never. |

## Reference format

Use Windows Credential Manager references like:

```text
windows-credential-manager://cfdi-vault/profile/private-key
windows-credential-manager://cfdi-vault/profile/private-key-phrase
windows-credential-manager://cfdi-vault/profile/certificate
```

These strings are references. They must not be replaced with credential values.

## Audit events

Every operation emits a redacted event with:

- provider;
- reference URI;
- credential kind;
- purpose;
- action;
- outcome;
- timestamp;
- optional redacted reason.

The event must never contain the resolved value.

## Local testing rule

Tests must use an injected in-memory backend. They must not read, write, or delete real Windows credentials. The production Windows backend is only selected when the operator runs the CLI on Windows with a `windows-credential-manager://` reference.

## Troubleshooting

| Symptom | Safe response |
|---|---|
| Reference not found | Re-register the reference; do not paste values into config. |
| Unsupported platform | Use Windows for the production adapter or use dummy/in-memory tests only. |
| Credential value appears in output | Treat as a security bug and stop the release. |
| Scanner detects sensitive content | Stop immediately and remove the offending artifact. |
