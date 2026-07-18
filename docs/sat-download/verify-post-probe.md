# Historical VERIFY transport note

**Internal history only. This is not a public CLI or an execution runbook.**

Earlier development used an isolated transport diagnostic to compare SOAP
headers, connection behavior, and the v1.5 `VerificaSolicitudDescarga` envelope.
That diagnostic is retired from the public command tree. It must not be used as
SAT evidence, as a substitute for a campaign grant, or as a route around the
campaign runner.

## Preserved contract knowledge

The productive adapter keeps the following offline-tested invariants:

- SOAP 1.1 and the canonical v1.5 VERIFY operation are used;
- the request is signed with the audited operation-wrapper shape;
- the WRAP authorization value belongs in the HTTP header, never in the XML;
- response parsing returns typed, redacted categories rather than raw SOAP;
- package identifiers and request identifiers remain private state.

Synthetic envelope and fake-transport tests preserve these invariants without
contacting SAT or loading real credentials. They are implementation tests, not
integration evidence.

## Current path

All real submission, due VERIFY, and package download work goes through:

```text
cfdi-vault sat campaign authorize
cfdi-vault sat campaign run
```

The runner claims the operation before an external effect, honors
`next_check_at`, records an append-only attempt, and never creates a
replacement request after a timeout. A human-authorized campaign run is the
only supported way to obtain SAT behavior evidence.
