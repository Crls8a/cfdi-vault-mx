# SAT campaign runbook

This document defines the human gate and evidence policy for the productive
SAT v1.5 campaign. It replaces the historical smoke, probe, diagnostic,
manual-recovery, and live-gate runbooks. Those names are retained only in
history and are not public commands.

## Public workflow

The only SAT-facing CLI is:

```text
cfdi-vault sat campaign create --profile <profile>
cfdi-vault sat campaign authorize --profile <profile> --campaign-ref <ref> --phase metadata-proof --expires-days 14 --reason <reason>
cfdi-vault sat campaign run --profile <profile> --campaign-ref <ref> --grant <grant-ref>
cfdi-vault sat campaign status --profile <profile> --campaign-ref <ref>
```

The campaign CLI is PostgreSQL-only. It never falls back to legacy JSON,
prints SAT identifiers, or stores ZIP/TXT/XML in the repository. `run` is a
one-shot wake: it contacts SAT only for a claimed operation whose persisted
`next_check_at` is due. A missing grant, mismatched commit, invalid profile, or
missing database fails closed.

## Human and security gate

No live command is authorized by this document alone. Before Carlos authorizes
a run, all of the following must be true:

1. The exact commit and campaign are identified and the checkout is clean.
2. PostgreSQL/Flyway, RabbitMQ, Redis, and the external artifact root are
   healthy; artifacts are outside the repository and `/app`.
3. The local profile and e.firma provider are ready; certificates, keys,
   passwords, and tokens stay outside the repository and logs.
4. The grant is bound to the campaign, profile, phase, commit, and budget.
5. The run is outside CI and no endpoint override is present.

The first proof is limited to received and issued metadata for
`2026-01-01..2026-01-14`, with at most two open operations. Do not create a
replacement request when one is pending. Wake `campaign run` at 5m, 15m, 30m,
and 1h, then only when the persisted due time permits it; the request may
remain pending for the local 48-hour service window.

## Evidence and redaction

Record only sanitized aggregates:

- campaign/window and direction;
- attempt count and categorized state;
- next review and service-window state;
- package, ZIP, TXT, XML, and worker counts.

Never record RFCs, UUIDs, SAT request/package ids, metadata rows, XML, ZIP
bytes, SOAP, authorization headers, credential paths, local paths, or secrets.
The sensitive-fixture scanner and the complete test suite must pass before and
after any real run.

## Metadata to XML boundary

The first real ZIP must be validated and its TXT processed by the worker before
an additional `cfdi-proof` grant is issued. Only then may the campaign request
CFDI/XML for an eligible window. A download timeout becomes `uncertain` and is
not retried automatically. Scheduler activation and campaign expansion wait
until the Metadata and XML proof is complete.

## Abort conditions

Stop without replacement requests when approval, profile readiness, commit
binding, storage safety, endpoint policy, claim ownership, or redaction cannot
be proven. A pending, expired, no-data, or uncertain result is recorded as a
categorized outcome and reviewed manually.
