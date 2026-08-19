# Future direction: cloud/server deployment security (not started)

Status: **planning stub only — not designed, not implemented**. Written so
the direction is known in advance, per Carlos's request while prioritizing
getting a real CFDI download working first (2026-08-19).

## Why this is separate from the local dashboard (ADR 0004)

ADR 0004's "no login for now" is only safe because the panel binds to
`127.0.0.1` and the FIEL phrase never leaves the local machine's OS secret
store. A server/cloud deployment breaks both of those assumptions at once —
it is a different trust model, not an incremental step from the local one.
Do not carry "no login" forward into a network-reachable deployment.

## What has to be designed before any FIEL material touches a server

- **Encryption at rest with a real key-management layer** (envelope
  encryption via a KMS or a dedicated secrets manager such as HashiCorp
  Vault/cloud KMS) — never a plain database column, even encrypted with an
  app-held key.
- **Real authentication and authorization** for anyone/anything that can
  reach the deployment — no exceptions, this is the point that makes the
  rest meaningful.
- **Audit logging of every credential use** — who/what triggered a SAT
  authentication, when, for which tenant.
- **Tenant isolation** if more than one RFC/organization is served by the
  same deployment.
- **Transport security** (TLS) for anything not on loopback.
- **A decision on where the private key material itself lives** — a
  server-side KMS-backed secret store is a different risk profile than
  today's per-operator OS Credential Manager/Keychain; this needs its own
  threat model, not a lift-and-shift of `src/cfdi_vault/os_secret_providers.py`.

## What stays true regardless of deployment target

- PostgreSQL remains the durable source of truth (ADR 0002).
- The SAT-facing adapter/campaign logic (`sat_v15_adapter.py`,
  `sat_db_campaign_runner.py`) does not need to change for this — it already
  takes a credential provider through a port; only which provider
  implementation is selected changes.
- `sat-monitor`'s current fail-closed default stays fail-closed until this
  design exists and is reviewed — see ADR 0002 and
  `docs/planning/sat-program/known-gaps.md`.

## Next step (later, not now)

Write a proper ADR once there is a concrete deployment target (which cloud,
single-tenant vs multi-tenant, expected operator count) — a security design
written against a hypothetical target tends to miss the constraints that
actually matter.
