# Lightweight governance policy

CFDI Vault MX uses a solo-maintainer-friendly workflow: normal sprint work can move through backlog/docs, branches, PRs, and CI without an approval issue. High-risk work still needs an explicit issue and human gate because the project touches fiscal data boundaries, SAT metadata, XML/ZIP evidence, and e.firma references.

## Quick path

1. Use `docs/planning/backlog.md` and a Sprint Packet for normal sprint execution.
2. Create an approved issue only when the change is high-risk or public/release-facing.
3. Open a reviewable PR for every publishable change.
4. Keep scanner, tests, and security rules mandatory for every PR.

## Decision

| Rule | Policy |
|---|---|
| Default solo-maintainer flow | Backlog/Sprint Packet -> branch -> PR -> CI -> human merge. |
| Issue-first flow | Required only for high-risk or explicit-decision work. |
| PRs | Required for publishable changes, even when no issue is required. |
| CI | Required before merge. |
| Security | Never optional. Sensitive data blockers stop the change immediately. |

## Change matrix

| Change type | Issue required | PR required | CI required | Human approval required |
|---|---:|---:|---:|---:|
| Small fix | No | Yes | Yes | No, unless risk appears |
| Minor docs | No | Yes | Scanner at minimum | No |
| Synthetic tests/fixtures | No | Yes | Yes | No, unless scanner finds risk |
| Internal refactor | No | Yes | Yes | No, unless architecture changes |
| Normal sprint slice | Recommended | Yes | Yes | Review/merge only |
| Release or milestone | Yes | Yes | Yes | Yes |
| Architecture decision | Yes | Yes | Yes | Yes |
| Security, e.firma, certs, secrets, KMS/Vault | Yes | Yes | Yes | Yes |
| Real SAT integration | Yes | Yes | Yes | Yes |
| Storage, schema, or migration change | Yes | Yes | Yes | Yes |
| Large public change | Yes | Yes | Yes | Yes |
| Force push or public history rewrite | Yes | Yes | N/A | Yes |

## Issue-required work

Create an issue before publishing a PR for:

- releases or milestones;
- architecture changes;
- security changes;
- e.firma, certificate, secret, KMS, or Vault handling;
- real SAT integration;
- storage layout, database schema, or migration changes;
- large public changes;
- irreversible decisions.

Create an approved issue before implementation when the change could be destructive, expose sensitive data, require real SAT/e.firma access, or force a public history rewrite.

## Issue-optional work

An issue is not required for:

- small fixes;
- internal refactors;
- minor documentation;
- tests;
- synthetic fixtures;
- small CLI improvements;
- minor non-risky CI adjustments.

These still need a focused PR and validation before merge.

## Always mandatory

- No real CFDI fixtures.
- No real SAT metadata.
- No real SAT ZIP/XML packages.
- No real `.cer`, `.key`, `.pfx`, `.pem`, or `.p12` files.
- No passwords, tokens, secrets, or private-key material.
- No local config committed.
- No real RFCs, fingerprints, taxpayer names, or local paths in fixtures or docs.
- Sensitive fixture scanner passes.
- Pytest passes when code or behavior changes.
- `git diff --check` passes before commit/PR.

## Sprint Packet

For normal sprint work, use a Sprint Packet instead of a mandatory approval issue:

```text
Goal:
Scope:
Out of scope:
Acceptance criteria:
Validation plan:
Security checklist:
PR plan:
```

The Sprint Packet can live in `docs/planning/backlog.md`, a sprint planning document, or the PR body.

## Agent operating rule

```text
If the change requires an issue:
  verify the approved issue before PR publication.
  verify it before implementation only for high-risk or destructive work.

If the change does not require an issue:
  execute from backlog/Sprint Packet.
  open a focused PR.
  wait for CI.
  do not auto-merge.
```

## Stop conditions

Stop and ask for human approval when:

- a required issue is missing;
- possible sensitive data is detected;
- real SAT or real e.firma access is needed;
- a destructive file/database operation is needed;
- a public force push or history rewrite is needed;
- architecture/security scope becomes ambiguous.

## Next step

Use this policy before creating the next sprint branch or PR. Do not weaken the fixture scanner or security model to make the workflow faster.
