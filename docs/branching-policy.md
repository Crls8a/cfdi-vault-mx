# Dev-first branching policy

All normal feature, chore, test, refactor, and documentation work must converge into `dev`.
`main` is reserved for stable release merges from `dev`.

## Branches permanentes

| Branch | Purpose | Rule |
|---|---|---|
| `main` | Stable release branch. | Receives release merges from `dev` only. |
| `dev` | Mandatory integration branch. | Normal feature work targets this branch. |

No normal feature branch should open a pull request directly to `main`.

## Flujo normal

1. Update `dev`.
2. Create the work branch from `dev`.
3. Work in a `feature`, `feat`, `chore`, `test`, `fix`, `docs`, or `refactor` branch.
4. Open the pull request against `dev`.
5. Resolve conflicts against `dev`.
6. Merge into `dev`.
7. Create a later release merge from `dev` into `main`.

## Subramas

Subbranches are allowed only when they make a larger change easier to review.

Examples:

- `feat/sat-v15-package-download-offline`
- `test/sat-v15-download-live-gate`

Even if a branch starts from another subbranch, its final integration path must converge into
`dev`. It must not skip directly to `main`.

## Hotfix

A direct `main` hotfix is an exception, not the normal flow.

Allowed only when all of these are true:

1. The change is critical enough to bypass `dev`.
2. The exception is documented in the pull request.
3. The hotfix merges into `main`.
4. The same fix is back-merged into `dev` immediately after release.

## SAT v1.5 integration order

SAT v1.5 work must merge toward `dev`, not `main`.

| Order | Branch | Required destination | Note |
|---:|---|---|---|
| 1 | `chore/sat-v15-context-reset` | `dev` | Establishes the clean SAT v1.5 context. |
| 2 | `feat/sat-v15-verify-transport-offline` | `dev` | Adds offline verify transport foundation. |
| 3 | `test/sat-v15-verify-live-gate` | `dev` | Adds controlled verify live gate after offline foundation. |
| 4 | `feat/sat-v15-package-download-offline` | `dev` | Adds offline package/download transport. |
| 5 | `test/sat-v15-download-live-gate` | `dev` | Adds controlled download live gate after package readiness. |

Do not merge these branches in this policy change. This document only defines the intended
integration path.

## Local check

Run the optional local check before opening a pull request:

```bash
python scripts/check_branch_policy.py
python scripts/check_branch_policy.py --strict
```

Normal mode prints warnings without failing when local history is incomplete. Strict mode exits
non-zero when the current branch appears not to be based on `dev`.
