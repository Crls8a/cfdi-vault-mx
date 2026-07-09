# Branch ledger after integration cleanup

This ledger records the branch map after `origin/dev` became the canonical development base. Old branches are reference snapshots, not live development bases.

## Quick path

1. Start every new feature from `dev`.
2. Return completed feature branches to `dev` after tests and scanner gates.
3. Use `main` only for releases.
4. Treat old branches as audit material; do not merge them directly.
5. If an old branch still has value, create a new branch from `dev` and migrate the useful change manually.

## Base canonical

| Item | Value |
| --- | --- |
| Canonical base | `origin/dev` |
| Canonical commit | `42d7a442eb1d458fb2c69f8c555c923463459d1b` |
| Local merge commit | `42d7a44 chore(dev): merge temporary integration sync` |
| Release branch | `main` only |

## Closed temporary branch

`integration/dev-sync-local` was a temporary reconciliation branch created to close a worktree/branch drift. It was absorbed into `dev` and must not be used as a development base.

## Policy

Old branches are reference snapshots. They may contain useful context, but many were created before the CLI split or before later SAT/security refactors. Do not make them "work" by reviving old structure.

Use this rule:

```text
origin/dev = current truth
old branches = reference material
new features = new branches from dev
```

When reviewing old work, separate:

1. Most recent commit date.
2. Real unique patches against `origin/dev`.
3. Old-looking diffs already covered by ancestry, patch-equivalence, squash, cherry-pick, or manual extraction.

`git cherry` and `git log --cherry-pick --right-only` carry more weight than a large triple-dot diff from an old merge base.

## Categories

| Category | Meaning | Default action |
| --- | --- | --- |
| absorbed by ancestry | Branch tip is contained in `origin/dev`. | Archive candidate. |
| absorbed by patch-equivalence | Branch history is not merged, but its patches exist in `origin/dev`. | Archive candidate. |
| superseded | Current `dev` has a safer or newer implementation. | Keep only for audit, then archive. |
| historical reference | Useful to understand past decisions, not a source branch. | Keep as reference if needed. |
| manual migration pending | Useful material exists, but must be extracted into a new branch from `dev`. | Create a new migration branch from `dev`. |
| blocked by risk | Direct merge could touch old CLI, `ports.py`, SAT/live state, or secrets. | Require design before any extraction. |
| archive candidate | No active unique work remains. | Archive/delete only with explicit authorization. |

## Absorbed by ancestry

- `integration/dev-sync-local`
- `codex/dev-sat-soap-public-api-docs`
- `codex/cli-refactor-base`
- `chore/sat-v15-context-reset`
- `fix/sat-harden-verify-scheduler-outcomes`
- `codex/sat-async-verify-scheduler`
- `codex/sprint-1-release-slice`

## Absorbed by patch-equivalence

- `codex/cli-refactor-parity-review`
- SAT auth transport/probe/endpoint branches
- Sprint 2 metadata, reconciliation, and status branches
- Sprint 4 and Sprint 5 secret boundary branches
- Live request state helper branches already covered by current implementation

## Superseded

- `feat/sat-redacted-verify-post-probe`
- `fix/sat-verify-probe-production-signed-envelope`
- `fix/sat-verify-signed-request-parity`
- `backup/live-request-state-persistence-49296f1`
- `feat/sat-live-smoke-command`

These branches may still show large diffs or non-equivalent commits because their merge bases are old. Do not merge them. Their useful behavior was covered by extraction, patch-equivalence, squash/cherry-pick, or current implementation.

## Seguimiento posterior

- `codex/cli-refactor-pr-governance`: useful documentation was migrated manually in `feature/migrate-governance-docs-from-old-branches`.
- `codex/gov-001-lightweight-governance`: useful documentation was migrated manually in `feature/migrate-governance-docs-from-old-branches`.
- The migration was docs-only.
- No merge or cherry-pick was performed from historical branches.
- Both branches remain historical references; they are not live development bases.
- `codex/sprint-3-sat-contract-orchestration` remains blocked by risk and requires a separate design review before touching code.
- Branch archiving still requires separate explicit authorization.

## Blocked branches

| Branch | Risk | Required before extraction |
| --- | --- | --- |
| `codex/sprint-3-sat-contract-orchestration` | Touches `ports.py` and SAT contract/orchestration surfaces. | Design review before touching code. |

Branches that touch `src/cfdi_vault/cli.py`, `ports.py`, SAT/live state, or secrets are unsafe for direct merge. They can revive old architecture or weaken security boundaries.

## Archive candidates

Archive candidates include:

- all branches absorbed by ancestry;
- all branches absorbed by patch-equivalence;
- superseded branches after audit needs are satisfied.

Do not delete or archive any branch without explicit authorization.

## Validation record

The cleanup that produced this ledger used `origin/dev` as base and required:

- `git diff --check`
- sensitive fixture scanner

No code change was required to create the ledger.

## Future workflow

```text
dev -> feature/* -> dev -> main for release
```

Rules:

- New features start from `dev`.
- Old branches are never used as base branches.
- Useful old work is migrated manually into a new branch from `dev`.
- `integration/dev-sync-local` is closed and not reused.
- `main` is reserved for releases.
