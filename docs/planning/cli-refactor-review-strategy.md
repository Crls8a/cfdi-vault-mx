# CLI refactor review strategy

Use this strategy to merge the CLI family refactor without rebuilding the legacy monolith or creating an unreviewable PR. The default path is small, ordered PRs with a 400 changed-line review budget.

## Quick path

1. Merge the base CLI split first.
2. Merge follow-up branches in dependency order: SAT subfamilies, parity report, then governance docs.
3. Keep each PR under 400 changed lines unless Carlos explicitly accepts `size:exception`.
4. Resolve conflicts into `src/cfdi_vault/adapters/cli/` family modules, never into the old monolithic `cli.py`.
5. Run the final gates before merge and clean the worktree after the branch lands.

## Review budget

| Rule | Policy |
|---|---|
| Default budget | 400 changed lines, counted as additions plus deletions. |
| Exception label | Use `size:exception` only after explicit maintainer acceptance. |
| Budget pressure | Split by reviewable CLI family or workflow instead of hiding scope in one PR. |
| Generated or mechanical churn | Still counts toward reviewer load unless the PR isolates it and explains why it cannot split cleanly. |

A PR should be small enough to review in about an hour. If the diff crosses the budget, either chain it or document why the exception is safer than splitting.

## Recommended PR and merge order

| Order | Branch/work item | Why it goes here | Merge rule |
|---:|---|---|---|
| 1 | `codex/cli-refactor-base` | Establishes the shim and adapter-family source of truth. | Merge first; all follow-up branches rebase or retarget on it. |
| 2 | SAT subfamilies | Moves the highest-risk large family into smaller SAT modules. | Merge before parity so the report validates the final family shape. |
| 3 | Parity report | Confirms command behavior and review findings after the split. | Merge after code-shape changes it evaluates. |
| 4 | Governance docs | Locks review, conflict, and cleanup rules for future work. | Merge last unless the rules are needed to unblock reviewers earlier. |

If a later branch is ready first, keep it open but do not merge it ahead of a dependency that changes the same CLI family surface.

## One PR vs chained PRs

Use one PR when all of this is true:

- the PR stays at or below 400 changed lines;
- the change has one clear work unit;
- the diff touches one CLI family or one docs/review artifact set;
- tests and scanner evidence fit naturally in the PR body;
- rollback would not remove unrelated work.

Use chained PRs when any of this is true:

- the PR exceeds 400 changed lines without an accepted `size:exception`;
- multiple CLI families change for different reasons;
- SAT behavior, security gates, or fixture policy need focused review;
- reviewers need to validate code shape before parity or governance follow-ups;
- conflict risk is lower when branches land in small dependency steps.

For chained PRs, each PR should state its dependency, current boundary, verification evidence, and what remains out of scope.

## Conflict rule

`src/cfdi_vault/cli.py` must remain a compatibility shim that imports and exports `app`.

When resolving a merge or rebase conflict:

1. Start from the split adapter package as the source of truth.
2. Never accept the old 3,400+ line `src/cfdi_vault/cli.py` implementation.
3. If another branch added command logic to `cli.py`, move that logic into the correct module under `src/cfdi_vault/adapters/cli/`.
4. Keep family ownership aligned with `docs/planning/cli-family-refactor-plan.md`.
5. Run the CLI/SAT validation gate before committing the conflict resolution.

This is not negotiable. Taking the old file may look faster, but it reintroduces the exact merge bomb the refactor removed.

## Final gates before merge

| Gate | Required when | Command or evidence |
|---|---|---|
| Sensitive fixture scanner | Every PR, including docs-only PRs. | `python scripts/scan_sensitive_fixtures.py --root .` |
| Whitespace check | Every PR. | `git diff --check` |
| Targeted CLI/SAT tests | CLI behavior, SAT command, or conflict-resolution code changed. | Run the relevant CLI/SAT pytest targets from the family refactor plan. |
| Full pytest | Production code changed or conflict resolution touched behavior. | `pytest` or the repo's standard full-suite command. |
| PR description | Every PR. | Include scope, out of scope, review budget, verification, and conflict notes. |

Docs-only governance changes do not require pytest unless they also change code, test fixtures, or executable examples.

## Worktree and branch cleanup

After a PR merges:

1. Verify the PR merged and CI is green.
2. Verify the worktree is clean with `git status -sb`.
3. Remove the merged worktree only when it has no uncommitted or unpushed work.
4. Run `git worktree prune` after removing stale worktrees.
5. Delete the local branch only after Git confirms it is merged.
6. Retarget or rebase any child branch that depended on the merged branch before continuing.

Never delete a dirty worktree or force-delete a branch that may contain unmerged work. When in doubt, keep it and report the cleanup blocker.

## Review checklist

- [ ] Review budget is at or below 400 changed lines, or `size:exception` is explicitly accepted.
- [ ] PR order matches the dependency chain or explains why it differs.
- [ ] `src/cfdi_vault/cli.py` remains a shim only.
- [ ] New or conflicting command logic lives in the correct CLI family module.
- [ ] Scanner and `git diff --check` pass.
- [ ] Targeted CLI/SAT tests pass when code changed.
- [ ] Full pytest runs before merge when production code changed.
- [ ] Worktree and local branch cleanup are planned after merge.
