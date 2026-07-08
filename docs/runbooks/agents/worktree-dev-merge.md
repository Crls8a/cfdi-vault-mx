# Agent worktree to dev merge runbook

Use this runbook whenever an agent finishes a branch or worktree. The goal is to prevent completed work from drifting forever in side branches.

## Rule

Completed, tested work must be integrated into `dev` before the worktree is considered done.

`dev` is the local integration branch for reviewed agent work. Feature branches may exist while work is in progress, but they must not become a permanent substitute for integration.

## Quick path

1. Finish the feature work in its own branch or worktree.
2. Run the required gates for that work.
3. Commit the work as a reviewable work unit.
4. Switch to `dev` or create `dev` from the most advanced clean tested branch if it does not exist.
5. Merge the finished branch into `dev`.
6. Resolve conflicts by preserving architecture rules, not by taking the largest file.
7. Run the integration gates on `dev`.
8. Only then mark the worktree ready for cleanup or PR handoff.

## Creating dev

If `dev` does not exist:

1. Identify the most advanced branch that is both clean and tested.
2. Create `dev` from that branch.
3. Record the reason in the final report and local worktree manifest.

Do not create `dev` from a dirty worktree, an untested branch, or a branch with unresolved security/schema concerns.

## Merge eligibility

| Branch state | Action |
|---|---|
| Clean, committed, scanner passed, tests passed | Merge into `dev`. |
| Dirty or partially staged | Do not merge. Split, finish, or ask for owner decision. |
| Tests failing for known unrelated infrastructure | Document the blocker before merge; do not hide it. |
| Sensitive data detected | Stop and ask Carlos. |
| Real SAT/e.firma needed | Stop and ask Carlos. |
| Irreversible schema/security/storage change | Stop and ask Carlos unless already covered by an approved plan. |

## Required gates before merge

Every completed worktree must run:

```powershell
python scripts\scan_sensitive_fixtures.py --root .
git diff --check
```

Also run the smallest meaningful test set for the touched area. If production code changed, run the full suite before merge or clearly document why it cannot run.

## Required gates after merge to dev

Run the same gates again from `dev`:

```powershell
python scripts\scan_sensitive_fixtures.py --root .
git diff --check HEAD~1..HEAD
```

For code merges, also run targeted tests and the full suite when feasible. The merge is not complete until `dev` is clean.

## Conflict rules

Resolve conflicts by ownership:

- Keep `src/cfdi_vault/cli.py` as the compatibility shim.
- Move CLI command behavior into `src/cfdi_vault/adapters/cli/` family modules.
- Keep tests pointed at the module that owns the behavior.
- Do not resurrect large legacy files just because that makes Git conflict resolution easier.
- Keep docs indexes additive unless two entries say contradictory things.

## Cleanup

After `dev` contains the work:

1. Verify the feature worktree is clean.
2. Verify the feature branch is merged or intentionally retained for audit.
3. Remove the worktree only when it has no uncommitted work.
4. Run `git worktree prune`.
5. Delete local branches only when Git confirms they are merged, or report why they remain.

Never delete dirty worktrees, force-delete branches, or reset someone else's WIP.

## Final report checklist

- [ ] Source branch and worktree path.
- [ ] `dev` start point.
- [ ] Merge commit or fast-forward result.
- [ ] Tests and scanner evidence.
- [ ] Conflicts and how they were resolved.
- [ ] Worktrees kept or removed, with reasons.
- [ ] Branches kept or deleted, with reasons.
