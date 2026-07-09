# Agent worktree to dev merge runbook

Use this runbook whenever an agent finishes a branch or worktree. The goal is to prevent completed work from drifting forever in side branches.

## Rule

Completed, tested work must be integrated into `dev` before the worktree is considered done.

`dev` is the integration branch for reviewed agent work. Feature branches may exist while work is in progress, but they must not become a permanent substitute for integration. `origin/dev` is the current source of truth when reconciling local or historical branches.

`main` is reserved for releases.

## Branch lineage guardrails

Use `dev` as the default base for new work.

| Situation | Rule |
|---|---|
| Independent feature, fix, test, or docs slice | Branch from `dev`. |
| Branch must start from another feature branch | Declare the parent dependency in the branch notes, PR body, or integration report. |
| Parent branch is still unmerged | Integrate and validate the parent first, or keep the child blocked. |
| Refactor work | Keep it small and do not mix behavior changes into the same branch. |
| Feature behavior | Integrate only with relevant tests and scanner evidence. |
| CLI/SAT work | Preserve domain, port, adapter, and infrastructure boundaries; do not put command logic back into `src/cfdi_vault/cli.py`. |
| Sensitive evidence | Never commit real SAT/CFDI data, RFCs, secrets, certificates, tokens, raw SOAP, ZIPs, XML, logs, or local paths. |
| Historical branch snapshot | Treat as reference material only; compare real unique patches against `origin/dev`. |
| Patch-equivalent or superseded branch | Do not merge it. Archive later with explicit authorization, or migrate only the useful part manually from a new branch based on `dev`. |
| Temporary integration branch | Do not reuse it as a base after it is absorbed into `dev`. |

If a branch cannot satisfy these rules, do not merge it as-is. Extract the safe part manually or leave it blocked with a clear plan.

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
- Keep SAT/CLI changes separated by layer: domain/application decisions in core modules, user input/output in CLI adapters, external I/O behind ports/adapters.

## Historical branch migration

Use this path when a branch was created before later architecture changes, such
as the CLI split or SAT/live-state hardening:

1. Keep the historical branch unchanged.
2. Compare it against `origin/dev` with `git cherry`, `git log --cherry-pick --right-only`, and file-level diffs.
3. Ignore large triple-dot diffs when `git cherry` shows the patches are already covered.
4. If useful work remains, create a new branch from `dev`.
5. Manually port only the useful behavior or documentation into the current architecture.
6. Run the scanner, `git diff --check`, and the smallest meaningful tests.

Never make an old branch "work" by restoring obsolete structure. In particular,
do not bring command logic back into `src/cfdi_vault/cli.py`.

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
- [ ] Parent branch or dependency chain, if any.
- [ ] Merge commit or fast-forward result.
- [ ] Tests and scanner evidence.
- [ ] Conflicts and how they were resolved.
- [ ] Whether any branch was superseded, manually extracted, discarded, or blocked.
- [ ] Confirmation that `src/cfdi_vault/cli.py` stayed a shim.
- [ ] Confirmation that no sensitive fiscal data or live SAT evidence was introduced.
- [ ] Worktrees kept or removed, with reasons.
- [ ] Branches kept or deleted, with reasons.
