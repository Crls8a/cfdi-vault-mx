# Module-feature work orchestration

`docs/work-items.yaml` is the local source of truth for modules, features,
waves, branches, issues, approvals, labels, dependencies, and gates.

## Quick path

1. `python scripts/work_orchestrator.py validate`
2. `python scripts/work_orchestrator.py status`
3. `python scripts/work_orchestrator.py pr-ready <ID>`

The tool reports state only. It never changes labels, opens a PR, pushes, or
merges.

## Principles

- `dev` is the integration branch; `main` is reserved for releases.
- Every feature, chore, and test branch converges into `dev`.
- No wave starts until dependencies are in `origin/dev`, unless a clean local
  `dev` base is explicitly authorized and recorded.
- Green tests do not replace fresh review.
- Every feature records module, owner, issue, branch, base, target, gates, and status.
- `status:approved` is an issue label. Exactly one `type:*` label belongs on the PR.

## Levels

| Level | Meaning | Examples |
| --- | --- | --- |
| Module | Stable ownership boundary | `sat-download`, `worker`, `queue`, `parser`, `object-storage`, `workflow`, `repo-governance` |
| Feature | Branch-sized functional unit | `CACHE-003`, `STOR-004B`, `LIB-005B`, `QUEUE-004`, `PARSER-005B`, `ORCH-001` |
| Wave | Features integrated as a group | Wave 1, Wave 2, Wave 3 |
| Gate | Required evidence | branch policy, fresh review, targeted/full pytest, Ruff, scanners, Docker Compose config, security review, branch-pr compliance |

## Progression rules

A work item progresses only when dependencies and gates pass and blockers are
cleared. PR readiness also requires an approved issue and exactly one declared
PR `type:*` label. Normal work targeting anything other than `dev` is invalid;
`main` produces an explicit release-only warning.

Wave 3 is **blocked** while `INTEGRATION-WAVE1-WAVE2` is blocked or absent from
`origin/dev`. Local integration does not satisfy that remote dependency.

## Maintenance

- Update work-item state in the same work unit as its coordination change.
- Write actionable blockers rather than relying on prompt context.
- Never record secrets, credentials, complete fiscal identifiers, or local paths.
- Re-run `validate` after changing dependencies or state.
