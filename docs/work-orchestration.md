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
- No wave starts until its required integration cut is present in `origin/dev`.
- Green tests do not replace fresh review.
- Every feature records module, owner, issue, branch, base, target, gates, and status.
- `status:approved` is an issue label. Exactly one `type:*` label belongs on the PR.

## Local-first integration model

This project uses local-first integration for active development.

- `dev` local may be ahead of `origin/dev` while a wave is being assembled.
- `origin/dev` is updated only through controlled integration cuts.
- Feature work starts from the current approved `dev` baseline.
- Remote PRs are created only after a local cut passes fresh review and gates.
- GitHub CI is intentionally lightweight and must not run heavy services by default.
- Container-backed checks remain local/manual unless explicitly promoted.
- Wave 3 or later work must not start until the required integration cut is present in `origin/dev`.

For the current governance transition, ORCH-001 and CI-001 converge locally in
`integration/dev-governance-ci`. That cut is the single publication unit; its
local readiness does not mean it has reached `origin/dev`.

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

Wave 3 is **blocked** until `INTEGRATION-GOV-CI` is integrated remotely in
`origin/dev`. A `local_ready` cut does not satisfy that remote dependency.

## Maintenance

- Update work-item state in the same work unit as its coordination change.
- Write actionable blockers rather than relying on prompt context.
- Never record secrets, credentials, complete fiscal identifiers, or local paths.
- Re-run `validate` after changing dependencies or state.
