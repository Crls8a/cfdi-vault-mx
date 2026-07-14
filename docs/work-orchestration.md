# Module-feature work orchestration

`docs/work-items.yaml` is the local source of truth for modules, features,
waves, branches, issues, approvals, labels, dependencies, and gates.

## Quick path

1. `python scripts/work_orchestrator.py validate`
2. `python scripts/work_orchestrator.py status`
3. `python scripts/work_orchestrator.py next`
4. `python scripts/work_orchestrator.py pr-ready <ID>` for publication readiness

The tool reports state only. It never changes labels, opens a PR, pushes, or
merges.

## Principles

- `dev` is the integration branch; `main` is reserved for releases.
- Every feature, chore, and test branch converges into `dev`.
- No wave starts until its required integration cut is present in `origin/dev`.
- Green tests do not replace fresh review.
- Dependencies and blockers are lists of unique, trim-aware, non-empty strings.
- Required scalar fields and Wave 3 references are non-empty strings.
- Declared local quality gates use exact `passed` evidence; arbitrary truthy values fail.
- Remote cuts require positive integer issue/PR references, `status:approved`,
  and exactly one lowercase canonical `type:<name>` PR label.

## Local-first integration model

This project uses local-first integration for active development.

- `dev` local may be ahead of `origin/dev` while a wave is being assembled.
- `origin/dev` is updated only through controlled integration cuts.
- Feature work starts from the current approved `dev` baseline.
- Remote PRs are created only after a local cut passes fresh review and gates.
- GitHub CI is intentionally lightweight and must not run heavy services by default.
- Container-backed checks remain local/manual unless explicitly promoted.
- Wave 3 or later work must not start until the required integration cut is present in `origin/dev`.

ORCH-001 and CI-001 reached `origin/dev` through the single GOV-001 publication
unit recorded as `INTEGRATION-GOV-CI`.

## Ceremony boundary

Local feature states (`planned` through `local_integrated`) require local gates,
dependencies, blockers, and fresh review, but no issue, remote branch, PR, or
label. Readiness, blockers, and generated prompts require a globally valid
registry and its exact authoritative item; malformed or forged context fails closed.

Integration cuts use `cut_ready → published_pr → integrated_remote`. Both
`kind: integration` and an `integration/*` branch are required; disagreement
fails closed. Publication retains the approved issue, canonical type label, PR
to `dev`, and exact lightweight-CI `passed` evidence. Integration cuts never
target release-only `main`; a future release kind must define that flow.

The sole historical exception is a complete `integrated_remote` integration
record marked `legacy_pre_ci001`, with truthful publication metadata and both
CI gates exactly `not_run_pre_ci001`. It never authorizes `pr-ready`.

## Levels

| Level | Meaning | Examples |
| --- | --- | --- |
| Module | Stable ownership boundary | `sat-download`, `worker`, `queue`, `parser`, `object-storage`, `workflow`, `repo-governance` |
| Feature | Branch-sized functional unit | `CACHE-003`, `STOR-004B`, `LIB-005B`, `QUEUE-004`, `PARSER-005B`, `ORCH-001` |
| Wave | Features integrated as a group | Wave 1, Wave 2, Wave 3 |
| Gate | Required evidence | branch policy, fresh review, targeted/full pytest, Ruff, scanners, Docker Compose config, security review, branch-pr compliance |

## Progression rules

A work item progresses only when its shared schema and invariants validate,
dependencies are integrated, blockers are cleared, and required gates have exact
pass evidence. `INTEGRATION-GOV-CI` is integrated remotely; Wave 3 remains
planned and can start only after explicit human approval. Active or completed
Wave 3 state requires both `started: true` and `human_approval: approved`.
The remote gate resolves the exact item named by `wave3.dependency`; no fixed
integration-cut ID can substitute for that declaration.

## Maintenance

- Update work-item state in the same work unit as its coordination change.
- Never record secrets, credentials, complete fiscal identifiers, or local paths.
- Re-run `validate` after changing dependencies or state.
