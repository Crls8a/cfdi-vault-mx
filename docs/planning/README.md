# Agile planning workspace

This folder is the planning layer for CFDI Vault MX. It turns the foundation documents into sprint-sized work that can be delegated, reviewed, and shipped without creating avoidable technical debt.

## Decision

The planning source of truth is Markdown in this repository. This keeps the plan versioned with the code and lets the team edit it through branches, pull requests, or any Git-backed editor. If the team later uses GitHub Projects, Linear, Jira, or Notion, each item should still link back to the backlog ID in this folder.

## Quick path

1. Read [Agile operating model](agile-operating-model.md) to understand cadence, roles, and quality gates.
2. Read [Lightweight governance policy](governance.md) before deciding whether an issue is required.
3. Read [Living system plan](living-system-plan.md) before changing objectives, architecture, security, source-of-truth docs, or release promises.
4. Read [Sprint roadmap](sprint-roadmap.md) to see the recommended execution order.
5. Use [Sprint 0 execution plan](sprint-0-execution.md) to start the first sprint safely.
6. Use [Backlog](backlog.md) to create Sprint Packets, issues, or assign work.
7. Use [Team board](team-board.md) to track the current sprint.

## Planning map

| Document | Use it for |
|---|---|
| [Agile operating model](agile-operating-model.md) | Team rules, roles, ceremonies, Definition of Ready, Definition of Done. |
| [Lightweight governance policy](governance.md) | Solo-maintainer issue policy, PR/CI requirements, and mandatory security gates. |
| [Living system plan](living-system-plan.md) | Source-of-truth hierarchy, security workstream, architecture/doc gaps, and next work units for the case study. |
| [Sprint roadmap](sprint-roadmap.md) | Sequencing, sprint goals, parallel tracks, blockers, exit criteria. |
| [Sprint 0 execution plan](sprint-0-execution.md) | First sprint scope, agent assignments, handoff prompts, acceptance gate. |
| [Sprint 0 review findings](sprint-0-review-findings.md) | Agent review results and Sprint 0 acceptance evidence. |
| [Backlog](backlog.md) | Work item IDs, dependencies, owner roles, acceptance criteria. |
| [Team board](team-board.md) | Current sprint execution, status, blocked work, handoff notes. |

## Editing workflow

1. Add or update a backlog item or Sprint Packet in [Backlog](backlog.md).
2. Confirm whether the change requires an issue using [Lightweight governance policy](governance.md).
3. Confirm it passes Definition of Ready from [Agile operating model](agile-operating-model.md).
4. Move it into the active sprint board in [Team board](team-board.md).
5. Link implementation PRs or external tickets back to the backlog ID when they exist.
6. Mark the item accepted only after tests, docs, and user-facing behavior match the acceptance criteria.

## Planning gate

Before coding a backlog item, confirm:

- [ ] The item maps to a user story or foundation decision.
- [ ] Dependencies are explicit.
- [ ] The owner role is clear.
- [ ] The expected user/operator behavior is documented.
- [ ] The failure mode is known or captured as an open question.
- [ ] The work can be reviewed inside the agreed review budget.

## Next step

Start Sprint 0 from [Sprint 0 execution plan](sprint-0-execution.md), then update [Team board](team-board.md).
