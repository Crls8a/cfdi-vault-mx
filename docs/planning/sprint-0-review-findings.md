# Sprint 0 review findings

This file records the first Sprint 0 agent review results. It is the evidence trail for whether Sprint 0 can be accepted.

## Summary

Sprint 0 is in review, not accepted yet. Architecture and documentation navigation are ready for team acceptance. QA found a real gap: the repository had a high-level synthetic-only rule, but no explicit fixture policy. That gap has been addressed by adding fixture policy documentation and a Sprint 1 scanner backlog item.

## Findings

| Backlog ID | Reviewer | Status | Finding | Follow-up |
|---|---|---|---|---|
| ARCH-001 | Architecture reviewer | Ready | No unknown architecture blocker found for Sprint 1. | Sprint 1 should start with safe profile config, storage resolver, and installer work. |
| PM-001 | PM / docs reviewer | Ready for acceptance | Sprint plan is finite enough to start Sprint 0. | Move to accepted only after team accepts review findings. |
| DOC-001 | PM / docs reviewer | Ready for acceptance | Root README and docs index point to planning. | Move to accepted after PM-001 is accepted. |
| QA-001 | QA / fixture reviewer | Was not ready; now remediated for review | Fixture policy was missing. | Review `docs/testing/fixture-policy.md` and the `QA-002` scanner evidence. |

## Architecture follow-ups for Sprint 1

- Define storage root resolver precedence: environment, config file, then default local path.
- Define safe profile config before wiring real storage, installer, or signer flows.
- Define exact `doctor` readiness checks for Docker, folders, PostgreSQL, RabbitMQ, Redis, and worker health.
- Refine retention/backup policy details for stored ZIP/XML evidence.

## QA follow-ups for Sprint 1

- Review the implemented `QA-002` fixture safety scanner.
- Scan for `.cer`, `.key`, credentials, committed runtime evidence, taxpayer names, and real-looking RFC values outside the allow-list.
- Keep `examples/README.md`, `tests/README.md`, and `docs/testing/fixture-policy.md` synchronized.

## Current exit decision

| Outcome | Status |
|---|---|
| Sprint 0 accepted | Not yet. Needs human/team acceptance. |
| Sprint 1 can start after acceptance | Yes, for STOR-001, INF-001, INST-001, and QA-002. |
| Known blockers | None for QA-002. Scanner is implemented and accepted; remaining improvements are hardening suggestions. |

## Next step

Review [Team board](team-board.md), then decide whether to accept Sprint 0.
