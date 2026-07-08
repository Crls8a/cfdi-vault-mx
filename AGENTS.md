# Agent Operating Rules

This repository is maintained primarily by a solo maintainer.

The project handles fiscal data workflows for CFDI, SAT metadata, XML/ZIP packages, local storage, RFC profiles, and references to e.firma. Security gates are mandatory.

## Project skills

Before creating or changing reusable `cfdi_vault` library functionality, package metadata, public APIs, SAT download modules, parsers, ports, or release gates, agents must load `skills/cfdi-library-quality/SKILL.md`.

## Default mode

Agents may operate in solo-maintainer mode for routine changes.

Formal GitHub review approval is not required for routine PRs if:

- CI passes;
- the sensitive fixture scanner passes;
- tests pass;
- the PR scope matches the backlog, Sprint Packet, or documented task;
- no sensitive fiscal data is introduced;
- no irreversible architecture, security, storage, or schema decision is made.


## Architecture discipline

Agents must keep adapters thin and protect SOLID boundaries. For CLI work:

- `src/cfdi_vault/cli.py` is only a compatibility entrypoint. Do not add command logic there.
- Typer command families live under `src/cfdi_vault/adapters/cli/`.
- CLI modules may parse user input, call application/domain services, and print output; business rules belong in application/domain modules.
- Prefer small family modules over large catch-all files. If a CLI file starts mixing unrelated command families, split it before adding more behavior.
- Do not introduce real SAT, e.firma, CFDI, RFC, certificate, token, or local-path data while refactoring adapters.

### CLI merge-conflict policy

When a merge or rebase touches CLI files, the source of truth is the split adapter package, not the legacy monolith:

- Keep `src/cfdi_vault/cli.py` as a thin compatibility shim that exports `app`.
- Preserve command behavior by resolving conflicts inside `src/cfdi_vault/adapters/cli/` family modules.
- Do not restore the previous 3,400+ line `cli.py` implementation to make a merge easier.
- If another branch added command logic to `src/cfdi_vault/cli.py`, move that logic into the correct family module before completing the merge.
- After any CLI conflict resolution, run CLI tests, the sensitive fixture scanner, and `git diff --check` before committing.

## Always required

- PR for public changes.
- CI before merge.
- Sensitive fixture scanner before commit and before merge.
- Tests before merge.
- `git diff --check`.
- Clear PR description.
- Clean working tree after completion.

## Dev integration rule

Completed agent work must not remain indefinitely in side worktrees. After a worktree is finished, committed, and tested, merge it into the local `dev` integration branch before marking the worktree complete.

- If `dev` does not exist, create it from the most advanced clean branch that has passed the relevant gates.
- Do not merge dirty, partially staged, untested, or sensitive work into `dev`.
- Re-run scanner, `git diff --check`, and relevant tests from `dev` after the merge.
- Keep worktrees until their work is integrated into `dev` or explicitly retained for audit.
- Follow [Agent worktree to dev merge runbook](docs/runbooks/agents/worktree-dev-merge.md) for exact steps and cleanup rules.

## Never allowed

- Real CFDI files.
- Real SAT metadata.
- Real SAT ZIP packages.
- Real `.cer`, `.key`, `.pfx`, `.pem`, or `.p12`.
- Passwords, tokens, private keys, or secrets.
- Local config files.
- Real RFCs, certificate fingerprints, or personal local paths in fixtures or docs.

## Human gate required

Stop and ask Carlos if:

- real SAT access is needed;
- real e.firma is needed;
- secrets or certificates are involved;
- sensitive data is detected;
- schema, storage, security, or architecture changes are irreversible;
- branch protection blocks merge;
- CI fails and the cause is not obvious;
- force push to a shared/public branch is required;
- destructive operations are needed;
- the task scope contradicts existing planning docs.

## Issues

Issues are required for:

- releases;
- architecture changes;
- security changes;
- e.firma, certificate, or secret handling;
- real SAT integration;
- storage, schema, or migrations;
- large public changes;
- irreversible decisions.

Issues are optional for:

- small fixes;
- tests;
- documentation;
- synthetic fixtures;
- internal refactors;
- minor CLI improvements;
- minor CI maintenance.

## Sprint execution

For normal sprints, use a Sprint Packet or backlog entry.

Agents should:

1. plan work units;
2. implement;
3. run internal review;
4. fix findings;
5. run scanner and tests;
6. create clean commits;
7. open PR;
8. merge only when CI is green and no human gate applies.

## Stacked work

Agents may continue development in a separate stacked branch while another PR is under review, but must not contaminate a PR branch with unrelated sprint work.
