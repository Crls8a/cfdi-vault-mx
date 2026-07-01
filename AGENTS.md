# Agent Operating Rules

This repository is maintained primarily by a solo maintainer.

The project handles fiscal data workflows for CFDI, SAT metadata, XML/ZIP packages, local storage, RFC profiles, and references to e.firma. Security gates are mandatory.

## Default mode

Agents may operate in solo-maintainer mode for routine changes.

Formal GitHub review approval is not required for routine PRs if:

- CI passes;
- the sensitive fixture scanner passes;
- tests pass;
- the PR scope matches the backlog, Sprint Packet, or documented task;
- no sensitive fiscal data is introduced;
- no irreversible architecture, security, storage, or schema decision is made.

## Always required

- PR for public changes.
- CI before merge.
- Sensitive fixture scanner before commit and before merge.
- Tests before merge.
- `git diff --check`.
- Clear PR description.
- Clean working tree after completion.

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
