# Foundation-first plan

This folder is the architectural gate for CFDI Vault MX v2. Contributors should read this before adding more production behavior.

## Decision

No more live SAT, parser-depth, queue-retry, or installer expansion should be implemented until the foundation documents answer:

1. What problem does the library solve?
2. What is explicitly out of scope?
3. Which flows are supported?
4. What data must be durable?
5. What can be cached or retried?
6. What remains ambiguous?
7. Which work can be delegated safely?

## Reading order

1. [Product scope](product-scope.md)
2. [User stories](user-stories.md)
3. [CLI and terminal UX design](cli-ux-design.md)
4. [CLI help design](cli-help-design.md)
5. [Installer design](installer-design.md)
6. [Recovery pipeline contract](recovery-pipeline.md)
7. [XML storage and retention design](storage-and-retention.md)
8. [Architecture blueprint](architecture-blueprint.md)
9. [Flows and states](flows-and-states.md)
10. [Data and accounting model](data-and-accounting-model.md)
11. [Open questions](open-questions.md)
12. [Delegation plan](delegation-plan.md)
13. [Workstream ownership](workstream-ownership.md)
14. [Agile planning workspace](../planning/README.md)

## Architecture gate checklist

- [ ] The feature has a documented use case.
- [ ] The user story has acceptance criteria.
- [ ] The CLI/UX behavior is documented when user-facing.
- [ ] The command appears in the CLI help catalog when user-facing.
- [ ] Installer/setup impact is documented when local dependencies change.
- [ ] Download, extraction, database load, and local storage registration are treated as one auditable pipeline.
- [ ] Storage location, growth, and extraction path are documented when evidence files are written.
- [ ] The data written by the feature has an owner and retention rule.
- [ ] The failure mode has a user-facing error or operator state.
- [ ] The queue behavior defines retry, idempotency, and DLQ handling.
- [ ] The parser behavior defines complete vs partial extraction.
- [ ] The work unit is small enough to review independently.
- [ ] The work is represented by a planning backlog ID before implementation starts.

If any item is unchecked, document the gap before coding.
