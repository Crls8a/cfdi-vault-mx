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

1. [Reference system scope](reference-system-scope.md)
2. [Product scope](product-scope.md)
3. [User stories](user-stories.md)
4. [CLI and terminal UX design](cli-ux-design.md)
5. [CLI help design](cli-help-design.md)
6. [Installer design](installer-design.md)
7. [Recovery pipeline contract](recovery-pipeline.md)
8. [XML storage and retention design](storage-and-retention.md)
9. [Infrastructure boundary](infrastructure-boundary.md)
10. [Architecture blueprint](architecture-blueprint.md)
11. [Flows and states](flows-and-states.md)
12. [Data and accounting model](data-and-accounting-model.md)
13. [Open questions](open-questions.md)
14. [Delegation plan](delegation-plan.md)
15. [Workstream ownership](workstream-ownership.md)
16. [Agile planning workspace](../planning/README.md)

## Architecture gate checklist

- [ ] The feature has a documented use case.
- [ ] The user story has acceptance criteria.
- [ ] The change preserves the library-versus-reference-system boundary.
- [ ] Public Python APIs are distinguished from internal/probing modules when packaging is affected.
- [ ] The CLI/UX behavior is documented when user-facing.
- [ ] The command appears in the CLI help catalog when user-facing.
- [ ] Installer/setup impact is documented when local dependencies change.
- [ ] Download, extraction, database load, and local storage registration are treated as one auditable pipeline.
- [ ] Recovery and synthetic import runtime data use PostgreSQL only.
- [ ] Slow XML ingestion and normalization cross the FastAPI/queue/worker boundary instead of becoming one direct CLI bulk load.
- [ ] Storage location, growth, and extraction path are documented when evidence files are written.
- [ ] The data written by the feature has an owner and retention rule.
- [ ] The failure mode has a user-facing error or operator state.
- [ ] The queue behavior defines retry, idempotency, and DLQ handling.
- [ ] The parser behavior defines complete vs partial extraction.
- [ ] The work unit is small enough to review independently.
- [ ] The work is represented by a planning backlog ID before implementation starts.

If any item is unchecked, document the gap before coding.
