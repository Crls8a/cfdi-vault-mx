# Accounting ledger V5 design (pending human approval)

**Status:** design only. No migration, model, worker, CLI, or SAT behavior is
changed by this document.

**Decision gate:** every schema, retention, and identity decision below is a
proposal. A maintainer must approve the additive migration and its rollback
runbook before implementation. The first implementation must remain offline
and use synthetic fixtures only.

## 1. Current facts (verified in the repository)

- PostgreSQL/Flyway is the durable recovery store. ZIP, TXT, and XML content is
  referenced from PostgreSQL but remains in external storage.
- `cfdi_documents` is tenant-scoped and has a unique `(tenant_id, uuid)` key.
  It stores the normalized header, parser status, XML hash, and a `raw_payload`
  JSONB column; the current schema and application do not enforce a boundedness
  limit for that payload.
- `cfdi_concepts` has a foreign key to `cfdi_documents.id`, but no tenant column,
  source evidence reference, ordinal, or idempotency key.
- `cfdi_taxes` stores a document identifier and optional concept foreign key, but
  has no tenant column, tax ordinal, source hash, or uniqueness constraint.
- `cfdi_payments`, `cfdi_payroll`, and `cfdi_related_documents` identify the
  parent by a document identifier only. They lack tenant-safe foreign keys,
  source evidence references, ordinals, and idempotency constraints.
- The payroll table has dates and type, but no durable amount columns. The
  payment table has date, form, currency, and amount, but no exchange rate or
  related-document identity.
- `xml_evidence` already records tenant, source package reference, XML hash,
  storage reference, parser version/status, and size. This is the preferred
  evidence anchor; raw XML must not be copied into ledger rows.
- Pure normalizers and report DTOs exist and are tested, but the worker does not
  yet persist their child records. Process-local duplicate suppression is not a
  durable idempotency guarantee.

These facts are a boundary, not an assertion that the accounting ledgers are
already populated.

## 2. Proposed V5 boundary (not approved)

The migration should be additive and owned by Flyway. It should preserve legacy
columns while adding a tenant-safe, evidence-aware generation of normalized
rows. New writes use the V5 columns; legacy rows are imported only after a
conflict report and explicit decision. No destructive rewrite is required.

### Tenant-safe references

1. Add `tenant_id` and `document_id` to every child ledger table. Keep legacy
   document identifier columns during a compatibility period.
2. Add unique parent keys `(tenant_id, id)` to both `cfdi_documents` and
   `xml_evidence`, then use composite foreign keys `(tenant_id, document_id)`
   from concepts, taxes, payments, payroll, and related documents, and
   `(tenant_id, source_evidence_id)` from every child to `xml_evidence`.
3. Add `(tenant_id, id)` uniqueness to concepts so a tax can reference a
   concept within the same tenant. A tax without a concept uses an explicit
   document-level scope, never a guessed concept.
4. Backfill new tenant/document columns only when exactly one parent matches.
   Zero matches or more than one match stops the migration and produces a
   manual-review report; it must not infer tenant ownership from an identifier.
5. Replace the legacy single-column child foreign keys after the composite
   constraints are validated. A compatibility `document_id` column may remain,
   but its standalone foreign key must be removed; the composite key is the
   canonical tenant boundary. Cross-tenant joins are a constraint violation.
6. Apply `NOT NULL` and the composite foreign keys only after the backfill
   validation succeeds. Keep the old columns read-only during the transition.

### Evidence and source references

Each V5 child row should carry:

- `source_evidence_id` referencing `xml_evidence.id` with the same tenant;
- `source_sha256` copied as an evidence fingerprint, not as public output;
- `parser_version` and `parser_status`;
- `source_ordinal` (the ordinal within the source document or complement);
- `normalization_generation` (an explicit parser/normalizer release generation);
- a private `idempotency_key` derived from tenant, document, evidence hash,
  record kind, generation, and ordinal.

For new rows, `source_evidence_id`, `source_sha256`, `source_ordinal`,
`normalization_generation`, and `idempotency_key` are `NOT NULL`. Add checks for
lowercase hexadecimal `source_sha256` of exactly 64 characters, positive
ordinals, and a non-empty bounded generation string. Add a same-tenant
composite foreign key to the new `(tenant_id, id)` key on `xml_evidence`.

**Proposed decision (pending):** V5 normalized fields must never depend on the
legacy `raw_payload`. A future diagnostic JSONB field may retain only an
allow-listed, redacted, size-bounded summary after an approved application or
schema bound is implemented. Until that bound is approved and tested, the V5
mapper must omit diagnostic JSONB rather than copy `raw_payload`. No raw XML,
ZIP/TXT bytes, secrets, or unbounded source text may enter normalized ledger
rows. Evidence references are private database data; public status exposes
only counts and completeness.

## 3. Proposed identity and uniqueness rules

The following keys are deterministic and evaluated inside PostgreSQL. They are
not filenames and are never printed by status commands.

| Ledger | Proposed identity and uniqueness | Conflict behavior |
|---|---|---|
| Concept | `(tenant_id, document_id, source_sha256, normalization_generation, source_ordinal)` | Same key is a no-op; same ordinal with a different hash or generation creates a quality conflict or new generation and does not overwrite. |
| Tax (concept scope) | `(tenant_id, document_id, source_sha256, normalization_generation, concept_ordinal, source_ordinal)` with a partial unique index `WHERE scope='concept'` | Preserve concept scope; conflicting evidence is manual review. |
| Tax (document scope) | `(tenant_id, document_id, source_sha256, normalization_generation, source_ordinal)` with a partial unique index `WHERE scope='document'` | `concept_ordinal` stays `NULL`; distinct source ordinals remain distinct. |
| Payment | `(tenant_id, document_id, source_sha256, normalization_generation, payment_ordinal)` | Reprocessing is idempotent; a changed payment at the same generation/ordinal is a conflict. |
| Payment-related document | `(tenant_id, document_id, source_sha256, normalization_generation, payment_ordinal, related_ordinal)` | Preserve each relation; duplicate relation in the same evidence is counted and reviewed. |
| Payroll | `(tenant_id, document_id, source_sha256, normalization_generation, payroll_ordinal)` | Same evidence/generation is a no-op; changed evidence is a new generation or conflict. |
| Related CFDI | `(tenant_id, document_id, source_sha256, normalization_generation, related_ordinal)` | Keep relation type and private related identity; never collapse rows by identifier alone. |

The tax table must enforce
`CHECK ((scope='document' AND concept_ordinal IS NULL) OR
(scope='concept' AND concept_ordinal > 0))`. The partial indexes above avoid
nullable-key ambiguity; an approved alternative is a reserved sentinel `0`
with the equivalent check and `COALESCE(concept_ordinal, 0)` expression index.
The database should expose a unique index over each key and an index over
`(tenant_id, document_id, source_sha256, normalization_generation)`. Hash or
generation changes must not silently delete the prior generation. The mapper
must use `INSERT ... ON CONFLICT` only for the exact key; broad upserts by
document alone are forbidden.

## 4. Missing payroll and payment fields

### Payroll (proposed nullable fields)

Add nullable numeric fields for source values that the normalizer can actually
observe: total perceptions, total deductions, total other payments, and a
source-provided net amount when present. Add currency and source period/type
metadata where the complement supplies it. Missing values remain `NULL` and
increment an incompleteness count. The mapper must never derive net pay by
subtracting incomplete totals, and it must not store employee identity fields
unless the approved retention policy permits them.

### Payments (proposed fields)

Add nullable `exchange_rate`, `payment_ordinal`, `source_evidence_id`, and
`source_sha256`. For each related document, persist a private related-document
identity, relation ordinal, applied amount when supplied, installment number
when supplied, and currency. Validate that a non-default currency has a
positive exchange rate; a default currency must not receive an invented rate.
Missing related identity is an incomplete record, not an inferred link.

`payment_ordinal`, related ordinals, `source_sha256`, and the generation are
non-null and positive/non-empty under the constraints above. The proposed
payment check is `currency IS NULL OR (currency = 'MXN' AND exchange_rate IS
NULL) OR (currency <> 'MXN' AND exchange_rate IS NOT NULL AND exchange_rate >
0)`. Thus exchange rate is conditionally required for a non-default currency,
and the default currency cannot carry an invented rate.

These fields support reconciliation but do not establish that an invoice was
paid, deductible, or taxable.

## 5. Transaction and worker boundaries

### External SAT operations

1. Transaction A selects a due operation, validates the grant, creates the
   claim, and commits. The SAT call happens after commit and outside any DB
   transaction.
2. The worker records the categorized response, artifact reference, and next
   state in Transaction B. A download timeout is `uncertain`; no automatic
   second download is allowed.
3. RabbitMQ messages contain only opaque work references and aggregate metadata.
   An outbox/event row is committed with the durable result before publication;
   a publisher retry is idempotent by event key.

### Parsing and ledger mapping

1. A parser job claims its reference in a short transaction, then reads the
   external XML and validates it without holding a DB transaction.
2. A second short transaction inserts the header/child rows using the exact
   evidence idempotency keys, writes aggregate counts, and marks the job done.
3. A crash before commit leaves the job retryable; a crash after commit is a
   no-op on the same keys. A parser error records a categorized terminal or
   partial result without deleting evidence.
4. Two workers must be safe under `FOR UPDATE SKIP LOCKED`; tenant and evidence
   constraints, not process memory, enforce isolation and idempotency.

No transaction may remain open during SAT, storage, or RabbitMQ network I/O.

## 6. Rollback and reprocess policy

- A failed database transaction rolls back only its uncommitted rows. Stored
  evidence and append-only job/audit history are retained.
- Reprocessing reads the same external evidence. The same generation and keys
  produce no new rows; a new parser generation creates a new, explicitly
  comparable generation.
- A different evidence hash for the same document is retained as a conflict or
  new generation; it is never used to overwrite the prior evidence.
- Repair uses a new mapper run and a new claim/event, not direct row edits or
  deletion. Any migration rollback is manual, reverse-order, and prohibited
  while live campaign state or child rows depend on it.
- Legacy rows remain queryable. Import is idempotent and stops on ambiguous
  tenant/parent matches.

### Manual reverse-order rollback runbook (proposed)

Rollback is not an online operation and is not automatic. Before touching the
schema, stop campaign/parse writers, drain the queue, take a database backup,
and record counts for every V5 generation and child table. Abort if any live
worker still owns a claim or if the audit cannot prove which rows are V5.

In reverse dependency order, an approved operator would:

1. disable the V5 mapper and reject new V5 jobs;
2. remove V5 outbox/event references only after their publication audit is
   complete (never remove evidence or raw artifacts);
3. drop V5 unique indexes, partial tax indexes, CHECK constraints, and
   composite foreign keys from concepts, taxes, payments, payroll, and related
   documents;
4. remove V5 child columns (source references, ordinals, generation,
   idempotency, tenant/document additions, and proposed payment/payroll fields)
   only after an approved export/backup confirms retention; leave legacy
   columns and rows untouched;
5. drop the `(tenant_id, id)` parent keys from `xml_evidence` and
   `cfdi_documents` last, after all V5 child references are gone;
6. rerun schema validation, restore the legacy mapper, and verify row counts,
   queue state, and redacted status output.

Affected objects are the V5 columns, constraints, indexes, and mapper-facing
outbox references on `cfdi_documents`, `xml_evidence`, `cfdi_concepts`,
`cfdi_taxes`, `cfdi_payments`, `cfdi_payroll`, and
`cfdi_related_documents`. A rollback must not delete `xml_evidence`, external
artifacts, legacy rows, or audit history. If any V5 rows cannot be separated,
rollback stops for manual review rather than guessing.

## 7. Public redaction contract

Safe status and report outputs may include period, direction, currency, parser
status, completeness, counts, totals, and fixed quality categories. They must
exclude row identifiers, tenant identifiers, RFC/UUID values, hashes, storage
keys/paths, raw payloads, SOAP, credentials, and error text from external
responses. Private operator exports require an explicit authorization boundary,
and even those exports must not contain raw artifacts or secrets.

## 8. Acceptance tests before implementation approval

The migration and mapper are accepted only when all tests below pass using a
clean synthetic PostgreSQL database and no SAT contact:

1. Flyway applies V5 additively; a documented reverse-order rollback is
   validated on a disposable database and leaves V1–V4 untouched.
2. Tenant isolation rejects a child row whose parent belongs to another
   tenant, including tax-to-concept references.
3. Valid legacy backfill succeeds; zero/multiple parent matches stop with a
   redacted conflict report and do not set `NOT NULL` prematurely.
4. The mapper ignores legacy `raw_payload` when populating normalized fields;
   a synthetic over-limit or unredacted diagnostic payload is rejected until
   the approved app/schema bound exists, and no raw payload appears in public
   output.
5. Reprocessing identical evidence produces no additional concept, tax,
   payment, payroll, or related-document rows.
6. Two concurrent workers cannot insert the same evidence/ordinal key; one
   succeeds and the other observes an idempotent no-op.
7. A changed evidence hash is retained as a separate generation or conflict;
   no row is overwritten or deleted.
8. Concept/tax/payment/payroll/related ordinal collisions and duplicate
   relation identities are classified deterministically.
9. Tax document-level rows accept a `NULL` concept ordinal under the partial
   unique index, concept-level rows require a positive ordinal, and collisions
   are rejected deterministically; the reserved-sentinel alternative has the
   same behavior if selected.
10. Payment exchange-rate rules accept valid non-default currency rates, reject
   non-positive rates, reject a rate for the default currency, and preserve
   missing related-document identity as incomplete.
11. Payroll amount columns remain nullable, preserve source values, and never
   calculate a net amount from missing inputs.
12. A claim is durable before a fake external effect; retries after a crash do
   not submit or download twice, and download timeout becomes `uncertain`.
13. SAT, storage, and queue calls occur outside DB transactions; queue
   references publish only after the outbox/event transaction commits.
14. Parser-worker restart retries safely; successful rerun leaves row counts,
   job counts, and artifact references unchanged.
15. Public status/report serialization passes a forbidden-data scanner and
   emits only the documented aggregate allowlist.
16. Ruff, the full test suite, sensitive/SAT scanners, `docker compose config`,
   and `git diff --check` pass with a clean tree.

Until these tests and the human gate pass, V5 remains a design proposal and no
schema or worker implementation should be presented as complete.
