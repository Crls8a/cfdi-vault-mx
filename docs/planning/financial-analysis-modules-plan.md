# Financial and accounting analysis modules plan

Status: phased implementation. The pure monthly, normalization, accounting,
quality, report-composition, and in-memory XML projection contracts are
implemented and unit-tested;
database ingestion, normalized ledgers, private exports, and operator CLI
remain pending. This document does not enable SAT access, change the database
schema, or make a tax determination.

## Purpose and boundary

CFDI Vault MX should expose financial-operational analysis as separate modules,
not as logic embedded in the SAT downloader or parser. PostgreSQL remains the
durable source of truth; ZIP/TXT/XML evidence remains in the configured
external storage. The execution order is:

```text
real ZIP/TXT → PostgreSQL metadata ledger → real ZIP/XML → normalized CFDI
→ complements (taxes/payments) → reconciliation/quality → analysis/reporting
```

The reports are decision support for the operator and accountant. They are not
tax advice, a fiscal opinion, or an automatic calculation of obligations. A
qualified accountant must review classifications, cancellations, payments,
currency, and period cut-offs.

## Audit of the current repository

The following classification is based on the current code and tests. It is
deliberately narrower than claiming that the full financial product exists.

| Area | Current evidence | Classification |
|---|---|---|
| Metadata parsing | `metadata_parser.py` decodes UTF-8-SIG, detects delimiters, validates required fields, and returns accepted/rejected rows. | Implemented and unit-tested with synthetic inputs; no real SAT package proven. |
| Metadata ledger | `CfdiMetadataLedger` stores direction, date, status, effect, total, source reference, and reconciliation state. | Implemented as persistence; analytical query layer is missing. |
| XML evidence | Campaign artifacts are stored outside PostgreSQL and referenced by `XmlEvidence`; the worker parses bounded XML packages. | Implemented and tested synthetically; no real ZIP/XML evidence proven. |
| CFDI header normalization | `CfdiDocument` and the common parser store version, parties, dates, currency, subtotal, total, type, payment method/form, parser status, and raw JSON payload. | Implemented for common fields; version/complement coverage remains partial. |
| Concepts, taxes, payments, payroll | Tables exist in `recovery_db.py`; pure concept, tax, payment, and Nomina normalizers now extract bounded CFDI evidence in memory, while campaign XML ingestion still does not populate the dedicated ledgers. | Concept, tax, payment, and payroll contracts implemented and unit-tested; DB mapping, employer/employee amounts, payment-to-invoice reconciliation, and end-to-end normalization remain pending. |
| Reconciliation | `reconciliation.py` classifies metadata versus XML as pending, downloaded, cancelled, state-check, or retry/permanent outcomes. | Implemented decision rules and tests; quality dashboard is missing. |
| Quality snapshot contract | `analysis.quality.snapshot_quality()` classifies identifier-free observations into fixed redacted buckets using existing reconciliation states and parser status mappings. | Implemented as a pure, unit-tested contract; PostgreSQL/worker joins and quality reporting remain pending. |
| Existing summary | `VaultService.summary()` groups the legacy invoice model by month, issuer, and comprobante type; CLI `summary` prints counts, subtotal, and total. | Implemented for the legacy path; not yet the PostgreSQL recovery analytics contract. |
| Monthly contract slice | `analysis.monthly.analyze_monthly()` plus `analysis.postgres.MonthlyAnalysisPostgresAdapter` produce deterministic month/direction/currency aggregates from typed metadata/XML evidence records and tenant-scoped PostgreSQL rows. | Implemented and unit-tested for UTC date bounds, metadata/XML precedence, partial-header fallback, sanitized DTOs, bounded active/cancelled/unknown status counts, and month-over-month deltas. Effect/type dimensions remain deferred because the current typed input and PostgreSQL read model do not expose those fields; private reporting is pending. |
| Accounting summary slice | `analysis.accounting.summarize_taxes()`, `summarize_payments()`, and `summarize_payroll()` aggregate normalized tax/payment/payroll DTOs with source-status propagation and incomplete-data counts. | Implemented as pure, unit-tested contracts; they consume only in-memory normalized records and return aggregate DTOs. They do not read/write PostgreSQL, enqueue jobs, or contact SAT. Persistence mapping, tax period/currency/direction dimensions, payment reconciliation, payroll ledger mapping, and private reporting remain pending. |
| Worker handoff | `RecoveryService` consumes reference-only metadata/XML jobs and updates PostgreSQL. | Implemented and synthetic-worker tested; financial aggregates are not emitted by the worker. |
| In-memory accounting projection | `analysis.projection.project_accounting_xml()` dispatches one stored XML value to the four pure normalizers and returns typed records, parser statuses, counts, and opaque deterministic references. | Implemented and unit-tested only; process-local duplicate suppression is not durable idempotency and no DB/worker/queue integration exists yet. |
| Reporting/export | `analysis.reporting.FinancialAnalysisReport` composes monthly, tax, payment, and quality DTOs with UTC/period validation and aggregate-only JSON projection, including bounded monthly status counts and trend deltas. | Implemented as a pure, unit-tested contract; PostgreSQL queries, private exports, and CLI integration remain pending. |

### Important limitation

The presence of accounting tables is not evidence that accounting analysis is
available. Metadata can support date/status/effect/count/total trends, but it
cannot reliably provide tax breakdowns, payment application, cash collection,
cost classification, or period recognition. Those require normalized XML and,
for deferred or partial payments, the relevant payment complement documents.

Payroll is intentionally a narrow pure-normalization slice. It accepts the
declared CFDI/Nomina version pair and canonical Nomina namespace, then records
period dates, payroll type, direct total attributes, child counts, and an
incompleteness count. It does not retain employee CURP/number, employer data,
earnings or deduction detail, net-pay calculations, or legal/accounting
classification. The existing `CfdiPayroll` table has identifiers, dates, and
raw payload only; it has no durable amount/employer columns. Database mapping,
schema changes, and worker ingestion remain a human-gated follow-up.

## Module boundaries

### 1. Ingestion module (`analysis.ingestion`)

**Owns:** importing metadata ledger rows and stored XML references through the
existing worker boundary; validation of source, tenant, direction, period, and
idempotency keys.

**Does not own:** SAT transport, credentials, ZIP extraction policy, report
formatting, or tax interpretation.

Input contract:

- a durable artifact reference and validation result;
- a metadata batch or parsed CFDI document;
- tenant, direction, source package reference, parser version, and evidence hash.

Output contract:

- idempotent ledger/document writes;
- accepted, duplicate, rejected, and partial counts;
- a queue/audit event containing references and aggregates only.

### 2. Normalization module (`analysis.normalization`)

**Owns:** mapping version-aware parser output into `CfdiDocument`,
`CfdiConcept`, `CfdiRelatedDocument`, and complement-specific records.

**Does not own:** deciding whether a document is legally deductible, paid, or
taxable.

The normalizer must preserve unknown fields in bounded JSONB payloads, mark the
parser as `complete` or `partial`, and never discard evidence when a complement
is unknown. A reprocess must read stored XML rather than call SAT again.

### 3. Monthly analysis module (`analysis.monthly`)

**Owns:** deterministic period aggregates over normalized records and metadata
fallbacks. It should support calendar month first, then explicit date ranges.

Minimum metrics:

- document count and subtotal/total by month, direction, effect, type, currency,
  and status;
- month-over-month count and total deltas;
- active/cancelled/unknown counts;
- metadata-only versus XML-backed coverage;
- top parties/categories only in private operator views.

The current pure contract exposes month-over-month deltas only when the
immediately preceding calendar month has an aggregate for the same
direction/currency key. Missing prior evidence is represented by `null` deltas,
not a synthetic zero. Effect/type dimensions remain deferred until the typed
read model provides bounded fields; the module does not infer them from status,
direction, or free-form payloads.

The output is a typed aggregate DTO. Public/status output contains counts and
totals only; identifiers and row-level details require an explicit private
export path.

### 4. Taxes, payments, and complements (`analysis.accounting`)

**Owns:** dedicated normalization and aggregate queries for:

- transferred and withheld taxes by tax, rate, currency, period, and direction;
- payment method/form and payment complement dates/amounts;
- invoice-to-payment application and unapplied balances;
- credit notes, related documents, and payroll complements when supported.

**Does not own:** legal tax advice, bank reconciliation, or assumptions about
cash basis/accrual basis. Every metric must state its source and completeness.

### 5. Reconciliation and data quality (`analysis.quality`)

**Owns:** a repeatable quality snapshot joining metadata, XML evidence,
normalized documents, and package/job history.

Required buckets:

- metadata without XML;
- XML without matching metadata;
- duplicate or conflicting XML hashes;
- cancelled metadata with unexpected XML;
- partial/unsupported parser results;
- missing payment complement where a payment workflow expects one;
- currency, total, date, or status conflicts;
- failed, expired, uncertain, and manual-review recovery states.

Each finding has a stable category, count, period, and next action. It must not
print fiscal rows or raw XML.

### 6. Reporting module (`analysis.reporting`)

**Owns:** versioned report DTOs and private export adapters (CSV/JSON first;
HTML/PDF later). It consumes the other modules and never queries SAT.

Report families:

1. monthly financial trend;
2. tax and payment summary;
3. metadata/XML coverage;
4. reconciliation and quality exceptions;
5. provenance: source package, parser version, evidence status, and generated
   time without exposing secrets or raw identifiers by default.

CLI integration belongs after these contracts stabilize. The current `summary`
command remains a compatibility surface until a recovery-DB report replaces it.

## Phased development plan

### Phase 0 — Contract and evidence baseline

Document the DTOs, source precedence, period/time-zone policy, privacy levels,
and completeness flags. Confirm that no report runs over data that has not been
persisted and reconciled. **Measure:** one synthetic fixture matrix and a
redaction test for every report family.

### Phase 1 — Ingestion and normalized header coverage

Connect the worker's existing metadata/XML writes to analysis read models (no
new SAT call). Add idempotent queries for document headers, direction, status,
effect, currency, dates, totals, and evidence coverage. **Measure:** reprocessing
the same artifact changes no counts; accepted/duplicate/partial counts agree
with the ledger; PostgreSQL remains the only durable store.

### Phase 2 — Monthly analysis

Implement calendar-month and explicit-range aggregates with metadata-only and
XML-backed coverage labels. Add month-over-month deltas and currency-separated
totals. **Measure:** synthetic expected sums match to cent precision, empty
periods are explicit, and mixed currencies are never silently added.

### Phase 3 — Accounting normalization

Implement concept rows first, then tax rows, payment complements, related
documents, and payroll as independent parser/normalizer slices. Unknown
complements remain `partial` and are not inferred. **Measure:** each slice has
valid, malformed, duplicate, unknown-version, and reprocess tests; normalized
rows retain evidence provenance.
The pure payroll slice is now implemented; its amount coverage is limited to
direct Nomina totals and child counts until a separate schema/worker mapping is
approved. `analysis.payroll_accounting.summarize_payroll()` groups those
records by UTC payment month and `TipoNomina` (`O`/`E`) and preserves missing
values as incomplete rather than zero. This function is deliberately pure: it
has no database session, storage reference, queue message, worker side effect,
or SAT transport boundary. A future persistence mapper must use the normalized
`PayrollRecord` values and durable idempotency keys; it must not move database
or worker behavior into this aggregate module.

The pending tenant-safe schema, evidence references, idempotency keys, payroll
amount fields, payment exchange-rate/related-document identity, and worker
transaction boundary are specified (without implementation) in
[`accounting-ledger-v5-design.md`](accounting-ledger-v5-design.md). The design
requires human approval before any Flyway migration or durable mapper work.

The pure projection slice is now implemented in
`analysis.projection.project_accounting_xml()`. It accepts one already-stored
XML byte sequence, rejects non-UTF-8/`DOCTYPE`/`ENTITY` input, invokes the
concept/tax/payment/payroll normalizers, and returns typed records plus parser
statuses, record counts, aggregate completeness, and deterministic opaque
source/idempotency references. `AccountingProjectionDispatcher` suppresses a
duplicate only in process memory for offline tests; it does not write a row,
publish a job, or replace the durable worker idempotency claim. The projection
`as_dict()` and `repr()` expose aggregates only; hash-derived source and
idempotency references remain typed in memory for a future private worker
handoff. XML rows, UUID/RFC values, paths, and raw XML remain private to the
typed records and are not serialized. Connecting this projection to PostgreSQL
or RabbitMQ is a separate ingestion phase and requires the existing
schema/worker review gate.

### Phase 4 — Reconciliation and quality snapshots

Join metadata ledger, XML evidence, normalized records, SAT/job states, and
payment expectations. **Measure:** every finding maps to one documented state,
has an aggregate count, and can be resolved/recomputed idempotently.

### Phase 5 — Private reports and exports

Expose report DTOs and private CSV/JSON exports with date, direction, status,
currency, and completeness filters. The first pure composition DTO is now
available through `analysis.reporting`; database query wiring and export
adapters remain pending. Add operator-facing aggregate status only after
redaction tests. **Measure:** no default output contains RFC, UUID, raw XML,
package bytes, storage paths, credentials, or SOAP.

### Phase 6 — Live evidence and promotion

Only after a real Metadata ZIP/TXT and then a real CFDI ZIP/XML are processed by
the worker may the live evidence be used to validate these modules. The real
artifacts stay outside Git and reports remain aggregate. **Measure:** one
sanitized provenance record, one reproducible import, and no duplicate package
or job. A real result does not promote the library to tax-product status.

## Acceptance and safety gates

- PostgreSQL/Flyway is the only durable analysis store; Redis is transient and
  RabbitMQ carries references, never XML/ZIP/rows.
- Metadata, XML, complement, and report tests use synthetic fixtures only until
  the separate human-gated SAT run.
- Tests cover idempotency, tenant isolation, date boundaries, time zones,
  currencies, cancellations, unknown/partial parser status, duplicate hashes,
  and redaction.
- Ruff, full suite, sensitive/SAT scanners, `docker compose config`, and
  `git diff --check` are required before integration.
- Reports expose provenance and completeness so a missing XML or payment
  complement cannot look like a zero amount.
- Storage references and hashes are evidence metadata; raw artifacts never go
  into PostgreSQL JSON reports or Git.
- No module determines tax liability, deductions, VAT payable, or compliance
  status without accountant review.

## Open findings to register

1. The recovery schema already has concept/tax/payment/payroll tables, but the
   campaign worker does not yet populate them from XML.
2. The legacy `VaultService.summary()` is not the recovery-DB financial report
   contract and should not be extended into a second persistence model.
3. The first real ZIP/TXT and ZIP/XML evidence is still missing; all current
   analysis claims are synthetic or structural.
4. A report privacy policy must distinguish private operator exports from safe
   status/health aggregates before adding CLI commands.

## Source documents and ownership

- Data model: `docs/foundation/data-and-accounting-model.md`.
- Reconciliation contract: `docs/sat-download/reconciliation-architecture.md`.
- Storage/evidence: `docs/foundation/storage-and-retention.md` and
  `docs/foundation/recovery-pipeline.md`.
- Parser contract: `src/cfdi_vault/parser.py`, `src/cfdi_vault/cfdi_parser.py`,
  and `src/cfdi_vault/metadata_parser.py`.
- Persistence/worker: `src/cfdi_vault/recovery_db.py` and
  `src/cfdi_vault/recovery_service.py`.
- Current compatibility summary: `src/cfdi_vault/service.py` and
  `src/cfdi_vault/adapters/cli/operations.py`.
