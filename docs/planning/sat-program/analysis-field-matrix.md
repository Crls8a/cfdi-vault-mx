# ANALYSIS-DB-FIELDS-001 — Field-availability matrix

This matrix is the gate before implementing PostgreSQL analysis reads. It
records what the current V5 writer can actually persist, what the source DTOs
contain, and what a report may safely claim. It does not authorize SAT contact
or a schema change.

## Decision

**Decision: `partial_read_model_required`.**

The next read unit may proceed without a migration only if every unavailable
field remains explicit in `AccountingReadResult` and the report stays
`partial`. The current V5 mapper must be enriched for fields that already
exist in the V1 tables before those fields can be reported as complete. A
payroll payment month cannot be reconstructed: V1/V5 have period boundaries,
but no durable `payment_date`/`FechaPago`. The system must not substitute the
period end, period start, or document issue date. A future additive migration
or an explicitly accepted partial payroll report is a separate decision.

## Matrix

| Domain | Required analytical field | Current durable source | Current V5 write status | Safe report behavior |
|---|---|---|---|---|
| Monthly | issue date/month | `cfdi_documents.issue_date` | Available through parent | Group by UTC issue date only. |
| Monthly | direction | `cfdi_metadata_ledger.direction` | Available when metadata exists | Preserve `received`/`issued`; XML-only direction is unknown. |
| Monthly | currency | `cfdi_documents.currency` and payment currency | Parent available; payment currency is nullable | Keep currencies separate; unknown remains unknown. |
| Monthly | status/effect | metadata/header projections | Available in existing adapters | Publish categories, never legal conclusions. |
| Tax | tax type and amount | `cfdi_taxes.tax_type`, `amount` | V5 mapper writes both | Aggregate these values with provenance state. |
| Tax | tax code | legacy `cfdi_taxes.tax` | V5 mapper omits it | Mark unavailable; do not infer from tax type. |
| Tax | factor | legacy `factor_type` | V5 mapper omits it | Mark unavailable; do not infer a factor. |
| Tax | base and rate/quota | legacy `base`, `rate_or_quota` | V5 mapper omits them | Mark unavailable; keep tax totals partial. |
| Payment | amount/currency/exchange rate | V5 payment columns | Amount/currency/exchange rate are persisted | Report money only with explicit completeness and currency separation. |
| Payment | payment date/form | legacy `payment_date`, `payment_form` | V5 mapper omits them | Do not group by payment month/form; return unavailable fields. |
| Payment | related-document evidence | `cfdi_related_documents` legacy shape | Current intent stores only a count; mapper intentionally omits identity | Report count as incomplete/unknown; never invent related rows. |
| Payroll | payroll type | legacy `payroll_type` | V5 mapper omits it | Use `UNKNOWN`/partial until the write surface preserves it. |
| Payroll | period start/end | legacy `payment_start_date`, `payment_end_date` | V5 mapper omits them | Preserve as unavailable until mapped; never use as payment date. |
| Payroll | payment date | no V1/V5 column | Not available | Payroll monthly analysis remains partial; no date substitution. |
| Payroll | perceptions/deductions/other payments | V5 payroll columns | Persisted by mapper | Aggregate only with parser/completeness state. |
| Payroll | source net/currency/period type | V5 nullable columns | Mapper writes `NULL` | Keep `money_available=false` and expose unavailable fields. |
| Quality | metadata/XML/parser/reconciliation categories | existing quality statements and V5 provenance | Partially available; child bridge is pending | Publish fixed categories and completeness only. |

## Read-path invariants

1. Every child read is tenant-scoped and joins the parent document and source
   evidence by the composite V5 identity; numeric IDs alone are insufficient.
2. Date filters use the parent issue date unless the source field itself is
   durably present. A missing payment date is not replaced by another date.
3. `NULL`, omitted, and unsupported values remain explicit; they never become
   zero, `UNKNOWN` without a reason, or a fabricated dimension.
4. Aggregates may expose counts, amounts, currency, parser status, and
   unavailable-field categories only. They never expose rows, UUIDs, RFCs,
   SOAP, raw payloads, or storage keys.
5. A reprocessed ledger row must remain idempotent and evidence-bound; the
   analysis adapter is read-only and must not repair writes implicitly.

## Follow-up boundary

`ANALYSIS-DB-READ-001` can implement tenant-safe reads for the persisted V5
fields and explicit partial DTOs. It must not claim complete tax dimensions,
payment-month grouping, or payroll-month grouping until a separate mapper/
schema work unit preserves those fields. That work unit requires fresh review
and, for a new column, the normal migration/issue gate.

## Evidence

- Scope: synthetic code/schema inspection only.
- No SAT request, credential, artifact, or fiscal data was used.
- Acceptance requires a fresh review, sensitive-fixture scan, SAT-context scan,
  and `git diff --check` recorded in `daily-evidence.md`.
