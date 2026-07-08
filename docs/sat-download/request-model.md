# SAT download request model

Target contract:
SAT Descarga Masiva CFDI y CFDI de Retenciones v1.5, mayo 2025.

Allowed sources:
- V1_5_CONTRACT
- RUNTIME_WSDL
- COMMUNITY_ORACLE as implementation oracle only

Forbidden as operational contract:
- v1.2
- 2023 manuals
- legacy endpoints
- forums/blogs/snippets
- old prompts

A SAT request does not download XML immediately. It asks SAT to prepare CFDI or metadata packages from a valid set of filters.

## Decision

Treat metadata requests as the default control-plane request type for period coverage. XML requests should usually be planned from the metadata ledger, not fired blindly for every period.

## Request dimensions

| Dimension | Values | Notes |
|---|---|---|
| Document family | CFDI, retenciones | Use different endpoint sets. |
| Direction | Issued, received, folio | v1.5 splits request operations by direction/folio. |
| Content type | `CFDI`, `Metadata` | CFDI packages contain XML; metadata packages contain TXT summaries. |
| Date range | Start and end datetime | Required for period requests; validate v1.5 time rules before live execution. |
| UUID/folio | UUID | Used for folio-specific requests; period filters should not be mixed unless the operation explicitly supports it. |
| Document status | Active/vigente, cancelled/cancelado, all/todos | Received XML with cancelled documents requires explicit care. |
| Document type | Income, expense, transfer, payroll, payment | Maps to SAT comprobante types such as `I`, `E`, `T`, `N`, `P`. |
| Counterparty RFC | Bounded list when supported by the operation | Validate per direction and source policy before signing. |
| Complement | Optional complement filter | Keep as typed value object, not free-form strings everywhere. |

## Proposed domain objects

```text
DownloadQuery
  document_family: cfdi | retenciones
  direction: issued | received | folio
  request_type: cfdi | metadata
  period: DateTimePeriod | None
  uuid: Uuid | None
  requester_rfc: Rfc
  issuer_rfc: Rfc | None
  receiver_rfcs: list[Rfc]
  document_status: active | cancelled | all | None
  document_type: income | expense | transfer | payroll | payment | None
  complement: Complement | None
  rfc_on_behalf: Rfc | None
```

## Validation rules

| Rule | Reason |
|---|---|
| `requester_rfc` is always required. | SAT verifies who is requesting the download. |
| Period requests require `start` and `end`. | SAT prepares packages for a time interval. |
| `FechaInicial < FechaFinal`. | v1.5 period queries must not collapse into an exact instant. |
| Use at least a two-second range. | Prevents exact-instant queries that SAT does not model as a useful interval. |
| Lower bound is six years back without time. | Keep historical backfill inside documented v1.5 limits. |
| Folio requests require `uuid`. | UUID identifies the requested CFDI. |
| Do not combine folio and broad period filters by default. | The operation shape is different. |
| Sign attributes in deterministic order. | XMLDSig failures often come from canonicalization/order mismatches. |
| Prevalidate duplicate query criteria. | Repeated identical requests can hit SAT duplicate/quota errors. |

## v1.5 operation split

| Operation | Source level | Repository handling |
|---|---|---|
| `SolicitaDescargaEmitidos` | `V1_5_CONTRACT` + `RUNTIME_WSDL` | v1.5-only issued request builder. |
| `SolicitaDescargaRecibidos` | `V1_5_CONTRACT` + `RUNTIME_WSDL` | v1.5-only received request builder. |
| `SolicitaDescargaFolio` | `V1_5_CONTRACT` + `RUNTIME_WSDL` | v1.5-only folio request builder. |

## Metadata-first planning

| Step | Output |
|---|---|
| Submit metadata-by-period request. | A request id and later one or more metadata package ids. |
| Parse metadata package. | A canonical ledger of UUIDs, RFCs, dates, totals, status, and source package. |
| Compare ledger to XML evidence. | UUIDs classified as downloaded, pending, cancelled, retryable, or manual-review. |
| Submit XML requests only for needed windows. | Fewer duplicate requests and fewer wasted package downloads. |

The repository should export CSV or analytics views from its own ledger. Do not assume SAT will provide a ready-made CSV artifact; model TXT metadata packages as an input format.

## Query idempotency

Before submitting, compute a stable query hash from normalized criteria:

```text
sha256(
  document_family + direction + request_type + period + uuid + requester_rfc +
  issuer_rfc + sorted(receiver_rfcs) + status + type + complement + rfc_on_behalf +
  recovery_variant_reason
)
```

Use that hash to avoid accidental duplicate submissions and to resume pending jobs.

## Review checklist

- [ ] Every public request builder validates before signing.
- [ ] Validation errors are explainable without exposing secrets.
- [ ] The normalized query hash is stable across process restarts.
- [ ] v1.5-specific request builders have isolated tests.
- [ ] XML signature tests cover attribute order and namespace handling.
- [ ] Metadata requests can populate a ledger before XML retry planning runs.
