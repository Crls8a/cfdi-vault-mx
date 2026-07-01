# SAT download request model

A SAT request does not download XML immediately. It asks SAT to prepare CFDI or metadata packages from a valid set of filters.

## Decision

Treat metadata requests as the default control-plane request type for period coverage. XML requests should usually be planned from the metadata ledger, not fired blindly for every period.

## Request dimensions

| Dimension | Values | Notes |
|---|---|---|
| Document family | CFDI, retenciones | Use different endpoint sets. |
| Direction | Issued, received, folio | Classic official docs describe a generic request; observed v1.5 behavior splits request operations. |
| Content type | `CFDI`, `Metadata` | CFDI packages contain XML; metadata packages contain TXT summaries. |
| Date range | Start and end datetime | Required for period requests. |
| UUID/folio | UUID | Used for folio-specific requests; period filters should not be mixed unless the operation explicitly supports it. |
| Document status | Active/vigente, cancelled/cancelado, all/todos | Behavior differs by direction and service version. |
| Document type | Income, expense, transfer, payroll, payment | Maps to SAT comprobante types such as `I`, `E`, `T`, `N`, `P`. |
| Counterparty RFC | Up to 5 receivers in some official request docs | Model as a bounded list, but validate per direction. |
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
| Folio requests require `uuid`. | UUID identifies the requested CFDI. |
| Do not combine folio and broad period filters by default. | Official classic docs treat UUID and period query shapes differently. |
| Limit receiver RFC collection to 5. | Official request docs document that upper bound. |
| Sign attributes in deterministic order. | XMLDSig failures often come from canonicalization/order mismatches. |
| Prevalidate duplicate query criteria. | Repeated identical requests can hit SAT duplicate/quota errors. |

## Official vs observed operation split

| Operation shape | Source level | Repository handling |
|---|---|---|
| `SolicitaDescarga` | Official classic request documentation. | Keep a request builder for the official baseline. |
| `SolicitaDescargaEmitidos` | Observed/community v1.5 behavior. | Implement in a versioned compatibility builder. |
| `SolicitaDescargaRecibidos` | Observed/community v1.5 behavior. | Implement in a versioned compatibility builder. |
| `SolicitaDescargaFolio` | Observed/community v1.5 behavior. | Implement in a versioned compatibility builder. |

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
- [ ] Version-specific request builders have isolated tests.
- [ ] XML signature tests cover attribute order and namespace handling.
- [ ] Metadata requests can populate a ledger before XML retry planning runs.
