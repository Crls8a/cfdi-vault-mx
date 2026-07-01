# Statuses, limits, and errors

The SAT workflow is asynchronous and quota-sensitive. Correct error handling is part of the core library, not an afterthought.

For user-facing message wording and edge-case examples, see [User-facing errors and edge cases](user-facing-errors.md).

## Request states

| State | Meaning | Repository behavior |
|---:|---|---|
| 1 | Accepted | Persist and poll later. |
| 2 | In process | Continue polling with backoff. |
| 3 | Finished | Persist package identifiers and start download. |
| 4 | Error | Mark terminal failure with SAT code and message. |
| 5 | Rejected | Mark terminal failure; surface validation details. |
| 6 | Expired | Mark terminal failure; package/request window is gone. |

## Limits to model explicitly

| Limit | Value from current public/verified sources | Library behavior |
|---|---:|---|
| Portal XML recovery | Up to 2,000 XML per day | Mention in docs; not a Web Service client limit. |
| Portal metadata | Up to 1,000,000 metadata records | Mention in docs; not a Web Service client limit. |
| Web Service CFDI records | Up to 200,000 records per request | Split large periods proactively. |
| Web Service metadata | Up to 1,000,000 metadata records | Keep streaming parsers for large TXT packages. |
| Package availability | 72 hours / 3 days | Download soon after finished verification. |
| Package downloads | 2 downloads per package | Persist raw package before parsing to avoid wasting attempts. |
| Receiver RFCs | Up to 5 in official request docs | Validate before signing. |

## Common codes

| Code | Area | Meaning | Handling |
|---:|---|---|---|
| 300 | Request/download | Invalid user | Stop; check certificate/requester identity. |
| 301 | Request/download | Malformed XML | Stop; inspect XML building, canonicalization, and attribute order. |
| 302 | Request/download | Malformed seal/signature | Stop; inspect XMLDSig generation. |
| 303 | Request/download | Signature does not match requester RFC | Stop; validate certificate RFC and query RFC. |
| 304 | Request/download | Revoked or expired certificate | Stop; require valid e.firma. |
| 305 | Request/download | Invalid certificate | Stop; validate certificate type and encoding. |
| 5000 | All | Accepted/success | Continue workflow. |
| 5001 | Request | Third party not authorized | Stop; requester is not authorized for the requested RFC data. |
| 5002 | Request/verification | Quota/lifetime duplicate condition | Do not blindly retry; check query hash and existing active requests. |
| 5003 | Verification | Maximum threshold reached | Split query or switch to metadata depending on use case. |
| 5004 | Verification/download | No information found | Mark as completed-empty or package-not-found depending on stage. |
| 5005 | Request | Duplicate request | Resume existing request if known; otherwise wait before retrying. |
| 5007 | Download | Package does not exist/expired | Mark expired; create a new request if still needed. |
| 5008 | Download | Maximum downloads reached | Stop; raw package should already be stored locally. |
| 5011 | Verification | Daily folio download limit reached | Stop or schedule for a later day. |
| 404 | Download | Generic/uncontrolled error | Retry once with jitter, then record incident. |

## State-aware retry matrix

| Condition | Retry? | Action |
|---|---|---|
| `EstadoSolicitud = 1` or `2` | Yes | Poll with exponential backoff and jitter. |
| `EstadoSolicitud = 3` | Continue workflow | Download all package ids immediately and persist bytes before parsing. |
| `EstadoSolicitud = 4` or `5` | No automatic retry | Open an operator incident; inspect filters, authorization, and signature. |
| `EstadoSolicitud = 6` | Conditional | Recreate from the metadata ledger if documents are still needed. |
| Download `5007` | Conditional | Package expired or unavailable; recreate request only if ledger says evidence is still missing. |
| Download `5008` | No blind retry | Do not redownload the same package; recreate a new request only with a business reason. |
| Verification `5003` | No | Split the time window or narrow filters. |
| Verification `5011` | Delayed | Mark quota-limited and defer to the next allowed cycle. |

## Polling policy

Start conservative. SAT processing can take time, and aggressive polling does not make packages appear faster.

```text
initial delay: 60 seconds
multiplier: 1.5 to 2.0
jitter: required
max delay: 15 minutes
max wall time: configurable, default below package expiry window
```

## Terminal-state policy

| Terminal condition | Persisted state |
|---|---|
| Rejected request | `request.status = rejected`, include SAT code/message. |
| Error state | `request.status = failed`, include raw response fingerprint. |
| Expired request/package | `status = expired`, do not retry same package. |
| Download exhausted | `package.status = exhausted`, require new request if package was not stored. |
| Empty result | `request.status = completed_empty`, keep query hash for audit. |

## Reconciliation-aware retry rule

Retries must answer three questions before creating a new SAT request:

1. Does the metadata ledger still say XML evidence is expected?
2. Did a previous package already contain the XML or fail for a terminal reason?
3. Would the new request duplicate an active or completed criteria hash?

If the answer is unclear, move the UUID or period to `manual_review` instead of creating another SAT request.

## Review checklist

- [ ] No code path retries terminal errors indefinitely.
- [ ] Duplicate request handling checks local persisted state first.
- [ ] Package download stores raw bytes before parsing.
- [ ] Polling uses jitter.
- [ ] Every SAT code is preserved in logs or persisted audit fields.
- [ ] Retry decisions read from the metadata ledger and package history.
