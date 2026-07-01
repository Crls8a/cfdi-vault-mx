# Idempotent local storage

STOR-001 implements the first local evidence layout for SAT recovery artifacts. Metadata CSV/TXT is the primary index; ZIP packages and extracted XML are stored only after hashing, and database rows point back to those files for audit.

## Quick path

1. Resolve the storage root from `--storage`, `CFDI_STORAGE_ROOT`, or the local fallback `storage/`; profile config wiring is planned after this storage contract.
2. Store evidence under the requester RFC and period partition.
3. Compute SHA-256 before registering package, metadata, or XML evidence.
4. Use the metadata ledger to decide which UUIDs still need XML.

## Folder layout

```text
<storageRoot>/
  <RFC>/
    metadata/
      YYYY/
        MM/
          <idSolicitud>-<sha12>.csv
    packages/
      YYYY/
        MM/
          <idPaquete>-<sha12>.zip
    xml/
      YYYY/
        MM/
          <uuid>-<sha12>.xml
    logs/
    db/
    exports/
```

`storage/` is runtime output and must not be committed. Versioned examples remain dummy-only and live outside this tree.

## Durable model

| Model | Purpose | Minimum traceability fields |
|---|---|---|
| `download_jobs` | Deduplicates exact user/scheduler intent. | tenant, RFC, direction, request type, criteria hash, status, timestamps. |
| `sat_requests` | Records SAT request lifecycle. | `id_solicitud`, criteria hash, SAT state/code/message, metadata SHA-256, metadata storage path, timestamps. |
| `sat_packages` | Records package download lifecycle. | `id_paquete`, `id_solicitud`, status, attempts, ZIP SHA-256, size, storage path, timestamps. |
| `cfdi_metadata_ledger` | Metadata-first UUID inventory. | UUID, issuer/receiver RFC, issue date, document status/type, source package, metadata SHA-256, reconciliation state, first/last seen. |
| `cfdi_documents` | Searchable normalized document header. | UUID, issuer/receiver RFC, issue date, document status/type, XML SHA-256, internal download state, timestamps. |
| `xml_evidence` | Stored XML proof. | UUID, package id, XML SHA-256, size, storage path, parser status, created timestamp. |
| `queue_job_events` / `reconciliation_events` | Pipeline audit trail. | queue/stage, status transition, actor, reason, correlation data, timestamp. |

## Idempotency rules

| Rule | Implementation |
|---|---|
| Do not repeat the same SAT request unnecessarily. | `DownloadQuery.criteria_hash()` is unique per tenant in `download_jobs`. Replays return the original job result. |
| Do not redownload a package already stored. | `sat_packages` is checked by `id_paquete`; a downloaded package with an existing local path is reused. |
| Do not overwrite evidence. | Local filenames include SHA-256 prefixes; idempotent writes reuse identical files and reject different bytes at the same key. |
| Do not reinsert an existing UUID blindly. | `cfdi_metadata_ledger` is unique by tenant, UUID, and direction; `cfdi_documents` is unique by tenant and UUID. Existing rows are updated for status/evidence changes. |

## Metadata-first behavior

Metadata TXT/CSV acts as the primary index because it tells the system which UUIDs should exist before broad XML retry work starts. The local CSV mirrors SAT metadata concepts with stable columns:

| Column | Meaning |
|---|---|
| `idSolicitud` | SAT request id that produced the metadata inventory. |
| `idPaquete` | Package id associated with the metadata row when available. |
| `uuid` | CFDI UUID to reconcile. |
| `rfcEmisor` / `rfcReceptor` | Issuer and receiver RFC values. |
| `fechaEmision` | Document issue timestamp. |
| `estadoComprobante` | SAT metadata document status. |
| `tipoComprobante` | CFDI effect/type. |

## XML download decision

Download or attach XML when:

- the UUID is new in metadata;
- the UUID exists but has no XML evidence;
- metadata shows a status change that needs local evidence or a state check;
- the UUID is in a retryable pending state.

Do not retry automatically when:

- cancellation is confirmed and no XML is expected;
- the package/request is expired;
- package download attempts are exhausted;
- SAT returned a permanent error for the request or package.

## CFDI pipeline states

The first model uses these internal states:

```text
DISCOVERED_IN_METADATA
XML_PENDING
XML_REQUESTED
XML_DOWNLOADED
XML_NOT_AVAILABLE
CANCELLED_METADATA
CANCELLED_CONFIRMED
STATE_CHECK_PENDING
STATE_CHECKED
RETRY_SCHEDULED
FAILED_PERMANENT
```

Current fake-SAT code actively writes `XML_PENDING`, `XML_DOWNLOADED`, and `CANCELLED_METADATA`. The remaining states are reserved for retry, state-check, and terminal SAT-error slices.

## Safety checklist

- [ ] No real CFDI XML, metadata, or SAT ZIP is committed.
- [ ] No `.cer`, `.key`, `.pfx`, `.pem`, `.p12`, password, token, or private-key material is committed.
- [ ] Runtime `storage/` and `logs/` stay ignored.
- [ ] `python scripts/scan_sensitive_fixtures.py` passes.
- [ ] Focused storage/recovery tests pass before review.
