# XML storage and retention design

XML and package storage is part of the product, not an implementation detail. Users must know where evidence lives on their machine, how it grows, and how to extract it without reverse-engineering the database.

## Decision

CFDI Vault MX stores raw SAT packages and extracted XML under a configurable storage root:

- CLI option: `--storage <path>`
- environment variable: `CFDI_STORAGE_ROOT`
- Docker default inside container: `/app/storage`
- Docker Compose host path: `./storage`
- local fallback: `storage/`

PostgreSQL stores searchable accounting data and storage references. The filesystem stores raw evidence.

Storage is not a separate user workflow. It is a mandatory stage of the recovery pipeline: every downloaded package and extracted XML must be registered before normalized data is considered loaded.

## Optional MinIO lab

Docker Compose includes an optional MinIO profile so the team can practice S3-compatible object keys before choosing a production object-storage provider.

```bash
docker compose --profile object-storage up -d minio minio-create-bucket
```

| Setting | Default |
|---|---|
| API endpoint | `http://localhost:9000` |
| Console endpoint | `http://localhost:9001` |
| Bucket | `cfdi-vault-evidence` |
| Container data volume | `minio_data` |

MinIO is a reference-system lab service only. The default app and worker still
use `CFDI_STORAGE_ROOT` and the host-mounted `./storage` directory. The optional
S3-compatible adapter implements the same storage port for MinIO labs when the
caller explicitly injects a compatible object client or installs the
`object-storage` extra; it is not required by the default app, worker, or
library import path.

## User-visible location

| Mode | User sees XML under |
|---|---|
| Local CLI default | `<repo>/storage/<RFC>/xml/YYYY/MM/...` |
| Local CLI custom | `<--storage>/<RFC>/xml/YYYY/MM/...` |
| Docker Compose | `<repo>/storage/<RFC>/xml/YYYY/MM/...` on the host, mounted to `/app/storage/<RFC>/xml/YYYY/MM/...` in the container |
| Docker Compose MinIO lab | Opaque objects under bucket `cfdi-vault-evidence`; not used by app/worker yet |
| Future packaged installer | User-selected data directory, shown by `doctor` and setup summary |

The `doctor` command must always show the resolved storage root and key subfolders.

## Target folder layout

STOR-001 implements the RFC/period partitioned layout. A profile-specific storage root may already represent one tenant, so the first stable partition is the requester RFC.

```text
<storageRoot>/
  <RFC>/
    metadata/YYYY/MM/<id_solicitud>-<sha12>.csv
    packages/YYYY/MM/<id_paquete>-<sha12>.zip
    xml/YYYY/MM/<uuid>-<sha12>.xml
    logs/
    exports/
```

Metadata, package, and XML filenames include a SHA-256 prefix so replaying the same work is safe and byte changes cannot silently overwrite evidence.

## Storage growth model

| Data | Growth driver | Growth control |
|---|---|---|
| Raw ZIP packages | Every SAT package downloaded. | Deduplicate by `id_paquete` and SHA-256; partition by period. |
| Extracted XML | Every recovered UUID. | Deduplicate by `(tenant_id, uuid, xml_sha256)`. |
| Exports | User-generated CSV/PDF/HTML. | Safe to prune; can be regenerated. |
| Logs | Worker/CLI operations. | Rotate by size/date. |
| Database rows | Jobs, events, ledger, documents. | Retention policy for queue events; never delete evidence without explicit command. |

## Evidence rules

- Store raw package before extraction.
- Store XML bytes before parsing.
- Compute SHA-256 for package and XML.
- Keep a database pointer from `sat_packages.storage_key` and `xml_evidence.storage_key`.
- Treat package/XML storage registration as part of the same recovery job that loads database records.
- Queue stored XML references for ingestion after evidence is registered; do not make the downloader perform one direct bulk database load.
- Unknown parser/complement support must not delete or rewrite evidence.
- Reprocessing should read stored XML, not ask SAT again when evidence already exists.

## Storage port and object-key contract

STOR-004A defines the adapter-neutral boundary in
`cfdi_vault.storage_contract` and `cfdi_vault.ports.StoragePort`:

- `StorageKey` is a relative, canonical POSIX object key. It rejects absolute
  paths, drive prefixes, backslashes, empty segments, and `.`/`..` traversal.
- Metadata, package, and XML key factories normalize identifier segments,
  validate a complete SHA-256 digest, and include its first 12 characters.
- `EvidenceReference` contains only `storage_key`, `sha256`, and `size_bytes`.
  It never contains evidence bytes, secrets, or an adapter-specific local path.
- `StoragePort` provides idempotent write, read, and stat operations.
  `LocalStorage` is the active adapter and preserves the existing filesystem
  layout and collision protection.
- Typed storage failures retain the relative key in structured `.key` data,
  while their messages expose only operation/category; RFCs, evidence IDs,
  adapter roots, and absolute paths stay private.
- Object keys remain case-sensitive, while `LocalStorage` rejects aliases that
  differ only by case so Windows and future object-storage behavior cannot
  produce two references for one local file.
- The optional S3-compatible adapter preserves the public `StorageKey` and
  `EvidenceReference` contract for callers, but maps each `StorageKey` to a
  deterministic opaque object key such as `evidence/<sha256(storage_key)>`
  before calling S3/MinIO. The object store receives only the opaque key plus
  SHA-256 and size metadata; it must not receive RFCs, SAT request/package IDs,
  UUIDs, fiscal names, or the original storage key in object keys or metadata.

The configured storage root/profile is the tenant boundary for filesystem
storage. PostgreSQL remains responsible for binding stable evidence references
to `tenant_id`, jobs, packages, and documents; object storage is only a byte
store addressed by opaque physical keys.
Existing recovery fields that expose filesystem paths remain compatibility
surfaces until their DB/application migration is delivered with the evidence
index work; new queue/API contracts must use object keys instead.

STOR-004B implements the optional S3-compatible adapter for explicit MinIO/S3
labs. It is not wired into the default `app` or `worker`; they continue to use
`CFDI_STORAGE_ROOT=/app/storage`, and no MinIO variables belong in their
runtime configuration until a separate runtime wiring change is accepted.

## Extraction and discovery UX

`storage status` and `storage locate` inspect one canonical relative storage
reference through the filesystem adapter. They do not query PostgreSQL, MinIO,
or any network service. Output is redacted by construction: the raw reference,
RFC/UUID/package segments, configured root, and physical path are never shown.

```bash
cfdi-vault storage status <relative-storage-reference>
cfdi-vault storage locate <relative-storage-reference>
cfdi-vault storage status <relative-storage-reference> --storage <path>
```

Observation is strictly read-only. The commands do not create a missing
storage root, repair its directory layout, or write evidence; an absent root is
reported as not found.

Successful status output is scriptable and exposes only safe metadata:

```text
status=exists
reference=ref-<fingerprint>
category=xml
size_bytes=<bytes>
sha256=<12-character-prefix>
```

`storage locate` returns a logical location such as
`filesystem://xml/ref-<fingerprint>`, never an absolute filesystem path. A
missing reference reports `status=not_found` or `location=unavailable` and exits
with status 1. Invalid references and adapter failures use stable error codes
without echoing the input or low-level exception.

## Manifest contract

JSON Lines manifests let users extract information without querying PostgreSQL directly.

`xml.jsonl` row shape:

```json
{"tenant_id":"acme","rfc":"<RFC>","uuid":"...","issue_date":"2024-01-15","xml_sha256":"...","storage_key":"<RFC>/xml/2024/01/...xml","source_package_id":"...","parser_status":"complete"}
```

Manifests are secondary indexes. PostgreSQL remains the source of truth.

## Retention policy

| Category | Default policy |
|---|---|
| XML evidence | Keep indefinitely unless user explicitly purges. |
| Raw SAT packages | Keep indefinitely for audit in v1; later allow archive/compress. |
| Exports | User-managed; safe to delete. |
| Logs | Rotate/delete after configured days. |
| Queue events | Keep enough history for audit, then archive by policy. |

## Open implementation tasks

- Add manifests for packages/XML.
- Add storage usage summary to `doctor`.
- Keep custom `--storage` observation covered by read-only CLI regression tests.
- Add safe export/copy command for XML evidence.
- Implement the storage-port MinIO adapter and prove filesystem/object-storage parity.
