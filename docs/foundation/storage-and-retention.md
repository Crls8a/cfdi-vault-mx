# XML storage and retention design

XML and package storage is part of the product, not an implementation detail. Users must know where evidence lives on their machine, how it grows, and how to extract it without reverse-engineering the database.

## Decision

CFDI Vault MX stores raw SAT packages and extracted XML under a configurable storage root:

- CLI option: `--storage <path>`
- environment variable: `CFDI_STORAGE_ROOT`
- Docker default inside container: `/app/storage`
- Docker Compose host path: `./storage`
- local fallback: `storage/`

The database stores searchable accounting data and storage references. The filesystem stores raw evidence.

Storage is not a separate user workflow. It is a mandatory stage of the recovery pipeline: every downloaded package and extracted XML must be registered before normalized data is considered loaded.

## User-visible location

| Mode | User sees XML under |
|---|---|
| Local CLI default | `<repo>/storage/<RFC>/xml/YYYY/MM/...` |
| Local CLI custom | `<--storage>/<RFC>/xml/YYYY/MM/...` |
| Docker Compose | `<repo>/storage/<RFC>/xml/YYYY/MM/...` on the host, mounted to `/app/storage/<RFC>/xml/YYYY/MM/...` in the container |
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
    db/
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
- Unknown parser/complement support must not delete or rewrite evidence.
- Reprocessing should read stored XML, not ask SAT again when evidence already exists.

## Extraction and discovery UX

Future CLI commands should make storage discoverable:

```bash
cfdi-vault storage status
cfdi-vault storage locate <UUID>
cfdi-vault storage open <UUID>
cfdi-vault storage manifest --tenant-id acme --format jsonl
cfdi-vault export xml --tenant-id acme --start 2024-01-01 --end 2024-01-31 --output ./out/xml
```

Expected `storage locate` output:

```text
UUID: <UUID>
XML: storage/<RFC>/xml/2024/01/<UUID>-<sha12>.xml
SHA-256: ...
Source package: storage/<RFC>/packages/2024/01/<id_paquete>-<sha12>.zip
Parser status: complete
```

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

- Add `storage status` and `storage locate`.
- Add manifests for packages/XML.
- Add storage usage summary to `doctor`.
- Add tests proving custom `--storage` is honored.
- Add safe export/copy command for XML evidence.
