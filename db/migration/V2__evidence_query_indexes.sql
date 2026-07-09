-- Additive DB-005 indexes for evidence, parser, reconciliation, and job lookups.
-- Rollback is DROP INDEX by name; no table data or columns are rewritten.

CREATE INDEX ix_xml_evidence_tenant_storage_key ON xml_evidence (tenant_id, storage_key);
CREATE INDEX ix_xml_evidence_tenant_sha256 ON xml_evidence (tenant_id, xml_sha256);
CREATE INDEX ix_xml_evidence_tenant_parser_created ON xml_evidence (tenant_id, parser_status, created_at);
CREATE INDEX ix_cfdi_documents_tenant_parser_updated ON cfdi_documents (tenant_id, parser_status, updated_at);
CREATE INDEX ix_cfdi_metadata_ledger_tenant_reconciliation_last_seen ON cfdi_metadata_ledger (tenant_id, reconciliation_state, last_seen_at);
CREATE INDEX ix_download_jobs_tenant_status_updated ON download_jobs (tenant_id, status, updated_at);
CREATE INDEX ix_queue_job_events_job_created ON queue_job_events (job_id, created_at);
