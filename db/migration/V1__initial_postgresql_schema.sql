-- Initial PostgreSQL schema for CFDI Vault MX.
-- Flyway owns schema creation; application code should not define production DDL outside migrations.


CREATE TABLE cfdi_documents (
	id SERIAL NOT NULL,
	tenant_id VARCHAR(64) NOT NULL,
	uuid VARCHAR(64) NOT NULL,
	version VARCHAR(16),
	document_type VARCHAR(8),
	status VARCHAR(32),
	issue_date TIMESTAMP WITH TIME ZONE,
	certified_at TIMESTAMP WITH TIME ZONE,
	currency VARCHAR(8),
	subtotal NUMERIC(18, 6),
	discount NUMERIC(18, 6),
	total NUMERIC(18, 6),
	issuer_rfc VARCHAR(32),
	issuer_name VARCHAR(256),
	receiver_rfc VARCHAR(32),
	receiver_name VARCHAR(256),
	payment_method VARCHAR(16),
	payment_form VARCHAR(16),
	download_state VARCHAR(64) NOT NULL,
	xml_sha256 VARCHAR(64),
	parser_status VARCHAR(32) NOT NULL,
	search_text TEXT NOT NULL,
	raw_payload JSONB NOT NULL,
	created_at TIMESTAMP WITH TIME ZONE NOT NULL,
	updated_at TIMESTAMP WITH TIME ZONE NOT NULL,
	PRIMARY KEY (id),
	CONSTRAINT uq_cfdi_documents_tenant_uuid UNIQUE (tenant_id, uuid)
);


CREATE TABLE cfdi_metadata_ledger (
	id SERIAL NOT NULL,
	tenant_id VARCHAR(64) NOT NULL,
	uuid VARCHAR(64) NOT NULL,
	direction VARCHAR(32) NOT NULL,
	issuer_rfc VARCHAR(32),
	issuer_name VARCHAR(256),
	receiver_rfc VARCHAR(32),
	receiver_name VARCHAR(256),
	issue_date TIMESTAMP WITH TIME ZONE,
	total NUMERIC(18, 6),
	status VARCHAR(32),
	effect VARCHAR(16),
	reconciliation_state VARCHAR(64) NOT NULL,
	source_package_id VARCHAR(128),
	source_metadata_sha256 VARCHAR(64),
	first_seen_at TIMESTAMP WITH TIME ZONE NOT NULL,
	last_seen_at TIMESTAMP WITH TIME ZONE NOT NULL,
	raw_payload JSONB NOT NULL,
	PRIMARY KEY (id),
	CONSTRAINT uq_metadata_ledger_uuid_direction UNIQUE (tenant_id, uuid, direction)
);


CREATE TABLE cfdi_parties (
	id SERIAL NOT NULL,
	tenant_id VARCHAR(64) NOT NULL,
	rfc VARCHAR(32) NOT NULL,
	name VARCHAR(256) NOT NULL,
	role VARCHAR(16) NOT NULL,
	document_uuid VARCHAR(64) NOT NULL,
	PRIMARY KEY (id)
);


CREATE TABLE cfdi_payments (
	id SERIAL NOT NULL,
	document_uuid VARCHAR(64) NOT NULL,
	payment_date TIMESTAMP WITH TIME ZONE,
	payment_form VARCHAR(16),
	currency VARCHAR(8),
	amount NUMERIC(18, 6),
	raw_payload JSONB NOT NULL,
	PRIMARY KEY (id)
);


CREATE TABLE cfdi_payroll (
	id SERIAL NOT NULL,
	document_uuid VARCHAR(64) NOT NULL,
	employee_curp VARCHAR(32),
	employee_number VARCHAR(64),
	payroll_type VARCHAR(16),
	payment_start_date TIMESTAMP WITH TIME ZONE,
	payment_end_date TIMESTAMP WITH TIME ZONE,
	raw_payload JSONB NOT NULL,
	PRIMARY KEY (id)
);


CREATE TABLE cfdi_related_documents (
	id SERIAL NOT NULL,
	document_uuid VARCHAR(64) NOT NULL,
	related_uuid VARCHAR(64) NOT NULL,
	relation_type VARCHAR(16),
	PRIMARY KEY (id)
);


CREATE TABLE invoices (
	id SERIAL NOT NULL,
	uuid VARCHAR(64) NOT NULL,
	issuer_rfc VARCHAR(32) NOT NULL,
	issuer_name VARCHAR(256) NOT NULL,
	receiver_rfc VARCHAR(32) NOT NULL,
	receiver_name VARCHAR(256) NOT NULL,
	issue_date TIMESTAMP WITH TIME ZONE NOT NULL,
	subtotal NUMERIC(18, 6) NOT NULL,
	total NUMERIC(18, 6) NOT NULL,
	currency VARCHAR(8) NOT NULL,
	comprobante_type VARCHAR(8) NOT NULL,
	payment_method VARCHAR(16),
	payment_form VARCHAR(16),
	xml_sha256 VARCHAR(64) NOT NULL,
	source_name VARCHAR(512) NOT NULL,
	imported_at TIMESTAMP WITH TIME ZONE NOT NULL,
	PRIMARY KEY (id)
);


CREATE TABLE queue_job_events (
	id SERIAL NOT NULL,
	job_id VARCHAR(64) NOT NULL,
	queue_name VARCHAR(128) NOT NULL,
	status VARCHAR(32) NOT NULL,
	correlation_id VARCHAR(64) NOT NULL,
	attempt INTEGER NOT NULL,
	message VARCHAR(512),
	payload JSONB NOT NULL,
	created_at TIMESTAMP WITH TIME ZONE NOT NULL,
	PRIMARY KEY (id)
);


CREATE TABLE reconciliation_events (
	id SERIAL NOT NULL,
	tenant_id VARCHAR(64) NOT NULL,
	uuid VARCHAR(64) NOT NULL,
	previous_state VARCHAR(64),
	new_state VARCHAR(64) NOT NULL,
	reason VARCHAR(512) NOT NULL,
	actor VARCHAR(64) NOT NULL,
	created_at TIMESTAMP WITH TIME ZONE NOT NULL,
	PRIMARY KEY (id)
);


CREATE TABLE sat_packages (
	id SERIAL NOT NULL,
	tenant_id VARCHAR(64) NOT NULL,
	id_paquete VARCHAR(128) NOT NULL,
	id_solicitud VARCHAR(128) NOT NULL,
	status VARCHAR(32) NOT NULL,
	attempts INTEGER NOT NULL,
	sha256_zip VARCHAR(64),
	size_bytes INTEGER,
	storage_key VARCHAR(1024),
	downloaded_at TIMESTAMP WITH TIME ZONE,
	expires_at TIMESTAMP WITH TIME ZONE,
	last_error JSONB NOT NULL,
	created_at TIMESTAMP WITH TIME ZONE NOT NULL,
	updated_at TIMESTAMP WITH TIME ZONE NOT NULL,
	PRIMARY KEY (id)
);


CREATE TABLE signer_audit (
	id SERIAL NOT NULL,
	tenant_id VARCHAR(64) NOT NULL,
	certificate_fingerprint VARCHAR(128),
	signer_mode VARCHAR(32) NOT NULL,
	operation VARCHAR(64) NOT NULL,
	request_id VARCHAR(128),
	created_at TIMESTAMP WITH TIME ZONE NOT NULL,
	PRIMARY KEY (id)
);


CREATE TABLE tenants (
	id VARCHAR(64) NOT NULL,
	name VARCHAR(256) NOT NULL,
	rfc VARCHAR(32) NOT NULL,
	created_at TIMESTAMP WITH TIME ZONE NOT NULL,
	PRIMARY KEY (id)
);


CREATE TABLE xml_evidence (
	id SERIAL NOT NULL,
	tenant_id VARCHAR(64) NOT NULL,
	uuid VARCHAR(64) NOT NULL,
	source_package_id VARCHAR(128),
	xml_sha256 VARCHAR(64) NOT NULL,
	size_bytes INTEGER NOT NULL,
	storage_key VARCHAR(1024) NOT NULL,
	parser_version VARCHAR(32) NOT NULL,
	parser_status VARCHAR(32) NOT NULL,
	created_at TIMESTAMP WITH TIME ZONE NOT NULL,
	PRIMARY KEY (id),
	CONSTRAINT uq_xml_evidence_hash UNIQUE (tenant_id, uuid, xml_sha256)
);


CREATE TABLE cfdi_concepts (
	id SERIAL NOT NULL,
	document_id INTEGER NOT NULL,
	product_service_key VARCHAR(32),
	unit_key VARCHAR(32),
	description TEXT NOT NULL,
	quantity NUMERIC(18, 6),
	unit_value NUMERIC(18, 6),
	amount NUMERIC(18, 6),
	discount NUMERIC(18, 6),
	tax_object VARCHAR(16),
	raw_payload JSONB NOT NULL,
	PRIMARY KEY (id),
	FOREIGN KEY(document_id) REFERENCES cfdi_documents (id)
);


CREATE TABLE credential_profiles (
	id VARCHAR(64) NOT NULL,
	tenant_id VARCHAR(64) NOT NULL,
	mode VARCHAR(32) NOT NULL,
	certificate_fingerprint VARCHAR(128),
	certificate_path VARCHAR(1024),
	key_path VARCHAR(1024),
	signer_endpoint VARCHAR(1024),
	is_active BOOLEAN NOT NULL,
	created_at TIMESTAMP WITH TIME ZONE NOT NULL,
	PRIMARY KEY (id),
	FOREIGN KEY(tenant_id) REFERENCES tenants (id)
);


CREATE TABLE download_jobs (
	id VARCHAR(64) NOT NULL,
	tenant_id VARCHAR(64) NOT NULL,
	rfc VARCHAR(32) NOT NULL,
	direction VARCHAR(32) NOT NULL,
	request_type VARCHAR(32) NOT NULL,
	status VARCHAR(32) NOT NULL,
	criteria_hash VARCHAR(64) NOT NULL,
	payload JSONB NOT NULL,
	created_at TIMESTAMP WITH TIME ZONE NOT NULL,
	updated_at TIMESTAMP WITH TIME ZONE NOT NULL,
	PRIMARY KEY (id),
	CONSTRAINT uq_download_jobs_tenant_hash UNIQUE (tenant_id, criteria_hash),
	FOREIGN KEY(tenant_id) REFERENCES tenants (id)
);


CREATE TABLE cfdi_taxes (
	id SERIAL NOT NULL,
	document_uuid VARCHAR(64) NOT NULL,
	concept_id INTEGER,
	tax_type VARCHAR(16) NOT NULL,
	tax VARCHAR(16),
	factor_type VARCHAR(16),
	rate_or_quota NUMERIC(18, 6),
	base NUMERIC(18, 6),
	amount NUMERIC(18, 6),
	PRIMARY KEY (id),
	FOREIGN KEY(concept_id) REFERENCES cfdi_concepts (id)
);


CREATE TABLE sat_requests (
	id SERIAL NOT NULL,
	tenant_id VARCHAR(64) NOT NULL,
	job_id VARCHAR(64),
	id_solicitud VARCHAR(128) NOT NULL,
	criteria_hash VARCHAR(64) NOT NULL,
	direction VARCHAR(32) NOT NULL,
	request_type VARCHAR(32) NOT NULL,
	sat_state VARCHAR(32) NOT NULL,
	sat_code VARCHAR(16),
	sat_message VARCHAR(512),
	requested_at TIMESTAMP WITH TIME ZONE NOT NULL,
	last_verified_at TIMESTAMP WITH TIME ZONE,
	metadata_sha256 VARCHAR(64),
	metadata_storage_key VARCHAR(1024),
	raw_response JSONB NOT NULL,
	PRIMARY KEY (id),
	FOREIGN KEY(job_id) REFERENCES download_jobs (id)
);

CREATE INDEX ix_cfdi_concepts_document_id ON cfdi_concepts (document_id);
CREATE INDEX ix_cfdi_documents_document_type ON cfdi_documents (document_type);
CREATE INDEX ix_cfdi_documents_download_state ON cfdi_documents (download_state);
CREATE INDEX ix_cfdi_documents_issue_date ON cfdi_documents (issue_date);
CREATE INDEX ix_cfdi_documents_issuer_rfc ON cfdi_documents (issuer_rfc);
CREATE INDEX ix_cfdi_documents_receiver_rfc ON cfdi_documents (receiver_rfc);
CREATE INDEX ix_cfdi_documents_status ON cfdi_documents (status);
CREATE INDEX ix_cfdi_documents_tenant_id ON cfdi_documents (tenant_id);
CREATE INDEX ix_cfdi_documents_tenant_issue_date ON cfdi_documents (tenant_id, issue_date);
CREATE INDEX ix_cfdi_documents_total ON cfdi_documents (total);
CREATE INDEX ix_cfdi_documents_uuid ON cfdi_documents (uuid);
CREATE INDEX ix_cfdi_documents_xml_sha256 ON cfdi_documents (xml_sha256);
CREATE INDEX ix_cfdi_metadata_ledger_direction ON cfdi_metadata_ledger (direction);
CREATE INDEX ix_cfdi_metadata_ledger_issue_date ON cfdi_metadata_ledger (issue_date);
CREATE INDEX ix_cfdi_metadata_ledger_issuer_rfc ON cfdi_metadata_ledger (issuer_rfc);
CREATE INDEX ix_cfdi_metadata_ledger_receiver_rfc ON cfdi_metadata_ledger (receiver_rfc);
CREATE INDEX ix_cfdi_metadata_ledger_reconciliation_state ON cfdi_metadata_ledger (reconciliation_state);
CREATE INDEX ix_cfdi_metadata_ledger_source_metadata_sha256 ON cfdi_metadata_ledger (source_metadata_sha256);
CREATE INDEX ix_cfdi_metadata_ledger_source_package_id ON cfdi_metadata_ledger (source_package_id);
CREATE INDEX ix_cfdi_metadata_ledger_status ON cfdi_metadata_ledger (status);
CREATE INDEX ix_cfdi_metadata_ledger_tenant_id ON cfdi_metadata_ledger (tenant_id);
CREATE INDEX ix_cfdi_metadata_ledger_uuid ON cfdi_metadata_ledger (uuid);
CREATE INDEX ix_cfdi_parties_document_uuid ON cfdi_parties (document_uuid);
CREATE INDEX ix_cfdi_parties_rfc ON cfdi_parties (rfc);
CREATE INDEX ix_cfdi_parties_tenant_id ON cfdi_parties (tenant_id);
CREATE INDEX ix_cfdi_payments_document_uuid ON cfdi_payments (document_uuid);
CREATE INDEX ix_cfdi_payroll_document_uuid ON cfdi_payroll (document_uuid);
CREATE INDEX ix_cfdi_related_documents_document_uuid ON cfdi_related_documents (document_uuid);
CREATE INDEX ix_cfdi_related_documents_related_uuid ON cfdi_related_documents (related_uuid);
CREATE INDEX ix_cfdi_taxes_document_uuid ON cfdi_taxes (document_uuid);
CREATE INDEX ix_credential_profiles_tenant_id ON credential_profiles (tenant_id);
CREATE INDEX ix_download_jobs_criteria_hash ON download_jobs (criteria_hash);
CREATE INDEX ix_download_jobs_rfc ON download_jobs (rfc);
CREATE INDEX ix_download_jobs_status ON download_jobs (status);
CREATE INDEX ix_download_jobs_tenant_id ON download_jobs (tenant_id);
CREATE UNIQUE INDEX ix_invoices_uuid ON invoices (uuid);
CREATE INDEX ix_queue_job_events_correlation_id ON queue_job_events (correlation_id);
CREATE INDEX ix_queue_job_events_job_id ON queue_job_events (job_id);
CREATE INDEX ix_queue_job_events_queue_name ON queue_job_events (queue_name);
CREATE INDEX ix_queue_job_events_status ON queue_job_events (status);
CREATE INDEX ix_reconciliation_events_new_state ON reconciliation_events (new_state);
CREATE INDEX ix_reconciliation_events_tenant_id ON reconciliation_events (tenant_id);
CREATE INDEX ix_reconciliation_events_uuid ON reconciliation_events (uuid);
CREATE UNIQUE INDEX ix_sat_packages_id_paquete ON sat_packages (id_paquete);
CREATE INDEX ix_sat_packages_id_solicitud ON sat_packages (id_solicitud);
CREATE INDEX ix_sat_packages_status ON sat_packages (status);
CREATE INDEX ix_sat_packages_tenant_id ON sat_packages (tenant_id);
CREATE INDEX ix_sat_requests_criteria_hash ON sat_requests (criteria_hash);
CREATE UNIQUE INDEX ix_sat_requests_id_solicitud ON sat_requests (id_solicitud);
CREATE INDEX ix_sat_requests_sat_state ON sat_requests (sat_state);
CREATE INDEX ix_sat_requests_tenant_id ON sat_requests (tenant_id);
CREATE INDEX ix_signer_audit_tenant_id ON signer_audit (tenant_id);
CREATE INDEX ix_tenants_rfc ON tenants (rfc);
CREATE INDEX ix_xml_evidence_parser_status ON xml_evidence (parser_status);
CREATE INDEX ix_xml_evidence_tenant_id ON xml_evidence (tenant_id);
CREATE INDEX ix_xml_evidence_uuid ON xml_evidence (uuid);
CREATE INDEX ix_xml_evidence_xml_sha256 ON xml_evidence (xml_sha256);
