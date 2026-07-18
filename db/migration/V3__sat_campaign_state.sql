-- SAT-DB-001 durable campaign state.
-- Flyway owns this additive migration. Payload bytes remain in external storage.
-- Rollback (manual, reverse dependency order): drop the append-only trigger and
-- indexes, drop SAT child tables, then remove V3 columns from sat_packages and
-- sat_requests. Before dropping the triggers, revoke any temporary maintenance
-- privileges and restore the pre-V3 privilege snapshot. The reverse-order
-- statements are documented here, not executed automatically:
-- REVOKE UPDATE, DELETE, TRUNCATE ON sat_verify_attempts FROM <maintenance-role>;
-- DROP TRIGGER sat_verify_attempts_validate_claim ON sat_verify_attempts;
-- DROP TRIGGER sat_verify_attempts_append_only ON sat_verify_attempts;
-- DROP FUNCTION sat_verify_attempts_validate_claim();
-- DROP FUNCTION sat_verify_attempts_append_only();
-- Never run rollback against a database containing live SAT state.

CREATE TABLE sat_campaigns (
	id SERIAL NOT NULL,
	campaign_ref VARCHAR(96) NOT NULL,
	tenant_id VARCHAR(64) NOT NULL,
	profile_ref VARCHAR(128) NOT NULL,
	manifest_sha256 VARCHAR(64) NOT NULL,
	commit_ref VARCHAR(128) NOT NULL,
	phase VARCHAR(32) NOT NULL,
	status VARCHAR(64) NOT NULL,
	max_open_operations SMALLINT NOT NULL DEFAULT 2,
	budget INTEGER NOT NULL,
	created_at TIMESTAMP WITH TIME ZONE NOT NULL,
	updated_at TIMESTAMP WITH TIME ZONE NOT NULL,
	PRIMARY KEY (id),
	CONSTRAINT uq_sat_campaigns_ref UNIQUE (campaign_ref),
	CONSTRAINT uq_sat_campaigns_tenant_id UNIQUE (tenant_id, id),
	CONSTRAINT uq_sat_campaigns_identity UNIQUE (id, profile_ref, manifest_sha256, commit_ref),
	CONSTRAINT fk_sat_campaigns_tenant FOREIGN KEY (tenant_id) REFERENCES tenants (id),
	CONSTRAINT ck_sat_campaigns_manifest_sha256 CHECK (manifest_sha256 ~ '^[0-9a-fA-F]{64}$'),
	CONSTRAINT ck_sat_campaigns_max_open CHECK (max_open_operations = 2),
	CONSTRAINT ck_sat_campaigns_budget CHECK (budget > 0)
);


CREATE TABLE sat_campaign_windows (
	id SERIAL NOT NULL,
	campaign_id INTEGER NOT NULL,
	work_ref VARCHAR(96) NOT NULL,
	parent_window_id INTEGER,
	direction VARCHAR(16) NOT NULL,
	start_date DATE NOT NULL,
	end_date DATE NOT NULL,
	split_depth SMALLINT NOT NULL DEFAULT 0,
	recovery_ref VARCHAR(96),
	status VARCHAR(64) NOT NULL,
	created_at TIMESTAMP WITH TIME ZONE NOT NULL,
	updated_at TIMESTAMP WITH TIME ZONE NOT NULL,
	PRIMARY KEY (id),
	CONSTRAINT uq_sat_campaign_windows_ref UNIQUE (work_ref),
	CONSTRAINT uq_sat_campaign_windows_period UNIQUE (campaign_id, direction, start_date, end_date),
	CONSTRAINT uq_sat_campaign_windows_campaign_id UNIQUE (campaign_id, id),
	CONSTRAINT fk_sat_campaign_windows_campaign FOREIGN KEY (campaign_id) REFERENCES sat_campaigns (id),
	CONSTRAINT fk_sat_campaign_windows_parent FOREIGN KEY (parent_window_id) REFERENCES sat_campaign_windows (id),
	CONSTRAINT fk_sat_campaign_windows_parent_campaign FOREIGN KEY (campaign_id, parent_window_id) REFERENCES sat_campaign_windows (campaign_id, id),
	CONSTRAINT ck_sat_campaign_windows_direction CHECK (direction IN ('received', 'issued')),
	CONSTRAINT ck_sat_campaign_windows_dates CHECK (start_date <= end_date),
	CONSTRAINT ck_sat_campaign_windows_split_depth CHECK (split_depth BETWEEN 0 AND 1),
	CONSTRAINT ck_sat_campaign_windows_period_length CHECK (end_date - start_date + 1 IN (7, 14)),
	CONSTRAINT ck_sat_campaign_windows_split_length CHECK (
		(split_depth = 0 AND end_date - start_date + 1 = 14)
		OR (split_depth = 1 AND end_date - start_date + 1 = 7)
	),
	CONSTRAINT ck_sat_campaign_windows_split_parent CHECK (
		split_depth = 0 OR parent_window_id IS NOT NULL
	),
	CONSTRAINT ck_sat_campaign_windows_status CHECK (status IN ('planned', 'reserved', 'metadata', 'cfdi', 'no_data', 'complete', 'manual_review', 'failed'))
 );


CREATE TABLE sat_grants (
	id SERIAL NOT NULL,
	campaign_id INTEGER NOT NULL,
	grant_ref VARCHAR(96) NOT NULL,
	phase VARCHAR(32) NOT NULL,
	manifest_sha256 VARCHAR(64) NOT NULL,
	commit_ref VARCHAR(128) NOT NULL,
	profile_ref VARCHAR(128) NOT NULL,
	reason VARCHAR(512) NOT NULL,
	budget INTEGER NOT NULL,
	expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
	created_at TIMESTAMP WITH TIME ZONE NOT NULL,
	PRIMARY KEY (id),
	CONSTRAINT uq_sat_grants_ref UNIQUE (grant_ref),
	CONSTRAINT fk_sat_grants_campaign FOREIGN KEY (campaign_id) REFERENCES sat_campaigns (id),
	CONSTRAINT fk_sat_grants_campaign_identity FOREIGN KEY (campaign_id, profile_ref, manifest_sha256, commit_ref) REFERENCES sat_campaigns (id, profile_ref, manifest_sha256, commit_ref),
	CONSTRAINT ck_sat_grants_phase CHECK (phase IN ('metadata-proof', 'cfdi-proof', 'continue')),
	CONSTRAINT ck_sat_grants_manifest_sha256 CHECK (manifest_sha256 ~ '^[0-9a-fA-F]{64}$'),
	CONSTRAINT ck_sat_grants_budget CHECK (budget > 0),
	CONSTRAINT ck_sat_grants_expiry CHECK (expires_at >= created_at)
);


CREATE TABLE sat_artifacts (
	id SERIAL NOT NULL,
	campaign_id INTEGER NOT NULL,
	window_id INTEGER,
	artifact_scope VARCHAR(16) NOT NULL DEFAULT 'window',
	artifact_ref VARCHAR(96) NOT NULL,
	kind VARCHAR(16) NOT NULL,
	storage_key VARCHAR(1024) NOT NULL,
	sha256 VARCHAR(64) NOT NULL,
	size_bytes BIGINT NOT NULL,
	validation_status VARCHAR(32) NOT NULL,
	counts JSONB NOT NULL DEFAULT '{}'::jsonb,
	created_at TIMESTAMP WITH TIME ZONE NOT NULL,
	PRIMARY KEY (id),
	CONSTRAINT uq_sat_artifacts_ref UNIQUE (artifact_ref),
	CONSTRAINT uq_sat_artifacts_content UNIQUE (campaign_id, kind, sha256),
	CONSTRAINT uq_sat_artifacts_campaign_id UNIQUE (campaign_id, id),
	CONSTRAINT fk_sat_artifacts_campaign FOREIGN KEY (campaign_id) REFERENCES sat_campaigns (id),
	CONSTRAINT fk_sat_artifacts_window FOREIGN KEY (window_id) REFERENCES sat_campaign_windows (id),
	CONSTRAINT fk_sat_artifacts_campaign_window FOREIGN KEY (campaign_id, window_id) REFERENCES sat_campaign_windows (campaign_id, id),
	CONSTRAINT ck_sat_artifacts_kind CHECK (kind IN ('metadata_zip', 'metadata_txt', 'cfdi_zip', 'cfdi_xml')),
	CONSTRAINT ck_sat_artifacts_scope CHECK (
		(artifact_scope = 'window' AND window_id IS NOT NULL)
		OR (artifact_scope = 'campaign' AND window_id IS NULL)
	),
	CONSTRAINT ck_sat_artifacts_sha256 CHECK (sha256 ~ '^[0-9a-fA-F]{64}$'),
	CONSTRAINT ck_sat_artifacts_size CHECK (size_bytes >= 0)
);


-- These columns extend the V1 request model without removing legacy data.
ALTER TABLE sat_requests
	ADD COLUMN campaign_id INTEGER REFERENCES sat_campaigns (id),
	ADD COLUMN window_id INTEGER REFERENCES sat_campaign_windows (id),
	ADD COLUMN work_ref VARCHAR(96),
	ADD COLUMN recovery_ref VARCHAR(96),
	ADD COLUMN next_check_at TIMESTAMP WITH TIME ZONE,
	ADD COLUMN service_window_expires_at TIMESTAMP WITH TIME ZONE,
	ADD COLUMN verify_attempts INTEGER NOT NULL DEFAULT 0,
	ADD COLUMN status VARCHAR(64) NOT NULL DEFAULT 'submitted',
	ADD COLUMN response_summary JSONB NOT NULL DEFAULT '{}'::jsonb,
	ADD CONSTRAINT uq_sat_requests_campaign_work_type UNIQUE (campaign_id, work_ref, request_type),
	ADD CONSTRAINT uq_sat_requests_campaign_id UNIQUE (campaign_id, id),
	ADD CONSTRAINT fk_sat_requests_campaign_tenant
		FOREIGN KEY (tenant_id, campaign_id) REFERENCES sat_campaigns (tenant_id, id),
	ADD CONSTRAINT fk_sat_requests_campaign_window FOREIGN KEY (campaign_id, window_id) REFERENCES sat_campaign_windows (campaign_id, id),
	ADD CONSTRAINT ck_sat_requests_campaign_window_pair CHECK (
		(campaign_id IS NULL AND window_id IS NULL) OR (campaign_id IS NOT NULL AND window_id IS NOT NULL)
	),
	ADD CONSTRAINT ck_sat_requests_work_ref_when_linked CHECK (campaign_id IS NULL OR work_ref IS NOT NULL),
	ADD CONSTRAINT ck_sat_requests_status CHECK (status IN (
		'planned', 'outstanding', 'recovery_linked', 'submitted', 'waiting_verify',
		'package', 'no_data', 'failed', 'expired', 'service_window_exceeded', 'uncertain'
	)),
	ADD CONSTRAINT ck_sat_requests_service_window CHECK (
		service_window_expires_at IS NULL OR service_window_expires_at >= requested_at
	);

COMMENT ON COLUMN sat_requests.raw_response IS
	'Legacy compatibility column. New flows use response_summary and do not persist transport bodies.';


CREATE TABLE sat_claims (
	id SERIAL NOT NULL,
	claim_ref VARCHAR(96) NOT NULL,
	campaign_id INTEGER NOT NULL,
	window_id INTEGER,
	request_id INTEGER,
	operation_kind VARCHAR(16) NOT NULL,
	idempotency_key VARCHAR(192) NOT NULL,
	operation_slot SMALLINT NOT NULL,
	worker_ref VARCHAR(128) NOT NULL,
	claimed_at TIMESTAMP WITH TIME ZONE NOT NULL,
	lease_until TIMESTAMP WITH TIME ZONE NOT NULL,
	completed_at TIMESTAMP WITH TIME ZONE,
	active BOOLEAN NOT NULL DEFAULT TRUE,
	result VARCHAR(32),
	result_code VARCHAR(32),
	PRIMARY KEY (id),
	CONSTRAINT uq_sat_claims_ref UNIQUE (claim_ref),
	CONSTRAINT uq_sat_claims_idempotency UNIQUE (campaign_id, idempotency_key),
	CONSTRAINT uq_sat_claims_campaign_id UNIQUE (campaign_id, id),
	CONSTRAINT fk_sat_claims_campaign FOREIGN KEY (campaign_id) REFERENCES sat_campaigns (id),
	CONSTRAINT fk_sat_claims_window FOREIGN KEY (window_id) REFERENCES sat_campaign_windows (id),
	CONSTRAINT fk_sat_claims_request FOREIGN KEY (request_id) REFERENCES sat_requests (id),
	CONSTRAINT fk_sat_claims_campaign_window FOREIGN KEY (campaign_id, window_id) REFERENCES sat_campaign_windows (campaign_id, id),
	CONSTRAINT fk_sat_claims_campaign_request FOREIGN KEY (campaign_id, request_id) REFERENCES sat_requests (campaign_id, id),
	CONSTRAINT ck_sat_claims_operation CHECK (operation_kind IN ('submit', 'verify', 'download')),
	CONSTRAINT ck_sat_claims_request_for_non_submit CHECK (
		operation_kind = 'submit' OR request_id IS NOT NULL
	),
	CONSTRAINT ck_sat_claims_slot CHECK (operation_slot BETWEEN 1 AND 2),
	CONSTRAINT ck_sat_claims_result CHECK (result IS NULL OR result IN (
		'pending', 'package', 'no_data', 'error', 'uncertain', 'expired',
		'duplicate_active_request', 'sat_too_many_results', 'service_window_exceeded',
		'lease_expired'
	)),
	CONSTRAINT ck_sat_claims_active CHECK (active = (completed_at IS NULL)),
	CONSTRAINT ck_sat_claims_dates CHECK (lease_until >= claimed_at AND (completed_at IS NULL OR completed_at >= claimed_at))
);


CREATE TABLE sat_verify_attempts (
	id SERIAL NOT NULL,
	campaign_id INTEGER NOT NULL,
	request_id INTEGER NOT NULL,
	claim_id INTEGER NOT NULL,
	attempt INTEGER NOT NULL,
	scheduled_at TIMESTAMP WITH TIME ZONE NOT NULL,
	contacted_at TIMESTAMP WITH TIME ZONE,
	category VARCHAR(32) NOT NULL,
	result VARCHAR(32) NOT NULL,
	result_code VARCHAR(32),
	next_check_at TIMESTAMP WITH TIME ZONE,
	claim_ref VARCHAR(96) NOT NULL,
	created_at TIMESTAMP WITH TIME ZONE NOT NULL,
	PRIMARY KEY (id),
	CONSTRAINT uq_sat_verify_attempts_number UNIQUE (request_id, attempt),
	CONSTRAINT uq_sat_verify_attempts_claim UNIQUE (claim_ref),
	CONSTRAINT fk_sat_verify_attempts_campaign_request FOREIGN KEY (campaign_id, request_id) REFERENCES sat_requests (campaign_id, id),
	CONSTRAINT fk_sat_verify_attempts_campaign_claim FOREIGN KEY (campaign_id, claim_id) REFERENCES sat_claims (campaign_id, id),
	CONSTRAINT fk_sat_verify_attempts_request FOREIGN KEY (request_id) REFERENCES sat_requests (id),
	CONSTRAINT fk_sat_verify_attempts_claim FOREIGN KEY (claim_id) REFERENCES sat_claims (id),
	CONSTRAINT ck_sat_verify_attempts_attempt CHECK (attempt > 0),
	CONSTRAINT ck_sat_verify_attempts_result CHECK (result IN (
		'pending', 'package', 'no_data', 'error', 'expired', 'duplicate_active_request',
		'sat_too_many_results', 'service_window_exceeded', 'download_uncertain'
	)),
	CONSTRAINT ck_sat_verify_attempts_category CHECK (category IN (
		'pending', 'package', 'no_data', 'error', 'expired', 'duplicate_active_request',
		'sat_too_many_results', 'service_window_exceeded', 'download_uncertain'
	)),
	CONSTRAINT ck_sat_verify_attempts_contacted CHECK (contacted_at IS NULL OR contacted_at >= scheduled_at)
);


CREATE TABLE sat_metadata_imports (
	id SERIAL NOT NULL,
	campaign_id INTEGER NOT NULL,
	window_id INTEGER NOT NULL,
	artifact_id INTEGER NOT NULL,
	encoding VARCHAR(32) NOT NULL,
	delimiter VARCHAR(4) NOT NULL,
	header_compatible BOOLEAN NOT NULL,
	record_count BIGINT NOT NULL DEFAULT 0,
	eligible_count BIGINT NOT NULL DEFAULT 0,
	cancelled_count BIGINT NOT NULL DEFAULT 0,
	duplicate_count BIGINT NOT NULL DEFAULT 0,
	conflict_count BIGINT NOT NULL DEFAULT 0,
	unknown_count BIGINT NOT NULL DEFAULT 0,
	created_at TIMESTAMP WITH TIME ZONE NOT NULL,
	PRIMARY KEY (id),
	CONSTRAINT fk_sat_metadata_imports_campaign_window FOREIGN KEY (campaign_id, window_id) REFERENCES sat_campaign_windows (campaign_id, id),
	CONSTRAINT fk_sat_metadata_imports_campaign_artifact FOREIGN KEY (campaign_id, artifact_id) REFERENCES sat_artifacts (campaign_id, id),
	CONSTRAINT fk_sat_metadata_imports_window FOREIGN KEY (window_id) REFERENCES sat_campaign_windows (id),
	CONSTRAINT fk_sat_metadata_imports_artifact FOREIGN KEY (artifact_id) REFERENCES sat_artifacts (id),
	CONSTRAINT uq_sat_metadata_imports_window_artifact UNIQUE (window_id, artifact_id),
	CONSTRAINT ck_sat_metadata_imports_counts CHECK (
		record_count >= 0 AND eligible_count >= 0 AND cancelled_count >= 0
		AND duplicate_count >= 0 AND conflict_count >= 0 AND unknown_count >= 0
	)
);


ALTER TABLE sat_packages
	ADD COLUMN campaign_id INTEGER REFERENCES sat_campaigns (id),
	ADD COLUMN window_id INTEGER REFERENCES sat_campaign_windows (id),
	ADD COLUMN artifact_id INTEGER REFERENCES sat_artifacts (id),
	ADD COLUMN claim_id INTEGER REFERENCES sat_claims (id),
	ADD COLUMN ordinal INTEGER,
	ADD COLUMN download_state VARCHAR(32) NOT NULL DEFAULT 'pending',
	ADD COLUMN validation_status VARCHAR(32) NOT NULL DEFAULT 'unvalidated',
	ADD CONSTRAINT ck_sat_packages_campaign_window_pair CHECK (
		(campaign_id IS NULL AND window_id IS NULL) OR (campaign_id IS NOT NULL AND window_id IS NOT NULL)
	),
	ADD CONSTRAINT ck_sat_packages_campaign_artifact_pair CHECK (
		(campaign_id IS NULL AND artifact_id IS NULL) OR (campaign_id IS NOT NULL AND artifact_id IS NOT NULL)
	),
	ADD CONSTRAINT ck_sat_packages_campaign_claim_pair CHECK (
		(campaign_id IS NULL AND claim_id IS NULL) OR (campaign_id IS NOT NULL AND claim_id IS NOT NULL)
	),
	ADD CONSTRAINT ck_sat_packages_download_state CHECK (
		download_state IN ('pending', 'downloaded', 'download_uncertain', 'download_failed')
	),
	ADD CONSTRAINT ck_sat_packages_validation_status CHECK (
		validation_status IN ('unvalidated', 'valid', 'invalid')
	);

ALTER TABLE sat_packages
	ADD CONSTRAINT fk_sat_packages_campaign_window
	FOREIGN KEY (campaign_id, window_id) REFERENCES sat_campaign_windows (campaign_id, id),
	ADD CONSTRAINT fk_sat_packages_campaign_artifact
	FOREIGN KEY (campaign_id, artifact_id) REFERENCES sat_artifacts (campaign_id, id),
	ADD CONSTRAINT fk_sat_packages_campaign_claim
		FOREIGN KEY (campaign_id, claim_id) REFERENCES sat_claims (campaign_id, id),
	ADD CONSTRAINT fk_sat_packages_campaign_tenant
		FOREIGN KEY (tenant_id, campaign_id) REFERENCES sat_campaigns (tenant_id, id),
	ADD CONSTRAINT ck_sat_packages_ordinal CHECK (ordinal IS NULL OR ordinal > 0);


CREATE OR REPLACE FUNCTION sat_verify_attempts_append_only()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
	RAISE EXCEPTION 'sat_verify_attempts is append-only';
END;
$$;

CREATE TRIGGER sat_verify_attempts_append_only
BEFORE UPDATE OR DELETE ON sat_verify_attempts
FOR EACH ROW EXECUTE FUNCTION sat_verify_attempts_append_only();

CREATE OR REPLACE FUNCTION sat_verify_attempts_validate_claim()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
	claim_ref_value VARCHAR(96);
	claim_operation_kind VARCHAR(16);
	claim_request_id INTEGER;
	claim_active BOOLEAN;
BEGIN
	SELECT claim_ref, operation_kind, request_id, active
	INTO claim_ref_value, claim_operation_kind, claim_request_id, claim_active
	FROM sat_claims
	WHERE id = NEW.claim_id AND campaign_id = NEW.campaign_id;
	IF claim_ref_value IS NULL
		OR claim_ref_value <> NEW.claim_ref
		OR claim_operation_kind <> 'verify'
		OR claim_request_id IS NULL
		OR claim_request_id <> NEW.request_id
		OR claim_active IS NOT TRUE THEN
		RAISE EXCEPTION 'sat_verify_attempts claim reference mismatch';
	END IF;
	RETURN NEW;
END;
$$;

CREATE TRIGGER sat_verify_attempts_validate_claim
BEFORE INSERT ON sat_verify_attempts
FOR EACH ROW EXECUTE FUNCTION sat_verify_attempts_validate_claim();


CREATE UNIQUE INDEX ix_sat_claims_campaign_open_slot
	ON sat_claims (campaign_id, operation_slot)
	WHERE active;
CREATE INDEX ix_sat_campaign_windows_campaign_status_date
	ON sat_campaign_windows (campaign_id, status, start_date);
CREATE INDEX ix_sat_grants_campaign_expires
	ON sat_grants (campaign_id, expires_at);
CREATE INDEX ix_sat_requests_campaign_status
	ON sat_requests (campaign_id, status);
CREATE INDEX ix_sat_requests_due_verify
	ON sat_requests (status, next_check_at)
	WHERE next_check_at IS NOT NULL;
CREATE INDEX ix_sat_requests_service_window
	ON sat_requests (status, service_window_expires_at)
	WHERE service_window_expires_at IS NOT NULL;
CREATE INDEX ix_sat_claims_lease
	ON sat_claims (lease_until)
	WHERE active;
CREATE INDEX ix_sat_verify_attempts_request_created
	ON sat_verify_attempts (request_id, created_at);
CREATE INDEX ix_sat_artifacts_campaign_kind
	ON sat_artifacts (campaign_id, kind);
CREATE INDEX ix_sat_metadata_imports_window
	ON sat_metadata_imports (window_id, created_at);
CREATE INDEX ix_sat_packages_campaign_state
	ON sat_packages (campaign_id, download_state);
CREATE INDEX ix_sat_packages_request_status
	ON sat_packages (id_solicitud, status);

COMMENT ON TABLE sat_verify_attempts IS
	'Append-only verification history. The table owner can bypass triggers; restrict maintenance, UPDATE, DELETE, and TRUNCATE to controlled migrations.';
COMMENT ON TABLE sat_claims IS
	'Claims are reclaimed by closing the expired row (active=false, completed_at set) in the same transaction that creates the replacement claim. Table owners remain responsible for controlled TRUNCATE.';

REVOKE UPDATE, DELETE, TRUNCATE ON sat_verify_attempts FROM PUBLIC;
