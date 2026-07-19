-- V6 durable ledger jobs, claims, outbox, and inbox.
-- PostgreSQL is the source of truth. Queue messages carry references only;
-- content remains in the configured external artifact store.
--
-- Manual rollback only, after workers stop, queues drain, leases are audited,
-- and a backup is verified. Reverse order: remove indexes and triggers,
-- remove helper functions, then remove ledger_inbox, ledger_outbox,
-- ledger_job_claims, and ledger_jobs. Never execute rollback against live
-- state, and never delete the audit history as part of routine operation.
-- DROP INDEX ix_ledger_inbox_unprocessed;
-- DROP INDEX ix_ledger_outbox_lease;
-- DROP INDEX ix_ledger_outbox_pending;
-- DROP INDEX ix_ledger_job_claims_lease;
-- DROP INDEX uq_ledger_job_claims_active;
-- DROP INDEX ix_ledger_jobs_due;
-- DROP TRIGGER ledger_jobs_validate_transition ON ledger_jobs;
-- DROP TRIGGER ledger_job_claims_append_only ON ledger_job_claims;
-- DROP FUNCTION ledger_jobs_validate_transition();
-- DROP FUNCTION ledger_job_claims_append_only();
-- DROP FUNCTION ledger_aggregate_counts_valid(JSONB);
-- DROP TABLE ledger_inbox;
-- DROP TABLE ledger_outbox;
-- DROP TABLE ledger_job_claims;
-- DROP TABLE ledger_jobs;

CREATE FUNCTION ledger_aggregate_counts_valid(value JSONB)
RETURNS BOOLEAN
LANGUAGE SQL
IMMUTABLE
AS $$
    SELECT jsonb_typeof(value) = 'object'
       AND NOT EXISTS (
           SELECT 1
           FROM jsonb_each_text(value) AS entry(key, value)
           WHERE entry.key <> ALL (ARRAY[
               'records', 'eligible', 'cancelled', 'duplicate', 'conflict',
               'unknown', 'concepts', 'taxes', 'payments', 'payroll', 'related'
           ])
           OR entry.value !~ '^[0-9]+$'
       );
$$;

CREATE TABLE ledger_jobs (
    job_id VARCHAR(96) NOT NULL,
    tenant_id VARCHAR(64) NOT NULL,
    job_type VARCHAR(64) NOT NULL,
    queue_name VARCHAR(128) NOT NULL,
    artifact_ref VARCHAR(192),
    idempotency_key VARCHAR(192) NOT NULL,
    status VARCHAR(24) NOT NULL DEFAULT 'queued',
    available_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    attempt_count INTEGER NOT NULL DEFAULT 0,
    max_attempts INTEGER NOT NULL DEFAULT 3,
    last_error_code VARCHAR(64),
    aggregate_counts JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP WITH TIME ZONE,
    PRIMARY KEY (job_id),
    CONSTRAINT fk_ledger_jobs_tenant FOREIGN KEY (tenant_id) REFERENCES tenants (id),
    CONSTRAINT uq_ledger_jobs_idempotency UNIQUE (tenant_id, job_type, idempotency_key),
    CONSTRAINT ck_ledger_jobs_job_id CHECK (length(job_id) BETWEEN 1 AND 96),
    CONSTRAINT ck_ledger_jobs_type CHECK (length(job_type) BETWEEN 1 AND 64),
    CONSTRAINT ck_ledger_jobs_queue CHECK (length(queue_name) BETWEEN 1 AND 128),
    CONSTRAINT ck_ledger_jobs_artifact CHECK (artifact_ref IS NULL OR length(artifact_ref) BETWEEN 1 AND 192),
    CONSTRAINT ck_ledger_jobs_idempotency CHECK (length(idempotency_key) BETWEEN 1 AND 192),
    CONSTRAINT ck_ledger_jobs_status CHECK (status IN (
        'queued', 'claimed', 'running', 'succeeded', 'duplicate', 'failed', 'uncertain', 'dead_letter'
    )),
    CONSTRAINT ck_ledger_jobs_attempts CHECK (attempt_count >= 0 AND max_attempts > 0 AND attempt_count <= max_attempts),
    CONSTRAINT ck_ledger_jobs_error_code CHECK (
        last_error_code IS NULL OR last_error_code ~ '^[a-z][a-z0-9_]{0,63}$'
    ),
    CONSTRAINT ck_ledger_jobs_counts CHECK (ledger_aggregate_counts_valid(aggregate_counts)),
    CONSTRAINT ck_ledger_jobs_completion CHECK (
        (status IN ('succeeded', 'duplicate', 'failed', 'uncertain', 'dead_letter') AND completed_at IS NOT NULL)
        OR (status NOT IN ('succeeded', 'duplicate', 'failed', 'uncertain', 'dead_letter'))
    )
);

CREATE FUNCTION ledger_jobs_validate_transition()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF OLD.status IN ('succeeded', 'duplicate', 'failed', 'uncertain', 'dead_letter')
       AND NEW.status <> OLD.status THEN
        RAISE EXCEPTION 'ledger job terminal state is immutable' USING ERRCODE = 'check_violation';
    END IF;
    IF OLD.status IN ('succeeded', 'duplicate', 'failed', 'uncertain', 'dead_letter')
       AND NEW.status = 'queued' THEN
        RAISE EXCEPTION 'ledger job cannot be reopened' USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER ledger_jobs_validate_transition
BEFORE UPDATE ON ledger_jobs
FOR EACH ROW
EXECUTE FUNCTION ledger_jobs_validate_transition();

CREATE TABLE ledger_job_claims (
    claim_id VARCHAR(96) NOT NULL,
    job_id VARCHAR(96) NOT NULL,
    worker_ref VARCHAR(128) NOT NULL,
    attempt INTEGER NOT NULL,
    lease_until TIMESTAMP WITH TIME ZONE NOT NULL,
    claimed_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP WITH TIME ZONE,
    result_code VARCHAR(64),
    PRIMARY KEY (claim_id),
    CONSTRAINT fk_ledger_job_claims_job FOREIGN KEY (job_id) REFERENCES ledger_jobs (job_id),
    CONSTRAINT uq_ledger_job_claims_attempt UNIQUE (job_id, attempt),
    CONSTRAINT ck_ledger_job_claims_claim_id CHECK (length(claim_id) BETWEEN 1 AND 96),
    CONSTRAINT ck_ledger_job_claims_worker CHECK (length(worker_ref) BETWEEN 1 AND 128),
    CONSTRAINT ck_ledger_job_claims_attempt CHECK (attempt > 0),
    CONSTRAINT ck_ledger_job_claims_lease CHECK (lease_until > claimed_at),
    CONSTRAINT ck_ledger_job_claims_result CHECK (
        result_code IS NULL OR result_code ~ '^[a-z][a-z0-9_]{0,63}$'
    ),
    CONSTRAINT ck_ledger_job_claims_completion CHECK (
        completed_at IS NULL OR completed_at >= claimed_at
    )
);

CREATE UNIQUE INDEX uq_ledger_job_claims_active
    ON ledger_job_claims (job_id)
    WHERE completed_at IS NULL;

CREATE FUNCTION ledger_job_claims_append_only()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'ledger job claim history is append-only' USING ERRCODE = 'check_violation';
    END IF;
    IF OLD.completed_at IS NOT NULL
       OR NEW.completed_at IS NULL
       OR OLD.claim_id IS DISTINCT FROM NEW.claim_id
       OR OLD.job_id IS DISTINCT FROM NEW.job_id
       OR OLD.worker_ref IS DISTINCT FROM NEW.worker_ref
       OR OLD.attempt IS DISTINCT FROM NEW.attempt
       OR OLD.lease_until IS DISTINCT FROM NEW.lease_until
       OR OLD.claimed_at IS DISTINCT FROM NEW.claimed_at THEN
        RAISE EXCEPTION 'ledger job claim history is immutable' USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER ledger_job_claims_append_only
BEFORE UPDATE OR DELETE ON ledger_job_claims
FOR EACH ROW
EXECUTE FUNCTION ledger_job_claims_append_only();

CREATE TABLE ledger_outbox (
    event_id VARCHAR(96) NOT NULL,
    job_id VARCHAR(96) NOT NULL,
    event_type VARCHAR(64) NOT NULL,
    routing_key VARCHAR(128) NOT NULL,
    schema_version SMALLINT NOT NULL DEFAULT 1,
    idempotency_key VARCHAR(192) NOT NULL,
    status VARCHAR(16) NOT NULL DEFAULT 'queued',
    available_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    publish_attempts INTEGER NOT NULL DEFAULT 0,
    lease_until TIMESTAMP WITH TIME ZONE,
    published_at TIMESTAMP WITH TIME ZONE,
    last_error_code VARCHAR(64),
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (event_id),
    CONSTRAINT fk_ledger_outbox_job FOREIGN KEY (job_id) REFERENCES ledger_jobs (job_id),
    CONSTRAINT uq_ledger_outbox_job_type UNIQUE (job_id, event_type),
    CONSTRAINT uq_ledger_outbox_job_idempotency UNIQUE (job_id, idempotency_key),
    CONSTRAINT ck_ledger_outbox_event_id CHECK (length(event_id) BETWEEN 1 AND 96),
    CONSTRAINT ck_ledger_outbox_type CHECK (length(event_type) BETWEEN 1 AND 64),
    CONSTRAINT ck_ledger_outbox_route CHECK (length(routing_key) BETWEEN 1 AND 128),
    CONSTRAINT ck_ledger_outbox_idempotency CHECK (length(idempotency_key) BETWEEN 1 AND 192),
    CONSTRAINT ck_ledger_outbox_schema CHECK (schema_version > 0),
    CONSTRAINT ck_ledger_outbox_status CHECK (status IN ('queued', 'claimed', 'published', 'failed', 'uncertain')),
    CONSTRAINT ck_ledger_outbox_attempts CHECK (publish_attempts >= 0),
    CONSTRAINT ck_ledger_outbox_lease CHECK (status <> 'claimed' OR lease_until IS NOT NULL),
    CONSTRAINT ck_ledger_outbox_published CHECK (status <> 'published' OR published_at IS NOT NULL),
    CONSTRAINT ck_ledger_outbox_error_code CHECK (
        last_error_code IS NULL OR last_error_code ~ '^[a-z][a-z0-9_]{0,63}$'
    )
);

CREATE TABLE ledger_inbox (
    event_id VARCHAR(96) NOT NULL,
    consumer_name VARCHAR(128) NOT NULL,
    received_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    processed_at TIMESTAMP WITH TIME ZONE,
    result_code VARCHAR(64),
    PRIMARY KEY (event_id, consumer_name),
    CONSTRAINT fk_ledger_inbox_event FOREIGN KEY (event_id) REFERENCES ledger_outbox (event_id),
    CONSTRAINT ck_ledger_inbox_event_id CHECK (length(event_id) BETWEEN 1 AND 96),
    CONSTRAINT ck_ledger_inbox_consumer CHECK (length(consumer_name) BETWEEN 1 AND 128),
    CONSTRAINT ck_ledger_inbox_result CHECK (
        result_code IS NULL OR result_code ~ '^[a-z][a-z0-9_]{0,63}$'
    ),
    CONSTRAINT ck_ledger_inbox_completion CHECK (
        (processed_at IS NULL AND result_code IS NULL) OR (processed_at IS NOT NULL AND result_code IS NOT NULL)
    )
);

CREATE INDEX ix_ledger_jobs_due
    ON ledger_jobs (status, available_at)
    WHERE status IN ('queued', 'claimed', 'running');
CREATE INDEX ix_ledger_job_claims_lease
    ON ledger_job_claims (lease_until)
    WHERE completed_at IS NULL;
CREATE INDEX ix_ledger_outbox_pending
    ON ledger_outbox (status, available_at)
    WHERE status IN ('queued', 'failed');
CREATE INDEX ix_ledger_outbox_lease
    ON ledger_outbox (lease_until)
    WHERE status = 'claimed';
CREATE INDEX ix_ledger_inbox_unprocessed
    ON ledger_inbox (consumer_name, received_at)
    WHERE processed_at IS NULL;

COMMENT ON TABLE ledger_jobs IS
    'Durable parser jobs; references and aggregate counters only, with no source content.';
COMMENT ON TABLE ledger_job_claims IS
    'Append-only claim history; only one active lease may exist for a job.';
COMMENT ON TABLE ledger_outbox IS
    'Transactional handoff references for the message broker.';
COMMENT ON TABLE ledger_inbox IS
    'Consumer deduplication records keyed by event and consumer.';
