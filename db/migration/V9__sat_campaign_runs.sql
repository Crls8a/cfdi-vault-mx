-- V9 adds the durable queue of requested SAT campaign runs (ADR 0005).
-- PostgreSQL remains the source of truth: the RabbitMQ 'sat.campaign.run'
-- message is a wake hint only and carries no work item, exactly like the
-- V8 'sat_schedule_changed' NOTIFY. A consumer must always re-claim the row
-- from this table before contacting SAT.
--
-- A run row is never retried automatically. The reaper only moves an expired
-- lease to 'abandoned'; re-running a campaign is a new, human-requested row.
--
-- Manual rollback only, after the campaign-run consumer is stopped, the queue
-- is drained, and history is exported. Reverse order:
-- DROP TRIGGER sat_campaign_runs_validate_transition ON sat_campaign_runs;
-- DROP FUNCTION sat_campaign_runs_validate_transition();
-- DROP INDEX ix_sat_campaign_runs_campaign_requested;
-- DROP INDEX ix_sat_campaign_runs_lease;
-- DROP INDEX ix_sat_campaign_runs_queued;
-- DROP INDEX uq_sat_campaign_runs_active;
-- DROP TABLE sat_campaign_runs;

CREATE TABLE sat_campaign_runs (
    run_ref VARCHAR(96) NOT NULL,
    campaign_id INTEGER NOT NULL,
    grant_ref VARCHAR(96) NOT NULL,
    profile_ref VARCHAR(128) NOT NULL,
    commit_ref VARCHAR(128) NOT NULL,
    status VARCHAR(16) NOT NULL DEFAULT 'queued',
    requested_via VARCHAR(16) NOT NULL,
    requested_at TIMESTAMP WITH TIME ZONE NOT NULL,
    claimed_at TIMESTAMP WITH TIME ZONE,
    lease_until TIMESTAMP WITH TIME ZONE,
    finished_at TIMESTAMP WITH TIME ZONE,
    worker_ref VARCHAR(128),
    result_code VARCHAR(64),
    contacted_count INTEGER NOT NULL DEFAULT 0,
    submitted_count INTEGER NOT NULL DEFAULT 0,
    package_count INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (run_ref),
    CONSTRAINT fk_sat_campaign_runs_campaign FOREIGN KEY (campaign_id) REFERENCES sat_campaigns (id),
    CONSTRAINT ck_sat_campaign_runs_ref CHECK (length(run_ref) BETWEEN 1 AND 96),
    CONSTRAINT ck_sat_campaign_runs_status CHECK (status IN (
        'queued', 'claimed', 'running', 'succeeded', 'failed', 'abandoned'
    )),
    CONSTRAINT ck_sat_campaign_runs_requested_via CHECK (requested_via IN ('panel', 'cli')),
    CONSTRAINT ck_sat_campaign_runs_result CHECK (
        result_code IS NULL OR result_code ~ '^[a-z][a-z0-9._-]{0,63}$'
    ),
    CONSTRAINT ck_sat_campaign_runs_counts CHECK (
        contacted_count >= 0 AND submitted_count >= 0 AND package_count >= 0
    ),
    CONSTRAINT ck_sat_campaign_runs_claim CHECK (
        claimed_at IS NULL OR claimed_at >= requested_at
    ),
    CONSTRAINT ck_sat_campaign_runs_lease CHECK (
        lease_until IS NULL OR lease_until > requested_at
    ),
    CONSTRAINT ck_sat_campaign_runs_completion CHECK (
        (status IN ('succeeded', 'failed', 'abandoned')) = (finished_at IS NOT NULL)
    )
);

-- One active run per authorized grant. A double-clicked panel button and a
-- crash-retry both resolve to the row that already exists.
CREATE UNIQUE INDEX uq_sat_campaign_runs_active
    ON sat_campaign_runs (campaign_id, grant_ref)
    WHERE status IN ('queued', 'claimed', 'running');

-- Claim scan: oldest queued row first.
CREATE INDEX ix_sat_campaign_runs_queued
    ON sat_campaign_runs (requested_at, run_ref)
    WHERE status = 'queued';

-- Reaper scan: non-terminal rows whose lease has expired.
CREATE INDEX ix_sat_campaign_runs_lease
    ON sat_campaign_runs (lease_until)
    WHERE status IN ('queued', 'claimed', 'running');

-- Status projection: newest run for one campaign.
CREATE INDEX ix_sat_campaign_runs_campaign_requested
    ON sat_campaign_runs (campaign_id, requested_at, run_ref);

CREATE FUNCTION sat_campaign_runs_validate_transition()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF OLD.status IN ('succeeded', 'failed', 'abandoned') AND (
        NEW.run_ref IS DISTINCT FROM OLD.run_ref
        OR NEW.campaign_id IS DISTINCT FROM OLD.campaign_id
        OR NEW.grant_ref IS DISTINCT FROM OLD.grant_ref
        OR NEW.profile_ref IS DISTINCT FROM OLD.profile_ref
        OR NEW.commit_ref IS DISTINCT FROM OLD.commit_ref
        OR NEW.status IS DISTINCT FROM OLD.status
        OR NEW.requested_via IS DISTINCT FROM OLD.requested_via
        OR NEW.requested_at IS DISTINCT FROM OLD.requested_at
        OR NEW.claimed_at IS DISTINCT FROM OLD.claimed_at
        OR NEW.lease_until IS DISTINCT FROM OLD.lease_until
        OR NEW.finished_at IS DISTINCT FROM OLD.finished_at
        OR NEW.worker_ref IS DISTINCT FROM OLD.worker_ref
        OR NEW.result_code IS DISTINCT FROM OLD.result_code
        OR NEW.contacted_count IS DISTINCT FROM OLD.contacted_count
        OR NEW.submitted_count IS DISTINCT FROM OLD.submitted_count
        OR NEW.package_count IS DISTINCT FROM OLD.package_count
    ) THEN
        RAISE EXCEPTION 'sat campaign run terminal state is immutable' USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER sat_campaign_runs_validate_transition
BEFORE UPDATE ON sat_campaign_runs
FOR EACH ROW
EXECUTE FUNCTION sat_campaign_runs_validate_transition();

COMMENT ON TABLE sat_campaign_runs IS
    'Durable requested campaign runs; opaque references and aggregate counters only.';
COMMENT ON FUNCTION sat_campaign_runs_validate_transition() IS
    'Terminal campaign-run rows are immutable; a new run requires a new human request.';
