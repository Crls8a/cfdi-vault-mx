-- V8 adds durable, sanitized monitor-cycle history and a non-durable wake hint.
-- PostgreSQL remains the source of truth: NOTIFY carries no row data and may be
-- lost or coalesced. The monitor must recompute due work after every wake.
--
-- Manual rollback only after the monitor is disabled and history is exported:
-- DROP TRIGGER sat_requests_schedule_changed ON sat_requests;
-- DROP FUNCTION sat_requests_schedule_changed();
-- DROP TRIGGER sat_monitor_runs_append_only ON sat_monitor_runs;
-- DROP FUNCTION sat_monitor_runs_append_only();
-- DROP TABLE sat_monitor_runs;

CREATE TABLE sat_monitor_runs (
    id BIGSERIAL PRIMARY KEY,
    run_ref VARCHAR(96) NOT NULL UNIQUE,
    started_at TIMESTAMP WITH TIME ZONE NOT NULL,
    finished_at TIMESTAMP WITH TIME ZONE NOT NULL,
    wake_reason VARCHAR(32) NOT NULL,
    due_count INTEGER NOT NULL DEFAULT 0,
    contacted_count INTEGER NOT NULL DEFAULT 0,
    package_count INTEGER NOT NULL DEFAULT 0,
    no_data_count INTEGER NOT NULL DEFAULT 0,
    error_count INTEGER NOT NULL DEFAULT 0,
    terminal_category VARCHAR(32),
    duration_ms INTEGER NOT NULL,
    watchdog_wake BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL,
    CONSTRAINT ck_sat_monitor_runs_ref CHECK (length(run_ref) BETWEEN 1 AND 96),
    CONSTRAINT ck_sat_monitor_runs_time CHECK (finished_at >= started_at),
    CONSTRAINT ck_sat_monitor_runs_reason CHECK (
        wake_reason IN ('startup', 'schedule_changed', 'watchdog', 'reconnect', 'manual', 'unknown')
    ),
    CONSTRAINT ck_sat_monitor_runs_counts CHECK (
        due_count >= 0 AND contacted_count >= 0 AND package_count >= 0
        AND no_data_count >= 0 AND error_count >= 0 AND duration_ms >= 0
    ),
    CONSTRAINT ck_sat_monitor_runs_terminal CHECK (
        terminal_category IS NULL OR terminal_category ~ '^[a-z][a-z0-9._-]{0,31}$'
    )
);

CREATE INDEX ix_sat_monitor_runs_started_at
    ON sat_monitor_runs (started_at DESC, id DESC);

CREATE FUNCTION sat_monitor_runs_append_only()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'sat monitor history is append-only' USING ERRCODE = 'check_violation';
END;
$$;

CREATE TRIGGER sat_monitor_runs_append_only
BEFORE UPDATE OR DELETE ON sat_monitor_runs
FOR EACH ROW
EXECUTE FUNCTION sat_monitor_runs_append_only();

CREATE FUNCTION sat_requests_schedule_changed()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'INSERT' OR NEW.next_check_at IS DISTINCT FROM OLD.next_check_at THEN
        PERFORM pg_notify('sat_schedule_changed', '');
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER sat_requests_schedule_changed
AFTER INSERT OR UPDATE OF next_check_at ON sat_requests
FOR EACH ROW
EXECUTE FUNCTION sat_requests_schedule_changed();

COMMENT ON TABLE sat_monitor_runs IS
    'Append-only sanitized monitor-cycle aggregates; no fiscal or transport payloads.';
COMMENT ON FUNCTION sat_requests_schedule_changed() IS
    'Non-durable wake hint; consumers must recompute due work from PostgreSQL.';
