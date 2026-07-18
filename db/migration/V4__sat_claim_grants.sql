-- SAT-LIVE-WORKER-001: bind every new external-effect claim to its grant.
-- Existing legacy rows remain nullable and are never reused for new contact.

ALTER TABLE sat_grants
    ADD CONSTRAINT uq_sat_grants_campaign_ref UNIQUE (campaign_id, grant_ref);

ALTER TABLE sat_requests
    ADD COLUMN grant_ref VARCHAR(96),
    ADD CONSTRAINT fk_sat_requests_campaign_grant
        FOREIGN KEY (campaign_id, grant_ref)
        REFERENCES sat_grants (campaign_id, grant_ref);

ALTER TABLE sat_claims
    ADD COLUMN grant_ref VARCHAR(96),
    ADD CONSTRAINT fk_sat_claims_campaign_grant
        FOREIGN KEY (campaign_id, grant_ref)
        REFERENCES sat_grants (campaign_id, grant_ref);

CREATE INDEX ix_sat_claims_campaign_grant_active
    ON sat_claims (campaign_id, grant_ref, active)
    WHERE active;

CREATE INDEX ix_sat_requests_campaign_grant
    ON sat_requests (campaign_id, grant_ref);

-- Rollback (manual, only after all linked claims are terminal):
-- DROP INDEX ix_sat_requests_campaign_grant;
-- DROP INDEX ix_sat_claims_campaign_grant_active;
-- ALTER TABLE sat_claims DROP CONSTRAINT fk_sat_claims_campaign_grant, DROP COLUMN grant_ref;
-- ALTER TABLE sat_requests DROP CONSTRAINT fk_sat_requests_campaign_grant, DROP COLUMN grant_ref;
-- ALTER TABLE sat_grants DROP CONSTRAINT uq_sat_grants_campaign_ref;
