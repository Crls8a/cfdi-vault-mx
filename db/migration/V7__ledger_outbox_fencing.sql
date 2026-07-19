-- V7 adds durable ownership fencing for outbox publication.
-- Existing rows remain readable during the transition; new claimed rows must
-- carry both an opaque claim token and the claiming worker reference.
--
-- Manual rollback only after publishers stop and leases are audited:
-- ALTER TABLE ledger_outbox DROP CONSTRAINT uq_ledger_outbox_claim_id;
-- ALTER TABLE ledger_outbox DROP CONSTRAINT ck_ledger_outbox_claim_fields,
--     DROP CONSTRAINT ck_ledger_outbox_claimed_by,
--     DROP CONSTRAINT ck_ledger_outbox_claim_id,
--     DROP COLUMN claimed_by, DROP COLUMN claim_id;

ALTER TABLE ledger_outbox
    ADD COLUMN claim_id VARCHAR(96),
    ADD COLUMN claimed_by VARCHAR(128),
    ADD CONSTRAINT uq_ledger_outbox_claim_id UNIQUE (claim_id),
    ADD CONSTRAINT ck_ledger_outbox_claim_id
        CHECK (claim_id IS NULL OR length(claim_id) BETWEEN 1 AND 96) NOT VALID,
    ADD CONSTRAINT ck_ledger_outbox_claimed_by
        CHECK (claimed_by IS NULL OR length(claimed_by) BETWEEN 1 AND 128) NOT VALID,
    ADD CONSTRAINT ck_ledger_outbox_claim_fields
        CHECK (
            (status = 'claimed' AND claim_id IS NOT NULL AND claimed_by IS NOT NULL)
            OR (status <> 'claimed' AND claim_id IS NULL AND claimed_by IS NULL)
        ) NOT VALID;
