-- Accounting ledger V5: additive, tenant-safe, evidence-aware child rows.
-- Flyway owns this migration. V1–V4 remain untouched and legacy columns remain
-- available during the explicit backfill/review transition.
-- Legacy standalone child foreign keys from V1 are intentionally retained during this
-- transition. A future backfill must prove one tenant/parent match and
-- validate composite foreign keys before removing the standalone FKs.
--
-- Manual rollback only (after writers stop, queues drain, counts are captured,
-- and a backup is verified): remove the V5 indexes, checks, composite foreign
-- keys, and child columns in reverse dependency order; remove the parent keys
-- from xml_evidence and cfdi_documents last. Never remove evidence, artifacts,
-- legacy rows, or audit history. V1–V4 are not modified by rollback.
-- Before restoring legacy NOT NULL, audit/backfill NULLs in
-- cfdi_concepts.raw_payload, cfdi_payments.document_uuid/raw_payload,
-- cfdi_payroll.document_uuid/raw_payload, cfdi_taxes.document_uuid, and
-- cfdi_related_documents.document_uuid. If any V5 row remains NULL, rollback
-- stops for manual review and does not restore the legacy constraint.

ALTER TABLE cfdi_documents
    ADD CONSTRAINT uq_cfdi_documents_tenant_id UNIQUE (tenant_id, id);
ALTER TABLE xml_evidence
    ADD CONSTRAINT uq_xml_evidence_tenant_id UNIQUE (tenant_id, id);
ALTER TABLE cfdi_concepts
    ADD COLUMN tenant_id VARCHAR(64),
    ADD COLUMN source_evidence_id INTEGER,
    ADD COLUMN source_sha256 VARCHAR(64),
    ADD COLUMN parser_version VARCHAR(32),
    ADD COLUMN parser_status VARCHAR(32),
    ADD COLUMN source_ordinal INTEGER,
    ADD COLUMN normalization_generation VARCHAR(64),
    ADD COLUMN idempotency_key VARCHAR(192),
    ADD CONSTRAINT fk_cfdi_concepts_v5_tenant_document
        FOREIGN KEY (tenant_id, document_id)
        REFERENCES cfdi_documents (tenant_id, id) NOT VALID,
    ADD CONSTRAINT fk_cfdi_concepts_v5_tenant_evidence
        FOREIGN KEY (tenant_id, source_evidence_id)
        REFERENCES xml_evidence (tenant_id, id) NOT VALID,
    ADD CONSTRAINT ck_cfdi_concepts_v5_hash
        CHECK (source_sha256 IS NULL OR source_sha256 ~ '^[0-9a-f]{64}$') NOT VALID,
    ADD CONSTRAINT ck_cfdi_concepts_v5_ordinal
        CHECK (source_ordinal IS NULL OR source_ordinal > 0) NOT VALID,
    ADD CONSTRAINT ck_cfdi_concepts_v5_generation
        CHECK (normalization_generation IS NULL OR length(normalization_generation) BETWEEN 1 AND 64) NOT VALID,
    ADD CONSTRAINT ck_cfdi_concepts_v5_idempotency
        CHECK (idempotency_key IS NULL OR length(idempotency_key) BETWEEN 1 AND 192) NOT VALID,
    ADD CONSTRAINT ck_cfdi_concepts_v5_required
        CHECK (tenant_id IS NOT NULL AND source_evidence_id IS NOT NULL AND source_sha256 IS NOT NULL
            AND source_ordinal IS NOT NULL AND normalization_generation IS NOT NULL
            AND idempotency_key IS NOT NULL) NOT VALID;

ALTER TABLE cfdi_concepts
    ADD CONSTRAINT uq_cfdi_concepts_tenant_id UNIQUE (tenant_id, id);
ALTER TABLE cfdi_concepts
    ADD CONSTRAINT uq_cfdi_concepts_tenant_id_document UNIQUE (tenant_id, id, document_id);

ALTER TABLE cfdi_taxes
    ADD COLUMN tenant_id VARCHAR(64),
    ADD COLUMN document_id INTEGER,
    ADD COLUMN source_evidence_id INTEGER,
    ADD COLUMN source_sha256 VARCHAR(64),
    ADD COLUMN parser_version VARCHAR(32),
    ADD COLUMN parser_status VARCHAR(32),
    ADD COLUMN source_ordinal INTEGER,
    ADD COLUMN normalization_generation VARCHAR(64),
    ADD COLUMN idempotency_key VARCHAR(192),
    ADD COLUMN scope VARCHAR(16),
    ADD COLUMN concept_ordinal INTEGER,
    ADD CONSTRAINT fk_cfdi_taxes_v5_tenant_document
        FOREIGN KEY (tenant_id, document_id)
        REFERENCES cfdi_documents (tenant_id, id) NOT VALID,
    ADD CONSTRAINT fk_cfdi_taxes_v5_tenant_concept
        FOREIGN KEY (tenant_id, concept_id, document_id)
        REFERENCES cfdi_concepts (tenant_id, id, document_id) NOT VALID,
    ADD CONSTRAINT fk_cfdi_taxes_v5_tenant_evidence
        FOREIGN KEY (tenant_id, source_evidence_id)
        REFERENCES xml_evidence (tenant_id, id) NOT VALID,
    ADD CONSTRAINT ck_cfdi_taxes_v5_scope
        CHECK (scope IS NULL OR scope IN ('concept', 'document')) NOT VALID,
    ADD CONSTRAINT ck_cfdi_taxes_v5_scope_ordinal
        CHECK (scope IS NULL OR (scope = 'document' AND concept_id IS NULL AND concept_ordinal IS NULL)
            OR (scope = 'concept' AND concept_id IS NOT NULL AND concept_ordinal > 0)) NOT VALID,
    ADD CONSTRAINT ck_cfdi_taxes_v5_hash
        CHECK (source_sha256 IS NULL OR source_sha256 ~ '^[0-9a-f]{64}$') NOT VALID,
    ADD CONSTRAINT ck_cfdi_taxes_v5_ordinal
        CHECK (source_ordinal IS NULL OR source_ordinal > 0) NOT VALID,
    ADD CONSTRAINT ck_cfdi_taxes_v5_generation
        CHECK (normalization_generation IS NULL OR length(normalization_generation) BETWEEN 1 AND 64) NOT VALID,
    ADD CONSTRAINT ck_cfdi_taxes_v5_idempotency
        CHECK (idempotency_key IS NULL OR length(idempotency_key) BETWEEN 1 AND 192) NOT VALID,
    ADD CONSTRAINT ck_cfdi_taxes_v5_required
        CHECK (tenant_id IS NOT NULL AND document_id IS NOT NULL AND source_evidence_id IS NOT NULL
            AND source_sha256 IS NOT NULL AND source_ordinal IS NOT NULL
            AND normalization_generation IS NOT NULL AND idempotency_key IS NOT NULL
            AND scope IS NOT NULL) NOT VALID;

ALTER TABLE cfdi_payments
    ADD COLUMN tenant_id VARCHAR(64),
    ADD COLUMN document_id INTEGER,
    ADD COLUMN exchange_rate NUMERIC(18, 8),
    ADD COLUMN payment_ordinal INTEGER,
    ADD COLUMN source_evidence_id INTEGER,
    ADD COLUMN source_sha256 VARCHAR(64),
    ADD COLUMN parser_version VARCHAR(32),
    ADD COLUMN parser_status VARCHAR(32),
    ADD COLUMN normalization_generation VARCHAR(64),
    ADD COLUMN idempotency_key VARCHAR(192),
    ADD CONSTRAINT fk_cfdi_payments_v5_tenant_document
        FOREIGN KEY (tenant_id, document_id)
        REFERENCES cfdi_documents (tenant_id, id) NOT VALID,
    ADD CONSTRAINT fk_cfdi_payments_v5_tenant_evidence
        FOREIGN KEY (tenant_id, source_evidence_id)
        REFERENCES xml_evidence (tenant_id, id) NOT VALID,
    ADD CONSTRAINT ck_cfdi_payments_v5_currency
        CHECK (currency IS NULL OR (currency = 'MXN' AND exchange_rate IS NULL)
            OR (currency <> 'MXN' AND exchange_rate IS NOT NULL AND exchange_rate > 0)) NOT VALID,
    ADD CONSTRAINT ck_cfdi_payments_v5_ordinal
        CHECK (payment_ordinal IS NULL OR payment_ordinal > 0) NOT VALID,
    ADD CONSTRAINT ck_cfdi_payments_v5_hash
        CHECK (source_sha256 IS NULL OR source_sha256 ~ '^[0-9a-f]{64}$') NOT VALID,
    ADD CONSTRAINT ck_cfdi_payments_v5_generation
        CHECK (normalization_generation IS NULL OR length(normalization_generation) BETWEEN 1 AND 64) NOT VALID,
    ADD CONSTRAINT ck_cfdi_payments_v5_idempotency
        CHECK (idempotency_key IS NULL OR length(idempotency_key) BETWEEN 1 AND 192) NOT VALID,
    ADD CONSTRAINT ck_cfdi_payments_v5_required
        CHECK (tenant_id IS NOT NULL AND document_id IS NOT NULL AND source_evidence_id IS NOT NULL
            AND source_sha256 IS NOT NULL AND payment_ordinal IS NOT NULL
            AND normalization_generation IS NOT NULL AND idempotency_key IS NOT NULL) NOT VALID;

ALTER TABLE cfdi_payroll
    ADD COLUMN tenant_id VARCHAR(64),
    ADD COLUMN document_id INTEGER,
    ADD COLUMN total_perceptions NUMERIC(18, 6),
    ADD COLUMN total_deductions NUMERIC(18, 6),
    ADD COLUMN total_other_payments NUMERIC(18, 6),
    ADD COLUMN source_net_amount NUMERIC(18, 6),
    ADD COLUMN currency VARCHAR(8),
    ADD COLUMN source_period_type VARCHAR(32),
    ADD COLUMN source_evidence_id INTEGER,
    ADD COLUMN source_sha256 VARCHAR(64),
    ADD COLUMN parser_version VARCHAR(32),
    ADD COLUMN parser_status VARCHAR(32),
    ADD COLUMN payroll_ordinal INTEGER,
    ADD COLUMN normalization_generation VARCHAR(64),
    ADD COLUMN idempotency_key VARCHAR(192),
    ADD CONSTRAINT fk_cfdi_payroll_v5_tenant_document
        FOREIGN KEY (tenant_id, document_id)
        REFERENCES cfdi_documents (tenant_id, id) NOT VALID,
    ADD CONSTRAINT fk_cfdi_payroll_v5_tenant_evidence
        FOREIGN KEY (tenant_id, source_evidence_id)
        REFERENCES xml_evidence (tenant_id, id) NOT VALID,
    ADD CONSTRAINT ck_cfdi_payroll_v5_hash
        CHECK (source_sha256 IS NULL OR source_sha256 ~ '^[0-9a-f]{64}$') NOT VALID,
    ADD CONSTRAINT ck_cfdi_payroll_v5_ordinal
        CHECK (payroll_ordinal IS NULL OR payroll_ordinal > 0) NOT VALID,
    ADD CONSTRAINT ck_cfdi_payroll_v5_generation
        CHECK (normalization_generation IS NULL OR length(normalization_generation) BETWEEN 1 AND 64) NOT VALID,
    ADD CONSTRAINT ck_cfdi_payroll_v5_idempotency
        CHECK (idempotency_key IS NULL OR length(idempotency_key) BETWEEN 1 AND 192) NOT VALID,
    ADD CONSTRAINT ck_cfdi_payroll_v5_required
        CHECK (tenant_id IS NOT NULL AND document_id IS NOT NULL AND source_evidence_id IS NOT NULL
            AND source_sha256 IS NOT NULL AND payroll_ordinal IS NOT NULL
            AND normalization_generation IS NOT NULL AND idempotency_key IS NOT NULL) NOT VALID;

ALTER TABLE cfdi_related_documents
    ADD COLUMN tenant_id VARCHAR(64),
    ADD COLUMN document_id INTEGER,
    ADD COLUMN source_evidence_id INTEGER,
    ADD COLUMN source_sha256 VARCHAR(64),
    ADD COLUMN parser_version VARCHAR(32),
    ADD COLUMN parser_status VARCHAR(32),
    ADD COLUMN related_ordinal INTEGER,
    ADD COLUMN payment_ordinal INTEGER,
    ADD COLUMN applied_amount NUMERIC(18, 6),
    ADD COLUMN installment_number INTEGER,
    ADD COLUMN currency VARCHAR(8),
    ADD COLUMN normalization_generation VARCHAR(64),
    ADD COLUMN idempotency_key VARCHAR(192),
    ADD CONSTRAINT fk_cfdi_related_v5_tenant_document
        FOREIGN KEY (tenant_id, document_id)
        REFERENCES cfdi_documents (tenant_id, id) NOT VALID,
    ADD CONSTRAINT fk_cfdi_related_v5_tenant_evidence
        FOREIGN KEY (tenant_id, source_evidence_id)
        REFERENCES xml_evidence (tenant_id, id) NOT VALID,
    ADD CONSTRAINT ck_cfdi_related_v5_hash
        CHECK (source_sha256 IS NULL OR source_sha256 ~ '^[0-9a-f]{64}$') NOT VALID,
    ADD CONSTRAINT ck_cfdi_related_v5_related_ordinal
        CHECK (related_ordinal IS NULL OR related_ordinal > 0) NOT VALID,
    ADD CONSTRAINT ck_cfdi_related_v5_payment_ordinal
        CHECK (payment_ordinal IS NULL OR payment_ordinal > 0) NOT VALID,
    ADD CONSTRAINT ck_cfdi_related_v5_installment
        CHECK (installment_number IS NULL OR installment_number > 0) NOT VALID,
    ADD CONSTRAINT ck_cfdi_related_v5_generation
        CHECK (normalization_generation IS NULL OR length(normalization_generation) BETWEEN 1 AND 64) NOT VALID,
    ADD CONSTRAINT ck_cfdi_related_v5_idempotency
        CHECK (idempotency_key IS NULL OR length(idempotency_key) BETWEEN 1 AND 192) NOT VALID,
    ADD CONSTRAINT ck_cfdi_related_v5_payment_identity
        CHECK ((payment_ordinal IS NULL AND applied_amount IS NULL AND installment_number IS NULL)
            OR (payment_ordinal IS NOT NULL AND payment_ordinal > 0)) NOT VALID,
    ADD CONSTRAINT ck_cfdi_related_v5_required
        CHECK (tenant_id IS NOT NULL AND document_id IS NOT NULL AND source_evidence_id IS NOT NULL
            AND source_sha256 IS NOT NULL AND related_ordinal IS NOT NULL
            AND normalization_generation IS NOT NULL AND idempotency_key IS NOT NULL
            AND (payment_ordinal IS NULL OR payment_ordinal > 0)) NOT VALID;

-- V5 writers use tenant/document/evidence columns and keep legacy payload and
-- document UUID fields nullable during the explicit backfill transition.
ALTER TABLE cfdi_concepts ALTER COLUMN raw_payload DROP NOT NULL;
ALTER TABLE cfdi_payments ALTER COLUMN document_uuid DROP NOT NULL, ALTER COLUMN raw_payload DROP NOT NULL;
ALTER TABLE cfdi_payroll ALTER COLUMN document_uuid DROP NOT NULL, ALTER COLUMN raw_payload DROP NOT NULL;
ALTER TABLE cfdi_taxes ALTER COLUMN document_uuid DROP NOT NULL;
ALTER TABLE cfdi_related_documents ALTER COLUMN document_uuid DROP NOT NULL;

CREATE UNIQUE INDEX uq_cfdi_concepts_v5_identity
    ON cfdi_concepts (tenant_id, document_id, source_sha256, normalization_generation, source_ordinal);
CREATE UNIQUE INDEX uq_cfdi_taxes_v5_concept_identity
    ON cfdi_taxes (tenant_id, document_id, source_sha256, normalization_generation, concept_ordinal, source_ordinal)
    WHERE scope = 'concept';
CREATE UNIQUE INDEX uq_cfdi_taxes_v5_document_identity
    ON cfdi_taxes (tenant_id, document_id, source_sha256, normalization_generation, source_ordinal)
    WHERE scope = 'document';
CREATE UNIQUE INDEX uq_cfdi_payments_v5_identity
    ON cfdi_payments (tenant_id, document_id, source_sha256, normalization_generation, payment_ordinal);
CREATE UNIQUE INDEX uq_cfdi_payroll_v5_identity
    ON cfdi_payroll (tenant_id, document_id, source_sha256, normalization_generation, payroll_ordinal);
CREATE UNIQUE INDEX uq_cfdi_related_documents_v5_identity
    ON cfdi_related_documents (tenant_id, document_id, source_sha256, normalization_generation, related_ordinal)
    WHERE payment_ordinal IS NULL;
CREATE UNIQUE INDEX uq_cfdi_related_documents_v5_payment_identity
    ON cfdi_related_documents
        (tenant_id, document_id, source_sha256, normalization_generation, payment_ordinal, related_ordinal)
    WHERE payment_ordinal IS NOT NULL;

CREATE INDEX ix_cfdi_concepts_v5_scope
    ON cfdi_concepts (tenant_id, document_id, source_sha256, normalization_generation);
CREATE INDEX ix_cfdi_taxes_v5_scope
    ON cfdi_taxes (tenant_id, document_id, source_sha256, normalization_generation);
CREATE INDEX ix_cfdi_payments_v5_scope
    ON cfdi_payments (tenant_id, document_id, source_sha256, normalization_generation);
CREATE INDEX ix_cfdi_payroll_v5_scope
    ON cfdi_payroll (tenant_id, document_id, source_sha256, normalization_generation);
CREATE INDEX ix_cfdi_related_documents_v5_scope
    ON cfdi_related_documents (tenant_id, document_id, source_sha256, normalization_generation);

COMMENT ON TABLE cfdi_concepts IS
    'V5 writes require tenant, evidence hash, ordinal, generation, and exact idempotency key.';
COMMENT ON TABLE cfdi_taxes IS
    'V5 tax identity is explicitly concept-scoped or document-scoped; legacy rows remain transitional.';
COMMENT ON TABLE cfdi_payments IS
    'V5 exchange-rate checks preserve missing source values as incomplete rather than inferred.';
COMMENT ON TABLE cfdi_related_documents IS
    'General relations use related_ordinal; payment relations additionally require payment_ordinal. '
    'Legacy rows remain transitional until the composite FK backfill is validated.';
