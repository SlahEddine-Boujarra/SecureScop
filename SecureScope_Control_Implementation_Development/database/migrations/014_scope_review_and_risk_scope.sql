-- Preserve existing scope versions; new reviews have explicit decision metadata.
ALTER TABLE securescope_scope_versions
    DROP CONSTRAINT IF EXISTS securescope_scope_versions_status_check;
ALTER TABLE securescope_scope_versions
    ADD CONSTRAINT securescope_scope_versions_status_check CHECK (status IN (
        'Draft', 'Under review', 'Reviewed', 'Changes requested',
        'Approved', 'Rejected', 'Superseded'
    ));
ALTER TABLE securescope_scope_versions
    ADD COLUMN IF NOT EXISTS submitted_by TEXT,
    ADD COLUMN IF NOT EXISTS submitted_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS submission_rationale TEXT,
    ADD COLUMN IF NOT EXISTS reviewed_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS review_rationale TEXT;

-- A risk references a scope, not a copy of that scope. Legacy risks remain NULL.
ALTER TABLE securescope_risk_register ADD COLUMN IF NOT EXISTS primary_scope_id BIGINT;
ALTER TABLE securescope_risk_register
    ADD CONSTRAINT securescope_risk_primary_scope_fk
    FOREIGN KEY (client_id, primary_scope_id)
    REFERENCES securescope_scope_definitions(client_id, id);
CREATE INDEX IF NOT EXISTS idx_risk_primary_scope
    ON securescope_risk_register(client_id, primary_scope_id);

CREATE OR REPLACE FUNCTION securescope_enforce_scope_review()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.status = 'Approved' AND OLD.status <> 'Approved' THEN
        IF OLD.status <> 'Reviewed' OR OLD.reviewed_at IS NULL
           OR NULLIF(btrim(OLD.review_rationale), '') IS NULL THEN
            RAISE EXCEPTION 'A recorded review is required before scope approval';
        END IF;
    END IF;
    IF NEW.status = 'Reviewed' AND OLD.status <> 'Reviewed' THEN
        IF OLD.status <> 'Under review' OR NEW.reviewed_by IS NULL
           OR NEW.reviewed_at IS NULL OR NULLIF(btrim(NEW.review_rationale), '') IS NULL THEN
            RAISE EXCEPTION 'Submit the scope and record a reviewer and rationale first';
        END IF;
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER trg_securescope_scope_review_transition
BEFORE UPDATE ON securescope_scope_versions
FOR EACH ROW EXECUTE FUNCTION securescope_enforce_scope_review();
