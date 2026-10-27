-- Drafts retain justification; formal exclusion approval remains mandatory on approval.
DO $$
DECLARE constraint_name TEXT;
BEGIN
    FOR constraint_name IN
        SELECT conname FROM pg_constraint WHERE conrelid='securescope_soa_items'::regclass
        AND contype='c' AND pg_get_constraintdef(oid) LIKE '%exclusion_justification%'
    LOOP
        EXECUTE format('ALTER TABLE securescope_soa_items DROP CONSTRAINT %I', constraint_name);
    END LOOP;
END $$;
ALTER TABLE securescope_soa_items ADD CONSTRAINT soa_item_justification_required CHECK (
    (applicability='Applicable' AND length(btrim(coalesce(inclusion_justification,'')))>0)
    OR (applicability='Not applicable' AND length(btrim(coalesce(exclusion_justification,'')))>0)
) NOT VALID;
-- Keep historical rows available during upgrade; new and changed rows are checked.
CREATE OR REPLACE FUNCTION securescope_guard_approved_soa_exclusions() RETURNS trigger AS $$
DECLARE version_id BIGINT;
BEGIN
    IF TG_TABLE_NAME='securescope_soa_items' THEN
        version_id := NEW.soa_version_id;
    ELSE
        version_id := NEW.id;
    END IF;
    IF EXISTS (SELECT 1 FROM securescope_soa_versions v
               JOIN securescope_soa_items i ON i.client_id=v.client_id AND i.soa_version_id=v.id
               WHERE v.id=version_id AND v.status='Approved'
               AND i.applicability='Not applicable' AND NOT i.approved) THEN
        RAISE EXCEPTION 'Approved SoA exclusions require formal approval';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
CREATE CONSTRAINT TRIGGER soa_exclusion_approval_items
AFTER INSERT OR UPDATE ON securescope_soa_items DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION securescope_guard_approved_soa_exclusions();
CREATE CONSTRAINT TRIGGER soa_exclusion_approval_versions
AFTER INSERT OR UPDATE ON securescope_soa_versions DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION securescope_guard_approved_soa_exclusions();
