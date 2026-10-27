-- Additive provenance; legacy and manually reviewed records retain their semantics.
ALTER TABLE securescope_evidence_records
    ADD COLUMN IF NOT EXISTS source_key TEXT,
    ADD COLUMN IF NOT EXISTS verification_origin TEXT NOT NULL DEFAULT 'Human review';
ALTER TABLE securescope_evidence_records
    ADD CONSTRAINT evidence_verification_origin_check
    CHECK (verification_origin IN ('Human review', 'System collector'));
CREATE UNIQUE INDEX IF NOT EXISTS evidence_unique_system_source
    ON securescope_evidence_records(client_id, tool_id, source_key)
    WHERE source_key IS NOT NULL;
ALTER TABLE securescope_evidence_control_mappings
    DROP CONSTRAINT IF EXISTS securescope_evidence_control_mappings_mapping_origin_check;
ALTER TABLE securescope_evidence_control_mappings
    ADD CONSTRAINT securescope_evidence_control_mappings_mapping_origin_check
    CHECK (mapping_origin IN ('Catalog suggestion', 'Consultant mapping', 'Automated check'));
ALTER TABLE securescope_engagement_record_links
    DROP CONSTRAINT IF EXISTS securescope_engagement_record_links_link_origin_check;
ALTER TABLE securescope_engagement_record_links
    ADD CONSTRAINT securescope_engagement_record_links_link_origin_check
    CHECK (link_origin IN ('Legacy backfill', 'Manual association', 'Scope inheritance', 'Automated collection'));
