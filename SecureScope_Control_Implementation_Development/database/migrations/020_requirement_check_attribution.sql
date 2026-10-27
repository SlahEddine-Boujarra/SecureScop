-- Exact immutable Nuclei criterion attribution; no historical backfill or decision writes.
CREATE UNIQUE INDEX IF NOT EXISTS m3_asset_owner_identity ON securescope_assets(client_id,id);
CREATE TABLE IF NOT EXISTS securescope_nuclei_requirement_sources (
    client_id BIGINT NOT NULL,
    evidence_id BIGINT NOT NULL,
    artifact_id BIGINT NOT NULL,
    asset_id BIGINT NOT NULL,
    source_key TEXT NOT NULL,
    observed_at TIMESTAMPTZ NOT NULL,
    artifact_sha256 CHAR(64) NOT NULL,
    facts JSONB NOT NULL,
    facts_sha256 CHAR(64) NOT NULL,
    rule_version INTEGER NOT NULL CHECK (rule_version=3),
    PRIMARY KEY (client_id,evidence_id),
    FOREIGN KEY (client_id,evidence_id) REFERENCES securescope_evidence_records(client_id,id),
    FOREIGN KEY (client_id,artifact_id) REFERENCES securescope_evidence_artifacts(client_id,id),
    FOREIGN KEY (client_id,asset_id) REFERENCES securescope_assets(client_id,id)
);
CREATE TABLE IF NOT EXISTS securescope_requirement_check_attributions (
    id BIGSERIAL PRIMARY KEY,
    client_id BIGINT NOT NULL,
    evidence_id BIGINT NOT NULL,
    profile_id BIGINT NOT NULL,
    engagement_id BIGINT NOT NULL,
    scope_id BIGINT NOT NULL,
    scope_version_id BIGINT NOT NULL,
    requirement_id TEXT NOT NULL,
    asset_id BIGINT NOT NULL,
    rule_version INTEGER NOT NULL CHECK (rule_version=3),
    requirement_sha256 CHAR(64) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (client_id,evidence_id,profile_id,requirement_id,asset_id),
    FOREIGN KEY (client_id,evidence_id) REFERENCES securescope_nuclei_requirement_sources(client_id,evidence_id),
    FOREIGN KEY (client_id,profile_id) REFERENCES securescope_control_assessment_profiles(client_id,id),
    FOREIGN KEY (client_id,engagement_id) REFERENCES securescope_engagements(client_id,id),
    FOREIGN KEY (client_id,scope_id) REFERENCES securescope_scope_definitions(client_id,id),
    FOREIGN KEY (client_id,scope_version_id) REFERENCES securescope_scope_versions(client_id,id),
    FOREIGN KEY (client_id,asset_id) REFERENCES securescope_assets(client_id,id)
);
CREATE INDEX IF NOT EXISTS requirement_attribution_context ON
    securescope_requirement_check_attributions(client_id,scope_id,profile_id,evidence_id);
CREATE OR REPLACE FUNCTION securescope_m3_source_guard() RETURNS trigger AS $$
BEGIN
    IF TG_OP <> 'INSERT' THEN RAISE EXCEPTION 'M3 source history is append-only'; END IF;
    IF NOT EXISTS (SELECT 1 FROM securescope_evidence_records e
        JOIN securescope_evidence_artifacts a ON a.client_id=e.client_id AND a.id=e.artifact_id
        WHERE e.client_id=NEW.client_id AND e.id=NEW.evidence_id AND e.tool_id='nuclei'
          AND e.source_key=NEW.source_key AND e.collected_at=NEW.observed_at
          AND e.verification_origin='System collector' AND e.validator='system:nuclei-worker'
          AND a.id=NEW.artifact_id AND a.sha256=NEW.artifact_sha256
          AND e.normalized_payload->'metadata'->'provenance'->>'asset_id'=NEW.asset_id::text
          AND NEW.facts->>'asset_id'=NEW.asset_id::text) THEN
        RAISE EXCEPTION 'M3 source ownership or identity mismatch';
    END IF;
    RETURN NEW;
END $$ LANGUAGE plpgsql;
CREATE OR REPLACE FUNCTION securescope_m3_attribution_guard() RETURNS trigger AS $$
BEGIN
    IF TG_OP <> 'INSERT' THEN RAISE EXCEPTION 'M3 attribution history is append-only'; END IF;
    IF NOT EXISTS (SELECT 1 FROM securescope_control_assessment_profiles p
        JOIN securescope_scope_definitions s ON s.client_id=p.client_id AND s.id=NEW.scope_id
        JOIN securescope_scope_versions v ON v.client_id=s.client_id AND v.scope_id=s.id
            AND v.id=s.current_approved_version_id AND v.id=NEW.scope_version_id
        JOIN securescope_nuclei_requirement_sources x ON x.client_id=p.client_id
            AND x.evidence_id=NEW.evidence_id AND x.asset_id=NEW.asset_id
        JOIN securescope_engagements g ON g.client_id=s.client_id AND g.id=s.engagement_id
        CROSS JOIN LATERAL jsonb_array_elements(p.assessment_scope->'implementation_requirements'->'requirements') r
        WHERE p.client_id=NEW.client_id AND p.id=NEW.profile_id AND v.status='Approved'
          AND NOT s.archived AND s.engagement_id=NEW.engagement_id
          AND g.status NOT IN ('Completed','Cancelled')
          AND p.control_id IN ('A.8.8','A.8.9','A.8.24','A.8.5')
          AND p.assessment_scope->'implementation_requirements'->>'reviewed'='true'
          AND COALESCE(p.assessment_scope->'implementation_requirements'->>'baseline_review_pending','false')='false'
          AND COALESCE(p.assessment_scope->'implementation_requirements'->>'continuous_auto_assurance','true')='true'
          AND p.assessment_scope->'implementation_requirements'->>'scope_id'=s.id::text
          AND p.assessment_scope->'implementation_requirements'->>'engagement_id'=s.engagement_id::text
          AND p.assessment_scope->'implementation_requirements'->>'scope_version_id'=v.id::text
          AND r->>'id'=NEW.requirement_id AND r->'asset_ids' @> to_jsonb(NEW.asset_id)
          AND r->>'machine_verifiable'='true'
          AND NOT EXISTS (SELECT 1 FROM securescope_control_assessment_profiles newer
            WHERE newer.client_id=p.client_id AND newer.control_id=p.control_id
              AND newer.assessment_scope->'implementation_requirements'->>'scope_id'=s.id::text
              AND newer.profile_version>p.profile_version)) THEN
        RAISE EXCEPTION 'M3 attribution profile/scope/asset mismatch';
    END IF;
    RETURN NEW;
END $$ LANGUAGE plpgsql;
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname='m3_source_guard'
                   AND tgrelid='securescope_nuclei_requirement_sources'::regclass) THEN
        CREATE TRIGGER m3_source_guard BEFORE INSERT OR UPDATE OR DELETE
            ON securescope_nuclei_requirement_sources FOR EACH ROW EXECUTE FUNCTION securescope_m3_source_guard();
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname='m3_attribution_guard'
                   AND tgrelid='securescope_requirement_check_attributions'::regclass) THEN
        CREATE TRIGGER m3_attribution_guard BEFORE INSERT OR UPDATE OR DELETE
            ON securescope_requirement_check_attributions FOR EACH ROW EXECUTE FUNCTION securescope_m3_attribution_guard();
    END IF;
END $$;
