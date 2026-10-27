-- Protected M2 provenance sidecars; no rewrite of M1 or clock evidence.
CREATE TABLE IF NOT EXISTS securescope_wazuh_job_sources (
    client_id BIGINT NOT NULL,
    job_id BIGINT NOT NULL,
    target_id BIGINT NOT NULL,
    observation_id BIGINT NOT NULL,
    run_id BIGINT NOT NULL,
    collected_at TIMESTAMPTZ NOT NULL,
    artifact_id BIGINT NOT NULL,
    policy_sha256 CHAR(64) NOT NULL,
    PRIMARY KEY (client_id,job_id,target_id),
    FOREIGN KEY (client_id,job_id) REFERENCES securescope_evidence_jobs(client_id,id),
    FOREIGN KEY (client_id,target_id) REFERENCES securescope_evidence_schedule_targets(client_id,id),
    FOREIGN KEY (client_id,observation_id) REFERENCES securescope_wazuh_observations(client_id,id),
    FOREIGN KEY (client_id,run_id) REFERENCES securescope_wazuh_collection_runs(client_id,id),
    FOREIGN KEY (client_id,artifact_id) REFERENCES securescope_evidence_artifacts(client_id,id)
);
CREATE TABLE IF NOT EXISTS securescope_evidence_association_provenance (
    id BIGSERIAL PRIMARY KEY,
    client_id BIGINT NOT NULL,
    evidence_id BIGINT NOT NULL,
    target_id BIGINT NOT NULL,
    job_id BIGINT NOT NULL,
    scope_link_id BIGINT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (client_id,evidence_id,target_id),
    FOREIGN KEY (client_id,evidence_id) REFERENCES securescope_evidence_records(client_id,id),
    FOREIGN KEY (client_id,target_id) REFERENCES securescope_evidence_schedule_targets(client_id,id),
    FOREIGN KEY (client_id,job_id) REFERENCES securescope_evidence_jobs(client_id,id),
    FOREIGN KEY (client_id,scope_link_id) REFERENCES securescope_engagement_record_links(client_id,id)
);
CREATE TABLE IF NOT EXISTS securescope_wazuh_attempt_runs (
    client_id BIGINT NOT NULL,
    attempt_id BIGINT NOT NULL,
    run_id BIGINT NOT NULL,
    PRIMARY KEY (client_id,attempt_id,run_id),
    FOREIGN KEY (client_id,attempt_id) REFERENCES securescope_evidence_job_attempts(client_id,id),
    FOREIGN KEY (client_id,run_id) REFERENCES securescope_wazuh_collection_runs(client_id,id)
);
CREATE INDEX IF NOT EXISTS evidence_provenance_lookup
    ON securescope_evidence_association_provenance(client_id,evidence_id,target_id);
CREATE OR REPLACE FUNCTION securescope_m2_source_guard() RETURNS trigger AS $$
BEGIN
    IF TG_OP <> 'INSERT' THEN
        RAISE EXCEPTION 'M2 source history is append-only';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM securescope_evidence_schedule_targets t
      JOIN securescope_evidence_jobs j ON j.client_id=t.client_id AND j.schedule_id=t.schedule_id
      JOIN securescope_wazuh_observations o ON o.client_id=t.client_id AND o.asset_id=t.asset_id
        AND o.binding_id=t.binding_id
      JOIN securescope_wazuh_run_assets r ON r.client_id=t.client_id AND r.observation_id=o.id
      WHERE t.client_id=NEW.client_id AND t.id=NEW.target_id AND j.id=NEW.job_id
        AND o.id=NEW.observation_id AND r.run_id=NEW.run_id) THEN
        RAISE EXCEPTION 'M2 source job/target/observation mismatch';
    END IF;
    RETURN NEW;
END $$ LANGUAGE plpgsql;
CREATE OR REPLACE FUNCTION securescope_m2_association_guard() RETURNS trigger AS $$
BEGIN
    IF TG_OP <> 'INSERT' THEN
        RAISE EXCEPTION 'M2 evidence association history is append-only';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM securescope_evidence_schedule_targets t
      JOIN securescope_wazuh_job_sources x ON x.client_id=t.client_id AND x.target_id=t.id
      JOIN securescope_engagement_record_links l ON l.client_id=t.client_id
        AND l.engagement_id=t.engagement_id AND l.scope_id=t.scope_id
      JOIN securescope_evidence_records e ON e.client_id=x.client_id AND e.id=l.evidence_id
        AND e.tool_id='wazuh'
        AND e.normalized_payload->'metadata'->'provenance'->>'source_record_id'=x.observation_id::text
      WHERE t.client_id=NEW.client_id AND t.id=NEW.target_id AND x.job_id=NEW.job_id
        AND l.id=NEW.scope_link_id AND l.evidence_id=NEW.evidence_id) THEN
        RAISE EXCEPTION 'M2 evidence association context mismatch';
    END IF;
    RETURN NEW;
END $$ LANGUAGE plpgsql;
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname='wazuh_job_source_guard'
                   AND tgrelid='securescope_wazuh_job_sources'::regclass) THEN
        CREATE TRIGGER wazuh_job_source_guard BEFORE INSERT OR UPDATE OR DELETE
            ON securescope_wazuh_job_sources FOR EACH ROW EXECUTE FUNCTION securescope_m2_source_guard();
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname='evidence_association_guard'
                   AND tgrelid='securescope_evidence_association_provenance'::regclass) THEN
        CREATE TRIGGER evidence_association_guard BEFORE INSERT OR UPDATE OR DELETE
            ON securescope_evidence_association_provenance FOR EACH ROW EXECUTE FUNCTION securescope_m2_association_guard();
    END IF;
END $$;
CREATE INDEX IF NOT EXISTS wazuh_job_source_current
    ON securescope_wazuh_job_sources(client_id,target_id,collected_at DESC,job_id DESC);
CREATE INDEX IF NOT EXISTS evidence_target_attempt_current
    ON securescope_evidence_target_attempts(client_id,target_id,attempt_id DESC);
CREATE OR REPLACE FUNCTION securescope_m2_target_result_guard() RETURNS trigger AS $$
DECLARE actual_job BIGINT;
BEGIN
    IF TG_TABLE_NAME='securescope_evidence_target_attempts' THEN
        SELECT job_id INTO actual_job FROM securescope_evidence_job_attempts
          WHERE client_id=NEW.client_id AND id=NEW.attempt_id;
    ELSE
        actual_job := NEW.job_id;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM securescope_evidence_schedule_targets t
        JOIN securescope_evidence_jobs j ON j.client_id=t.client_id AND j.schedule_id=t.schedule_id
        WHERE t.client_id=NEW.client_id AND t.id=NEW.target_id AND j.id=actual_job) THEN
        RAISE EXCEPTION 'Target does not belong to this job schedule';
    END IF;
    RETURN NEW;
END $$ LANGUAGE plpgsql;
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname='evidence_target_attempt_owner'
                   AND tgrelid='securescope_evidence_target_attempts'::regclass) THEN
        CREATE TRIGGER evidence_target_attempt_owner BEFORE INSERT OR UPDATE
            ON securescope_evidence_target_attempts FOR EACH ROW EXECUTE FUNCTION securescope_m2_target_result_guard();
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname='evidence_job_result_owner'
                   AND tgrelid='securescope_evidence_job_results'::regclass) THEN
        CREATE TRIGGER evidence_job_result_owner BEFORE INSERT OR UPDATE
            ON securescope_evidence_job_results FOR EACH ROW EXECUTE FUNCTION securescope_m2_target_result_guard();
    END IF;
END $$;
