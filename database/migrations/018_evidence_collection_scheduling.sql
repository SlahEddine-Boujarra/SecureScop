-- M2 is opt-in. Existing jobs, migrations and source observations are retained.
CREATE TABLE IF NOT EXISTS securescope_evidence_schedules (
    id BIGSERIAL PRIMARY KEY,
    client_id BIGINT NOT NULL REFERENCES securescope_clients(id),
    schedule_uuid UUID NOT NULL,
    revision INTEGER NOT NULL DEFAULT 1 CHECK (revision > 0),
    connector_id TEXT NOT NULL,
    name TEXT NOT NULL,
    interval_seconds INTEGER NOT NULL CHECK (interval_seconds BETWEEN 30 AND 604800),
    max_attempts INTEGER NOT NULL DEFAULT 3 CHECK (max_attempts BETWEEN 1 AND 5),
    enabled BOOLEAN NOT NULL DEFAULT FALSE,
    pause_reason TEXT NOT NULL DEFAULT '',
    next_run_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    approved_by TEXT NOT NULL,
    approved_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    missed_occurrences BIGINT NOT NULL DEFAULT 0,
    UNIQUE (client_id,id),
    UNIQUE (client_id,schedule_uuid,revision)
);
CREATE UNIQUE INDEX IF NOT EXISTS evidence_schedule_active_revision
    ON securescope_evidence_schedules(client_id,schedule_uuid) WHERE enabled;
CREATE INDEX IF NOT EXISTS evidence_schedule_due
    ON securescope_evidence_schedules(next_run_at,id) WHERE enabled;
CREATE TABLE IF NOT EXISTS securescope_evidence_schedule_targets (
    id BIGSERIAL PRIMARY KEY,
    client_id BIGINT NOT NULL,
    schedule_id BIGINT NOT NULL,
    asset_id BIGINT NOT NULL REFERENCES securescope_assets(id),
    binding_id BIGINT NOT NULL,
    engagement_id BIGINT NOT NULL,
    scope_id BIGINT NOT NULL,
    scope_version_id BIGINT NOT NULL,
    profile_id BIGINT NOT NULL,
    requirement_id TEXT NOT NULL,
    control_id TEXT NOT NULL CHECK (control_id IN ('A.8.15','A.8.16')),
    accept_health BOOLEAN NOT NULL DEFAULT FALSE,
    health_policy JSONB NOT NULL DEFAULT '{}'::jsonb,
    UNIQUE (client_id,id),
    UNIQUE (schedule_id,profile_id,requirement_id,asset_id),
    FOREIGN KEY (client_id,schedule_id) REFERENCES securescope_evidence_schedules(client_id,id),
    FOREIGN KEY (client_id,binding_id,asset_id) REFERENCES securescope_wazuh_bindings(client_id,id,asset_id),
    FOREIGN KEY (client_id,engagement_id) REFERENCES securescope_engagements(client_id,id),
    FOREIGN KEY (client_id,scope_id) REFERENCES securescope_scope_definitions(client_id,id),
    FOREIGN KEY (client_id,scope_version_id) REFERENCES securescope_scope_versions(client_id,id),
    FOREIGN KEY (client_id,profile_id) REFERENCES securescope_control_assessment_profiles(client_id,id),
    CHECK (NOT accept_health OR control_id='A.8.16')
);
ALTER TABLE securescope_evidence_jobs ADD COLUMN IF NOT EXISTS operation TEXT;
ALTER TABLE securescope_evidence_jobs ADD COLUMN IF NOT EXISTS schedule_id BIGINT;
ALTER TABLE securescope_evidence_jobs ADD COLUMN IF NOT EXISTS scheduled_for TIMESTAMPTZ;
ALTER TABLE securescope_evidence_jobs ADD COLUMN IF NOT EXISTS fencing_token BIGINT;
ALTER TABLE securescope_evidence_jobs ADD COLUMN IF NOT EXISTS execution_deadline TIMESTAMPTZ;
ALTER TABLE securescope_evidence_jobs ADD COLUMN IF NOT EXISTS diagnostic_outcome TEXT NOT NULL DEFAULT '';
ALTER TABLE securescope_evidence_jobs ADD COLUMN IF NOT EXISTS assurance_refresh_state TEXT NOT NULL DEFAULT 'pending';
ALTER TABLE securescope_evidence_jobs ADD COLUMN IF NOT EXISTS assurance_refresh_attempts INTEGER NOT NULL DEFAULT 0;
ALTER TABLE securescope_evidence_jobs ADD COLUMN IF NOT EXISTS assurance_refresh_available_at TIMESTAMPTZ NOT NULL DEFAULT NOW();
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='evidence_job_schedule_owner'
                   AND conrelid='securescope_evidence_jobs'::regclass) THEN
        ALTER TABLE securescope_evidence_jobs ADD CONSTRAINT evidence_job_schedule_owner
            FOREIGN KEY (client_id,schedule_id) REFERENCES securescope_evidence_schedules(client_id,id);
    END IF;
END $$;
CREATE UNIQUE INDEX IF NOT EXISTS evidence_schedule_occurrence
    ON securescope_evidence_jobs(schedule_id,scheduled_for) WHERE schedule_id IS NOT NULL;
CREATE TABLE IF NOT EXISTS securescope_evidence_execution_leases (
    client_id BIGINT NOT NULL REFERENCES securescope_clients(id),
    connector_id TEXT NOT NULL,
    token BIGINT NOT NULL DEFAULT 0,
    job_id BIGINT,
    worker_name TEXT NOT NULL DEFAULT '',
    expires_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (client_id,connector_id),
    FOREIGN KEY (client_id,job_id) REFERENCES securescope_evidence_jobs(client_id,id)
);
CREATE TABLE IF NOT EXISTS securescope_evidence_job_attempts (
    id BIGSERIAL PRIMARY KEY,
    client_id BIGINT NOT NULL,
    job_id BIGINT NOT NULL,
    attempt_number INTEGER NOT NULL,
    fencing_token BIGINT NOT NULL,
    worker_name TEXT NOT NULL,
    started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMPTZ,
    outcome TEXT NOT NULL DEFAULT 'running',
    error_code TEXT NOT NULL DEFAULT '',
    UNIQUE (client_id,id),
    UNIQUE (client_id,job_id,attempt_number),
    FOREIGN KEY (client_id,job_id) REFERENCES securescope_evidence_jobs(client_id,id)
);
CREATE TABLE IF NOT EXISTS securescope_evidence_target_attempts (
    id BIGSERIAL PRIMARY KEY,
    client_id BIGINT NOT NULL,
    attempt_id BIGINT NOT NULL,
    target_id BIGINT NOT NULL,
    acquisition TEXT NOT NULL DEFAULT 'pending',
    ingestion TEXT NOT NULL DEFAULT 'pending',
    error_code TEXT NOT NULL DEFAULT '',
    observation_id BIGINT,
    UNIQUE (client_id,attempt_id,target_id),
    FOREIGN KEY (client_id,attempt_id) REFERENCES securescope_evidence_job_attempts(client_id,id),
    FOREIGN KEY (client_id,target_id) REFERENCES securescope_evidence_schedule_targets(client_id,id),
    FOREIGN KEY (client_id,observation_id) REFERENCES securescope_wazuh_observations(client_id,id)
);
CREATE TABLE IF NOT EXISTS securescope_evidence_job_results (
    client_id BIGINT NOT NULL,
    job_id BIGINT NOT NULL,
    target_id BIGINT NOT NULL,
    evidence_id BIGINT NOT NULL,
    PRIMARY KEY (client_id,job_id,target_id,evidence_id),
    FOREIGN KEY (client_id,job_id) REFERENCES securescope_evidence_jobs(client_id,id),
    FOREIGN KEY (client_id,target_id) REFERENCES securescope_evidence_schedule_targets(client_id,id),
    FOREIGN KEY (client_id,evidence_id) REFERENCES securescope_evidence_records(client_id,id)
);
CREATE OR REPLACE FUNCTION securescope_schedule_target_guard() RETURNS trigger AS $$
BEGIN
    IF TG_OP <> 'INSERT' THEN
        RAISE EXCEPTION 'Schedule targets are immutable; create a new schedule revision';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM securescope_scope_versions v
      JOIN securescope_scope_definitions s ON s.client_id=v.client_id AND s.id=v.scope_id
      WHERE v.client_id=NEW.client_id AND v.id=NEW.scope_version_id
        AND v.scope_id=NEW.scope_id AND s.engagement_id=NEW.engagement_id) THEN
        RAISE EXCEPTION 'Schedule target scope ownership mismatch';
    END IF;
    RETURN NEW;
END $$ LANGUAGE plpgsql;
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname='evidence_schedule_target_guard'
                   AND tgrelid='securescope_evidence_schedule_targets'::regclass) THEN
        CREATE TRIGGER evidence_schedule_target_guard BEFORE INSERT OR UPDATE OR DELETE
            ON securescope_evidence_schedule_targets FOR EACH ROW
            EXECUTE FUNCTION securescope_schedule_target_guard();
    END IF;
END $$;
-- Host connector rate admission shared across workspaces (no tenant data or credentials).
CREATE TABLE IF NOT EXISTS securescope_evidence_connector_budget (
    connector_id TEXT PRIMARY KEY,
    next_request_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE OR REPLACE FUNCTION securescope_schedule_revision_guard() RETURNS trigger AS $$
BEGIN
    IF ROW(NEW.client_id,NEW.schedule_uuid,NEW.revision,NEW.connector_id,NEW.name,
           NEW.interval_seconds,NEW.max_attempts,NEW.approved_by,NEW.approved_at)
       IS DISTINCT FROM ROW(OLD.client_id,OLD.schedule_uuid,OLD.revision,OLD.connector_id,OLD.name,
           OLD.interval_seconds,OLD.max_attempts,OLD.approved_by,OLD.approved_at) THEN
        RAISE EXCEPTION 'Approved schedule configuration is immutable; create a new revision';
    END IF;
    RETURN NEW;
END $$ LANGUAGE plpgsql;
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname='evidence_schedule_revision_guard'
                   AND tgrelid='securescope_evidence_schedules'::regclass) THEN
        CREATE TRIGGER evidence_schedule_revision_guard BEFORE UPDATE
            ON securescope_evidence_schedules FOR EACH ROW EXECUTE FUNCTION securescope_schedule_revision_guard();
    END IF;
END $$;
