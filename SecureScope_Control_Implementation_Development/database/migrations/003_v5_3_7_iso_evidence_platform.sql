-- SecureScope v5.3.7 ISO 27001 evidence platform.
-- Additive only: no existing object or customer row is removed or rewritten.

CREATE TABLE IF NOT EXISTS securescope_users (
    id BIGSERIAL PRIMARY KEY,
    user_uuid UUID NOT NULL UNIQUE,
    email TEXT NOT NULL UNIQUE,
    display_name TEXT NOT NULL,
    active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CHECK (email = lower(email))
);

CREATE TABLE IF NOT EXISTS securescope_workspace_memberships (
    id BIGSERIAL PRIMARY KEY,
    client_id BIGINT NOT NULL
        REFERENCES securescope_clients(id) ON DELETE CASCADE,
    user_id BIGINT NOT NULL REFERENCES securescope_users(id) ON DELETE CASCADE,
    role TEXT NOT NULL CHECK (role IN (
        'Administrator', 'Client contributor', 'Consultant', 'Auditor'
    )),
    active BOOLEAN NOT NULL DEFAULT TRUE,
    granted_by TEXT NOT NULL,
    granted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (client_id, user_id),
    UNIQUE (client_id, id)
);

CREATE TABLE IF NOT EXISTS securescope_connectors (
    id BIGSERIAL PRIMARY KEY,
    client_id BIGINT NOT NULL
        REFERENCES securescope_clients(id) ON DELETE CASCADE,
    tool_id TEXT NOT NULL,
    integration_mode TEXT NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT FALSE,
    configuration JSONB NOT NULL DEFAULT '{}'::jsonb,
    health_status TEXT NOT NULL DEFAULT 'Not configured' CHECK (health_status IN (
        'Not configured', 'Ready', 'Degraded', 'Unavailable', 'Disabled'
    )),
    last_attempt_at TIMESTAMPTZ,
    last_success_at TIMESTAMPTZ,
    last_error TEXT NOT NULL DEFAULT '',
    configured_by TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (client_id, tool_id),
    UNIQUE (client_id, id),
    CHECK (NOT (configuration ?| ARRAY[
        'password', 'token', 'secret', 'api_key', 'private_key'
    ]))
);

CREATE TABLE IF NOT EXISTS securescope_evidence_artifacts (
    id BIGSERIAL PRIMARY KEY,
    client_id BIGINT NOT NULL
        REFERENCES securescope_clients(id) ON DELETE CASCADE,
    artifact_uuid UUID NOT NULL UNIQUE,
    original_filename TEXT NOT NULL,
    storage_reference TEXT NOT NULL,
    media_type TEXT NOT NULL DEFAULT 'application/octet-stream',
    byte_size BIGINT NOT NULL CHECK (byte_size >= 0),
    sha256 CHAR(64) NOT NULL,
    encrypted BOOLEAN NOT NULL DEFAULT FALSE,
    created_by TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (client_id, id),
    UNIQUE (client_id, sha256, storage_reference)
);

CREATE TABLE IF NOT EXISTS securescope_evidence_records (
    id BIGSERIAL PRIMARY KEY,
    client_id BIGINT NOT NULL
        REFERENCES securescope_clients(id) ON DELETE CASCADE,
    evidence_uuid UUID NOT NULL UNIQUE,
    artifact_id BIGINT,
    tool_id TEXT NOT NULL,
    collection_method TEXT NOT NULL CHECK (collection_method IN (
        'Existing worker', 'Defensive local CLI', 'Authenticated API',
        'Report import', 'Manual evidence'
    )),
    evidence_type TEXT NOT NULL,
    title TEXT NOT NULL,
    summary TEXT NOT NULL,
    source_asset_or_system TEXT NOT NULL DEFAULT '',
    scope_description TEXT NOT NULL,
    normalized_payload JSONB NOT NULL DEFAULT '{}'::jsonb,
    observation_count INTEGER NOT NULL DEFAULT 0 CHECK (observation_count >= 0),
    collected_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ,
    freshness_status TEXT NOT NULL DEFAULT 'Current' CHECK (freshness_status IN (
        'Current', 'Approaching expiration', 'Expired', 'Unknown'
    )),
    validation_status TEXT NOT NULL DEFAULT 'Pending' CHECK (validation_status IN (
        'Pending', 'Validated', 'Rejected', 'More evidence required'
    )),
    confidence TEXT NOT NULL DEFAULT 'Low' CHECK (confidence IN ('Low', 'Medium', 'High')),
    owner TEXT NOT NULL,
    submitted_by TEXT NOT NULL,
    validator TEXT,
    validation_comment TEXT NOT NULL DEFAULT '',
    validated_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (client_id, id),
    FOREIGN KEY (client_id, artifact_id)
        REFERENCES securescope_evidence_artifacts(client_id, id) ON DELETE RESTRICT,
    CHECK (expires_at IS NULL OR expires_at > collected_at),
    CHECK (
        (validation_status = 'Pending' AND validator IS NULL AND validated_at IS NULL)
        OR (validation_status <> 'Pending' AND validator IS NOT NULL AND validated_at IS NOT NULL)
    )
);

CREATE TABLE IF NOT EXISTS securescope_evidence_control_mappings (
    id BIGSERIAL PRIMARY KEY,
    client_id BIGINT NOT NULL
        REFERENCES securescope_clients(id) ON DELETE CASCADE,
    evidence_id BIGINT NOT NULL,
    control_id TEXT NOT NULL,
    mapping_origin TEXT NOT NULL CHECK (mapping_origin IN (
        'Catalog suggestion', 'Consultant mapping'
    )),
    evidence_dimension TEXT NOT NULL CHECK (evidence_dimension IN (
        'Design', 'Implementation', 'Effectiveness'
    )),
    rationale TEXT NOT NULL,
    consultant_approved BOOLEAN NOT NULL DEFAULT FALSE,
    approved_by TEXT,
    approved_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (client_id, evidence_id, control_id, evidence_dimension),
    UNIQUE (client_id, id),
    FOREIGN KEY (client_id, evidence_id)
        REFERENCES securescope_evidence_records(client_id, id) ON DELETE CASCADE,
    CHECK (
        (NOT consultant_approved AND approved_by IS NULL AND approved_at IS NULL)
        OR (consultant_approved AND approved_by IS NOT NULL AND approved_at IS NOT NULL)
    )
);

CREATE TABLE IF NOT EXISTS securescope_evidence_requests (
    id BIGSERIAL PRIMARY KEY,
    client_id BIGINT NOT NULL
        REFERENCES securescope_clients(id) ON DELETE CASCADE,
    request_uuid UUID NOT NULL UNIQUE,
    control_id TEXT NOT NULL,
    title TEXT NOT NULL,
    requested_evidence TEXT NOT NULL,
    assigned_to TEXT NOT NULL,
    due_date DATE NOT NULL,
    status TEXT NOT NULL DEFAULT 'Open' CHECK (status IN (
        'Open', 'Submitted', 'Accepted', 'Rejected', 'Cancelled'
    )),
    response_evidence_id BIGINT,
    requested_by TEXT NOT NULL,
    closed_by TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (client_id, id),
    FOREIGN KEY (client_id, response_evidence_id)
        REFERENCES securescope_evidence_records(client_id, id) ON DELETE RESTRICT
);

CREATE TABLE IF NOT EXISTS securescope_evidence_jobs (
    id BIGSERIAL PRIMARY KEY,
    client_id BIGINT NOT NULL
        REFERENCES securescope_clients(id) ON DELETE CASCADE,
    job_uuid UUID NOT NULL UNIQUE,
    tool_id TEXT NOT NULL,
    job_type TEXT NOT NULL CHECK (job_type IN ('Collect', 'Import', 'Synchronize')),
    status TEXT NOT NULL DEFAULT 'Queued' CHECK (status IN (
        'Queued', 'Claimed', 'Running', 'Succeeded', 'Failed', 'Cancelled'
    )),
    request_payload JSONB NOT NULL DEFAULT '{}'::jsonb,
    requested_by TEXT NOT NULL,
    worker_name TEXT,
    attempt_count INTEGER NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
    max_attempts INTEGER NOT NULL DEFAULT 3 CHECK (max_attempts > 0),
    available_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    claimed_at TIMESTAMPTZ,
    heartbeat_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    result_evidence_id BIGINT,
    last_error TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (client_id, id),
    FOREIGN KEY (client_id, result_evidence_id)
        REFERENCES securescope_evidence_records(client_id, id) ON DELETE RESTRICT
);

CREATE TABLE IF NOT EXISTS securescope_evidence_audit_events (
    id BIGSERIAL PRIMARY KEY,
    client_id BIGINT NOT NULL
        REFERENCES securescope_clients(id) ON DELETE CASCADE,
    event_uuid UUID NOT NULL UNIQUE,
    event_type TEXT NOT NULL,
    entity_type TEXT NOT NULL,
    entity_id TEXT NOT NULL,
    actor TEXT NOT NULL,
    summary TEXT NOT NULL,
    event_payload JSONB NOT NULL DEFAULT '{}'::jsonb,
    previous_event_hash CHAR(64),
    event_hash CHAR(64) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (client_id, id),
    UNIQUE (client_id, event_hash)
);

CREATE OR REPLACE FUNCTION securescope_reject_evidence_audit_update()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'SecureScope evidence audit events are immutable';
END;
$$;

DROP TRIGGER IF EXISTS trg_securescope_evidence_audit_immutable
    ON securescope_evidence_audit_events;
CREATE TRIGGER trg_securescope_evidence_audit_immutable
BEFORE UPDATE ON securescope_evidence_audit_events
FOR EACH ROW EXECUTE FUNCTION securescope_reject_evidence_audit_update();

CREATE INDEX IF NOT EXISTS idx_memberships_client_role
    ON securescope_workspace_memberships(client_id, role, active);
CREATE INDEX IF NOT EXISTS idx_connectors_client_health
    ON securescope_connectors(client_id, health_status, tool_id);
CREATE INDEX IF NOT EXISTS idx_evidence_records_client_review
    ON securescope_evidence_records(client_id, validation_status, collected_at DESC);
CREATE INDEX IF NOT EXISTS idx_evidence_records_client_freshness
    ON securescope_evidence_records(client_id, freshness_status, expires_at);
CREATE INDEX IF NOT EXISTS idx_evidence_mappings_client_control
    ON securescope_evidence_control_mappings(client_id, control_id, consultant_approved);
CREATE INDEX IF NOT EXISTS idx_evidence_requests_client_due
    ON securescope_evidence_requests(client_id, status, due_date);
CREATE INDEX IF NOT EXISTS idx_evidence_jobs_claim
    ON securescope_evidence_jobs(status, available_at, created_at);
CREATE INDEX IF NOT EXISTS idx_evidence_audit_client_time
    ON securescope_evidence_audit_events(client_id, created_at DESC);
