-- SecureScope v6.1 Quick Remediation schema.
-- Additive migration: scanner queues and v6 exposure/GRC data are preserved.

CREATE TABLE IF NOT EXISTS securescope_remediation_executions (
    id BIGSERIAL PRIMARY KEY,
    client_id BIGINT NOT NULL
        REFERENCES securescope_clients(id) ON DELETE CASCADE,
    execution_uuid UUID NOT NULL UNIQUE,
    plan_id BIGINT NOT NULL,
    finding_id BIGINT NOT NULL,
    recipe_id TEXT NOT NULL,
    recipe_version TEXT NOT NULL,
    recipe_checksum CHAR(64) NOT NULL,
    candidate_checksum CHAR(64) NOT NULL,
    execution_level TEXT NOT NULL
        CHECK (execution_level IN (
            'Guided manual', 'Prepared automation', 'Approved execution'
        )),
    status TEXT NOT NULL DEFAULT 'Draft'
        CHECK (status IN (
            'Draft', 'Ready', 'Awaiting approval', 'Approved', 'Running',
            'Pending restart', 'Pending verification', 'Verified', 'Failed',
            'Rolled back', 'Risk accepted'
        )),
    asset_identity TEXT NOT NULL,
    asset_ip INET NOT NULL,
    asset_tag TEXT NOT NULL DEFAULT '',
    wazuh_agent_id TEXT NOT NULL,
    wazuh_agent_status TEXT NOT NULL,
    requested_by TEXT NOT NULL,
    requested_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    approved_by TEXT,
    approved_at TIMESTAMPTZ,
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    restart_required BOOLEAN,
    dispatch_result JSONB NOT NULL DEFAULT '{}'::jsonb,
    sanitized_log TEXT NOT NULL DEFAULT '',
    exit_code INTEGER,
    verification_engine TEXT NOT NULL DEFAULT 'Nuclei',
    verification_not_before TIMESTAMPTZ,
    verification_batch_id BIGINT,
    verification_reference TEXT,
    failure_reason TEXT,
    rollback_reference TEXT,
    version INTEGER NOT NULL DEFAULT 1 CHECK (version > 0),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (client_id, id),
    FOREIGN KEY (client_id, plan_id)
        REFERENCES securescope_remediation_plans(client_id, id) ON DELETE CASCADE,
    FOREIGN KEY (client_id, finding_id)
        REFERENCES securescope_findings(client_id, id) ON DELETE CASCADE,
    CHECK (
        (approved_by IS NULL AND approved_at IS NULL)
        OR (approved_by IS NOT NULL AND approved_at IS NOT NULL)
    ),
    CHECK (
        status NOT IN ('Approved', 'Running', 'Pending restart',
                       'Pending verification', 'Verified')
        OR approved_by IS NOT NULL
    )
);

CREATE TABLE IF NOT EXISTS securescope_remediation_execution_events (
    id BIGSERIAL PRIMARY KEY,
    client_id BIGINT NOT NULL
        REFERENCES securescope_clients(id) ON DELETE CASCADE,
    execution_id BIGINT NOT NULL,
    from_status TEXT,
    to_status TEXT NOT NULL,
    actor TEXT NOT NULL,
    reason TEXT NOT NULL,
    evidence_reference TEXT,
    event_payload JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    FOREIGN KEY (client_id, execution_id)
        REFERENCES securescope_remediation_executions(client_id, id)
        ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_remediation_executions_client_status
    ON securescope_remediation_executions(client_id, status, requested_at);
CREATE INDEX IF NOT EXISTS idx_remediation_executions_client_finding
    ON securescope_remediation_executions(client_id, finding_id, requested_at DESC);
CREATE INDEX IF NOT EXISTS idx_remediation_execution_events_client
    ON securescope_remediation_execution_events(client_id, execution_id, created_at);
