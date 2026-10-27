-- Supporting records for policy discussion, risk organization and planning.
-- Canonical policies/risks/scans remain in their existing tables.
CREATE TABLE IF NOT EXISTS securescope_workspace_records (
    client_id BIGINT NOT NULL REFERENCES securescope_clients(id) ON DELETE CASCADE,
    kind TEXT NOT NULL CHECK (kind IN ('risk_group','risk_detail','risk_task','risk_snapshot','calendar_event','policy_comment','policy_audit')),
    record_key TEXT NOT NULL,
    payload JSONB NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(payload)='object'),
    revision INTEGER NOT NULL DEFAULT 1 CHECK (revision>0),
    updated_by TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY(client_id,kind,record_key)
);
