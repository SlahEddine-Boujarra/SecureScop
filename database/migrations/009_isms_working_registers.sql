-- Editable registers and drafts with client ownership and immutable revisions.
CREATE TABLE IF NOT EXISTS securescope_working_registers (
    client_id BIGINT NOT NULL REFERENCES securescope_clients(id) ON DELETE CASCADE,
    register_key TEXT NOT NULL,
    rows JSONB NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(rows) = 'array'),
    revision INTEGER NOT NULL CHECK (revision > 0),
    updated_by TEXT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (client_id, register_key)
);
CREATE TABLE IF NOT EXISTS securescope_working_register_versions (
    client_id BIGINT NOT NULL REFERENCES securescope_clients(id) ON DELETE CASCADE,
    register_key TEXT NOT NULL,
    revision INTEGER NOT NULL,
    rows JSONB NOT NULL,
    recorded_by TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (client_id, register_key, revision)
);

ALTER TABLE securescope_risk_register
    ADD COLUMN IF NOT EXISTS residual_verified BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS residual_evidence TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS residual_verified_by TEXT NOT NULL DEFAULT '';
