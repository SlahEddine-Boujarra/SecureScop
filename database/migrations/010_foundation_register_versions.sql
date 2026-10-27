-- Additive formal Policy/Objectives versions and risk review snapshots.
CREATE TABLE IF NOT EXISTS securescope_foundation_versions (
    id BIGSERIAL PRIMARY KEY,
    client_id BIGINT NOT NULL REFERENCES securescope_clients(id) ON DELETE CASCADE,
    engagement_id BIGINT NOT NULL,
    scope_id BIGINT NOT NULL,
    register_key TEXT NOT NULL CHECK (register_key IN ('policy', 'objectives', 'risks')),
    version INTEGER NOT NULL CHECK (version > 0),
    status TEXT NOT NULL CHECK (status IN ('Suggested', 'Draft', 'In review', 'Approved')),
    records JSONB NOT NULL CHECK (jsonb_typeof(records) = 'array'),
    owner TEXT NOT NULL,
    recorded_by TEXT NOT NULL,
    review_note TEXT NOT NULL DEFAULT '',
    approved_by TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    FOREIGN KEY (client_id, engagement_id)
        REFERENCES securescope_engagements(client_id, id) ON DELETE CASCADE,
    FOREIGN KEY (client_id, scope_id)
        REFERENCES securescope_scope_definitions(client_id, id) ON DELETE CASCADE,
    UNIQUE (client_id, engagement_id, scope_id, register_key, version),
    CHECK (status <> 'Approved' OR
        (approved_by IS NOT NULL AND btrim(review_note) <> ''))
);
CREATE TABLE IF NOT EXISTS securescope_workspace_bootstraps (
    client_id BIGINT PRIMARY KEY REFERENCES securescope_clients(id) ON DELETE CASCADE,
    administrator_email TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
