-- Additive monitoring provenance. Existing observations and human decisions are untouched.
CREATE TABLE IF NOT EXISTS securescope_wazuh_bindings (
    id BIGSERIAL PRIMARY KEY,
    client_id BIGINT NOT NULL REFERENCES securescope_clients(id) ON DELETE CASCADE,
    asset_id BIGINT NOT NULL REFERENCES securescope_assets(id) ON DELETE CASCADE,
    connector_id TEXT NOT NULL,
    manager_name TEXT NOT NULL CHECK (length(manager_name) > 0),
    agent_id TEXT NOT NULL CHECK (agent_id ~ '^[0-9]{3,}$' AND agent_id <> '000'),
    heartbeat_max_age_seconds INTEGER NOT NULL CHECK (heartbeat_max_age_seconds BETWEEN 1 AND 604800),
    telemetry_max_age_seconds INTEGER NOT NULL CHECK (telemetry_max_age_seconds BETWEEN 1 AND 31536000),
    approved_by TEXT NOT NULL,
    approved_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    rationale TEXT NOT NULL CHECK (length(trim(rationale)) > 0),
    revoked_by TEXT,
    revoked_at TIMESTAMPTZ,
    UNIQUE (client_id, id),
    UNIQUE (client_id, id, asset_id),
    CHECK ((revoked_at IS NULL) = (revoked_by IS NULL))
);
CREATE UNIQUE INDEX IF NOT EXISTS wazuh_binding_active_agent
    ON securescope_wazuh_bindings(connector_id, manager_name, agent_id) WHERE revoked_at IS NULL;
CREATE UNIQUE INDEX IF NOT EXISTS wazuh_binding_active_asset
    ON securescope_wazuh_bindings(client_id, asset_id, connector_id) WHERE revoked_at IS NULL;

CREATE TABLE IF NOT EXISTS securescope_wazuh_collection_runs (
    id BIGSERIAL PRIMARY KEY,
    client_id BIGINT NOT NULL REFERENCES securescope_clients(id) ON DELETE CASCADE,
    connector_id TEXT NOT NULL,
    requested_by TEXT NOT NULL,
    started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMPTZ,
    outcome TEXT NOT NULL DEFAULT 'running' CHECK (outcome IN ('running','succeeded','partial','failed')),
    error_code TEXT NOT NULL DEFAULT '',
    UNIQUE (client_id, id)
);
CREATE TABLE IF NOT EXISTS securescope_wazuh_observations (
    id BIGSERIAL PRIMARY KEY,
    client_id BIGINT NOT NULL REFERENCES securescope_clients(id) ON DELETE CASCADE,
    binding_id BIGINT NOT NULL,
    asset_id BIGINT NOT NULL REFERENCES securescope_assets(id) ON DELETE CASCADE,
    source_key TEXT NOT NULL,
    payload_sha256 TEXT NOT NULL CHECK (length(payload_sha256) = 64),
    payload JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (client_id, id),
    UNIQUE (client_id, source_key),
    UNIQUE (client_id, id, asset_id),
    FOREIGN KEY (client_id, binding_id, asset_id) REFERENCES securescope_wazuh_bindings(client_id,id,asset_id)
);
CREATE TABLE IF NOT EXISTS securescope_wazuh_run_assets (
    client_id BIGINT NOT NULL,
    run_id BIGINT NOT NULL,
    observation_id BIGINT NOT NULL,
    asset_id BIGINT NOT NULL REFERENCES securescope_assets(id) ON DELETE CASCADE,
    PRIMARY KEY (client_id,run_id,asset_id),
    FOREIGN KEY (client_id,run_id) REFERENCES securescope_wazuh_collection_runs(client_id,id),
    FOREIGN KEY (client_id,observation_id,asset_id) REFERENCES securescope_wazuh_observations(client_id,id,asset_id)
);
CREATE INDEX IF NOT EXISTS wazuh_run_asset_latest
    ON securescope_wazuh_run_assets(client_id,asset_id,run_id DESC);

CREATE OR REPLACE FUNCTION securescope_check_wazuh_asset_owner() RETURNS trigger AS $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM securescope_assets a
                   WHERE a.id=NEW.asset_id AND a.client_id=NEW.client_id) THEN
        RAISE EXCEPTION 'Wazuh asset belongs to another workspace';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname='wazuh_binding_asset_owner' AND tgrelid='securescope_wazuh_bindings'::regclass) THEN
        CREATE TRIGGER wazuh_binding_asset_owner BEFORE INSERT OR UPDATE
            ON securescope_wazuh_bindings FOR EACH ROW
            EXECUTE FUNCTION securescope_check_wazuh_asset_owner();
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname='wazuh_observation_asset_owner' AND tgrelid='securescope_wazuh_observations'::regclass) THEN
        CREATE TRIGGER wazuh_observation_asset_owner BEFORE INSERT OR UPDATE
            ON securescope_wazuh_observations FOR EACH ROW
            EXECUTE FUNCTION securescope_check_wazuh_asset_owner();
    END IF;
END;
$$;

-- Updates must not rewrite facts referenced by evidence. Tenant deletion behavior is unchanged.
CREATE OR REPLACE FUNCTION securescope_wazuh_immutable_observation() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'Wazuh observations are immutable; append a new observation';
END;
$$ LANGUAGE plpgsql;
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname='wazuh_observation_immutable'
                   AND tgrelid='securescope_wazuh_observations'::regclass) THEN
        CREATE TRIGGER wazuh_observation_immutable BEFORE UPDATE ON securescope_wazuh_observations
            FOR EACH ROW EXECUTE FUNCTION securescope_wazuh_immutable_observation();
    END IF;
END;
$$;
