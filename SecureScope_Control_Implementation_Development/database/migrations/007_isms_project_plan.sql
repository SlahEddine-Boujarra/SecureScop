-- Additive, client-isolated ISMS implementation tracker.
CREATE TABLE IF NOT EXISTS securescope_isms_project_tasks (
    client_id BIGINT NOT NULL REFERENCES securescope_clients(id) ON DELETE CASCADE,
    task_ref INTEGER NOT NULL CHECK (task_ref BETWEEN 1 AND 30 AND task_ref <> 15),
    resource TEXT NOT NULL CHECK (length(btrim(resource)) BETWEEN 1 AND 1000),
    start_date DATE,
    work_days INTEGER NOT NULL DEFAULT 0 CHECK (work_days BETWEEN 0 AND 3650),
    completed_days INTEGER NOT NULL DEFAULT 0,
    notes TEXT NOT NULL DEFAULT '' CHECK (length(notes) <= 5000),
    revision INTEGER NOT NULL DEFAULT 1 CHECK (revision > 0),
    updated_by TEXT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (client_id, task_ref),
    CHECK (completed_days BETWEEN 0 AND work_days),
    CHECK (completed_days = 0 OR start_date IS NOT NULL),
    CHECK (start_date IS NULL OR EXTRACT(ISODOW FROM start_date) BETWEEN 1 AND 5),
    CHECK (start_date IS NULL OR start_date BETWEEN DATE '2000-01-01' AND DATE '2100-12-31')
);

CREATE TABLE IF NOT EXISTS securescope_isms_project_events (
    id BIGSERIAL PRIMARY KEY,
    client_id BIGINT NOT NULL,
    task_ref INTEGER NOT NULL,
    revision INTEGER NOT NULL,
    actor TEXT NOT NULL,
    before_state JSONB NOT NULL,
    after_state JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    FOREIGN KEY (client_id, task_ref)
        REFERENCES securescope_isms_project_tasks(client_id, task_ref) ON DELETE CASCADE,
    UNIQUE (client_id, task_ref, revision)
);
CREATE INDEX IF NOT EXISTS idx_isms_project_events_client_time
    ON securescope_isms_project_events (client_id, created_at DESC, id DESC);
