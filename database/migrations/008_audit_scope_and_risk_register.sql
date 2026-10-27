-- ISO audit planning and risk register records. Additive and client scoped.
CREATE TABLE IF NOT EXISTS securescope_audit_scopes (
    id BIGSERIAL PRIMARY KEY,
    client_id BIGINT NOT NULL REFERENCES securescope_clients(id) ON DELETE CASCADE,
    audit_no TEXT NOT NULL,
    audit_year INTEGER NOT NULL CHECK (audit_year BETWEEN 2000 AND 2200),
    status TEXT NOT NULL DEFAULT 'Draft'
        CHECK (status IN ('Draft', 'Planned', 'In progress', 'Completed', 'Cancelled')),
    scope_statement TEXT NOT NULL DEFAULT '',
    objectives TEXT NOT NULL DEFAULT '',
    criteria TEXT NOT NULL DEFAULT 'ISO/IEC 27001:2022',
    sites TEXT NOT NULL DEFAULT '',
    processes TEXT NOT NULL DEFAULT '',
    systems TEXT NOT NULL DEFAULT '',
    exclusions TEXT NOT NULL DEFAULT '',
    lead_auditor TEXT NOT NULL DEFAULT '',
    planned_start DATE,
    planned_end DATE,
    approved_by TEXT,
    approved_at TIMESTAMPTZ,
    approval_comment TEXT NOT NULL DEFAULT '',
    revision INTEGER NOT NULL DEFAULT 1 CHECK (revision > 0),
    updated_by TEXT NOT NULL DEFAULT 'securescope-ui',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (client_id, audit_no),
    CHECK (planned_end IS NULL OR planned_start IS NULL OR planned_end >= planned_start)
);

CREATE TABLE IF NOT EXISTS securescope_audit_schedule_rows (
    client_id BIGINT NOT NULL REFERENCES securescope_clients(id) ON DELETE CASCADE,
    audit_scope_id BIGINT NOT NULL REFERENCES securescope_audit_scopes(id) ON DELETE CASCADE,
    row_key TEXT NOT NULL,
    iso_ref TEXT NOT NULL DEFAULT '',
    row_label TEXT NOT NULL,
    row_type TEXT NOT NULL DEFAULT 'requirement'
        CHECK (row_type IN ('section', 'requirement', 'control_family')),
    audit_no TEXT NOT NULL DEFAULT '',
    jan TEXT NOT NULL DEFAULT '',
    feb TEXT NOT NULL DEFAULT '',
    mar TEXT NOT NULL DEFAULT '',
    apr TEXT NOT NULL DEFAULT '',
    may TEXT NOT NULL DEFAULT '',
    jun TEXT NOT NULL DEFAULT '',
    jul TEXT NOT NULL DEFAULT '',
    aug TEXT NOT NULL DEFAULT '',
    sep TEXT NOT NULL DEFAULT '',
    oct TEXT NOT NULL DEFAULT '',
    nov TEXT NOT NULL DEFAULT '',
    dec TEXT NOT NULL DEFAULT '',
    notes TEXT NOT NULL DEFAULT '',
    updated_by TEXT NOT NULL DEFAULT 'securescope-ui',
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (client_id, audit_scope_id, row_key)
);

CREATE TABLE IF NOT EXISTS securescope_risk_register (
    id BIGSERIAL PRIMARY KEY,
    client_id BIGINT NOT NULL REFERENCES securescope_clients(id) ON DELETE CASCADE,
    risk_ref INTEGER NOT NULL CHECK (risk_ref > 0),
    asset_group TEXT NOT NULL DEFAULT '',
    asset_subcategory TEXT NOT NULL DEFAULT '',
    asset TEXT NOT NULL DEFAULT '',
    threat TEXT NOT NULL DEFAULT '',
    vulnerability TEXT NOT NULL DEFAULT '',
    risk_type TEXT NOT NULL DEFAULT 'C',
    risk_owner TEXT NOT NULL DEFAULT '',
    existing_controls TEXT NOT NULL DEFAULT '',
    pre_likelihood INTEGER CHECK (pre_likelihood BETWEEN 1 AND 5),
    pre_likelihood_rationale TEXT NOT NULL DEFAULT '',
    pre_impact INTEGER CHECK (pre_impact BETWEEN 1 AND 5),
    pre_impact_rationale TEXT NOT NULL DEFAULT '',
    treatment_option TEXT NOT NULL DEFAULT 'Modify'
        CHECK (treatment_option IN ('Modify', 'Accept', 'Avoid', 'Transfer / Share')),
    treatment_action TEXT NOT NULL DEFAULT '',
    control_references JSONB NOT NULL DEFAULT '[]'::jsonb,
    treatment_cost NUMERIC(14, 2),
    treatment_action_owner TEXT NOT NULL DEFAULT '',
    treatment_action_timescale TEXT NOT NULL DEFAULT '',
    treatment_action_progress TEXT NOT NULL DEFAULT '',
    treatment_action_status TEXT NOT NULL DEFAULT 'Not Started'
        CHECK (treatment_action_status IN ('Not Started', 'In Progress', 'Completed', 'Rejected', 'Accepted risk')),
    post_likelihood INTEGER CHECK (post_likelihood BETWEEN 1 AND 5),
    post_likelihood_rationale TEXT NOT NULL DEFAULT '',
    post_impact INTEGER CHECK (post_impact BETWEEN 1 AND 5),
    post_impact_rationale TEXT NOT NULL DEFAULT '',
    comments TEXT NOT NULL DEFAULT '',
    revision INTEGER NOT NULL DEFAULT 1 CHECK (revision > 0),
    updated_by TEXT NOT NULL DEFAULT 'securescope-ui',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (client_id, risk_ref)
);

CREATE INDEX IF NOT EXISTS idx_audit_scope_client_year
    ON securescope_audit_scopes(client_id, audit_year DESC, id DESC);
CREATE INDEX IF NOT EXISTS idx_risk_register_client_level
    ON securescope_risk_register(client_id, treatment_action_status, risk_ref);
