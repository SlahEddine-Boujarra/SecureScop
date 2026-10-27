-- SecureScope v5.3.8.4 organization knowledge and guided discovery foundation.
-- Additive only. Existing GRC, scanner and evidence records remain unchanged.

CREATE TABLE IF NOT EXISTS securescope_organization_profiles (
    client_id BIGINT PRIMARY KEY
        REFERENCES securescope_clients(id) ON DELETE CASCADE,
    industry TEXT NOT NULL,
    main_activity TEXT NOT NULL,
    employee_band TEXT NOT NULL DEFAULT 'Unknown' CHECK (employee_band IN (
        'Unknown', '1-10', '11-25', '26-50', '51-100', '101-250',
        '251-500', '501+'
    )),
    infrastructure_model TEXT NOT NULL DEFAULT 'Unknown' CHECK (
        infrastructure_model IN (
            'Unknown', 'Cloud', 'On-premises', 'Hybrid', 'Mostly SaaS'
        )
    ),
    locations JSONB NOT NULL DEFAULT '[]'::jsonb,
    departments JSONB NOT NULL DEFAULT '[]'::jsonb,
    products_and_services JSONB NOT NULL DEFAULT '[]'::jsonb,
    technologies JSONB NOT NULL DEFAULT '[]'::jsonb,
    customer_markets JSONB NOT NULL DEFAULT '[]'::jsonb,
    certification_drivers JSONB NOT NULL DEFAULT '[]'::jsonb,
    profile_status TEXT NOT NULL DEFAULT 'Confirmed'
        CHECK (profile_status IN ('Draft', 'Confirmed')),
    updated_by TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS securescope_organization_facts (
    id BIGSERIAL PRIMARY KEY,
    client_id BIGINT NOT NULL
        REFERENCES securescope_clients(id) ON DELETE CASCADE,
    engagement_id BIGINT,
    scope_id BIGINT,
    fact_type TEXT NOT NULL,
    fact_key TEXT NOT NULL,
    value_text TEXT NOT NULL,
    source_type TEXT NOT NULL CHECK (source_type IN (
        'Guided discovery', 'Document', 'Import', 'Technical discovery',
        'Integration', 'Manual', 'AI proposal'
    )),
    source_reference TEXT NOT NULL DEFAULT '',
    confidence NUMERIC(4, 3) NOT NULL DEFAULT 1.000
        CHECK (confidence >= 0 AND confidence <= 1),
    status TEXT NOT NULL DEFAULT 'Confirmed' CHECK (status IN (
        'Proposed', 'Confirmed', 'Rejected', 'Superseded'
    )),
    verified_by TEXT,
    verified_at TIMESTAMPTZ,
    created_by TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (client_id, engagement_id, fact_type, fact_key, source_type),
    FOREIGN KEY (client_id, engagement_id)
        REFERENCES securescope_engagements(client_id, id) ON DELETE CASCADE,
    FOREIGN KEY (client_id, scope_id)
        REFERENCES securescope_scope_definitions(client_id, id) ON DELETE SET NULL,
    CHECK (
        (status = 'Confirmed' AND verified_by IS NOT NULL AND verified_at IS NOT NULL)
        OR status <> 'Confirmed'
    )
);

CREATE INDEX IF NOT EXISTS idx_org_facts_client_type_status
    ON securescope_organization_facts (client_id, fact_type, status);

CREATE INDEX IF NOT EXISTS idx_org_facts_engagement
    ON securescope_organization_facts (client_id, engagement_id, fact_type);
