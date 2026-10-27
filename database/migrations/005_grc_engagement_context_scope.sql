-- SecureScope v5.3.8 GRC engagement, context and scope foundation.
-- Additive only: migrations 001-004 and all scanner-owned records are preserved.

CREATE TABLE IF NOT EXISTS securescope_consulting_organizations (
    id BIGSERIAL PRIMARY KEY,
    organization_uuid UUID NOT NULL UNIQUE,
    name TEXT NOT NULL UNIQUE,
    legal_name TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'Active'
        CHECK (status IN ('Active', 'Inactive')),
    created_by TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (id)
);

CREATE TABLE IF NOT EXISTS securescope_consulting_organization_memberships (
    id BIGSERIAL PRIMARY KEY,
    organization_id BIGINT NOT NULL
        REFERENCES securescope_consulting_organizations(id) ON DELETE CASCADE,
    user_id BIGINT NOT NULL REFERENCES securescope_users(id) ON DELETE CASCADE,
    role TEXT NOT NULL CHECK (role IN (
        'Organization administrator', 'Portfolio manager',
        'Consultant', 'Independent reviewer'
    )),
    active BOOLEAN NOT NULL DEFAULT TRUE,
    granted_by TEXT NOT NULL,
    granted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (organization_id, user_id)
);

CREATE TABLE IF NOT EXISTS securescope_client_consulting_organizations (
    id BIGSERIAL PRIMARY KEY,
    client_id BIGINT NOT NULL
        REFERENCES securescope_clients(id) ON DELETE CASCADE,
    organization_id BIGINT NOT NULL
        REFERENCES securescope_consulting_organizations(id) ON DELETE RESTRICT,
    relationship_status TEXT NOT NULL DEFAULT 'Active'
        CHECK (relationship_status IN ('Active', 'Inactive')),
    is_primary BOOLEAN NOT NULL DEFAULT FALSE,
    started_on DATE,
    ended_on DATE,
    created_by TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (client_id, organization_id),
    CHECK (ended_on IS NULL OR started_on IS NULL OR ended_on >= started_on)
);

CREATE UNIQUE INDEX IF NOT EXISTS
    uq_client_primary_consulting_organization
    ON securescope_client_consulting_organizations(client_id)
    WHERE is_primary AND relationship_status = 'Active';

CREATE TABLE IF NOT EXISTS securescope_engagements (
    id BIGSERIAL PRIMARY KEY,
    client_id BIGINT NOT NULL
        REFERENCES securescope_clients(id) ON DELETE CASCADE,
    consulting_organization_id BIGINT NOT NULL,
    engagement_uuid UUID NOT NULL UNIQUE,
    reference TEXT NOT NULL,
    name TEXT NOT NULL,
    engagement_type TEXT NOT NULL CHECK (engagement_type IN (
        'ISO 27001 implementation', 'Initial gap assessment',
        'Stage 1 readiness', 'Stage 2 readiness', 'Internal audit',
        'Surveillance audit', 'Recertification', 'Continuous vCISO', 'Other'
    )),
    objective TEXT NOT NULL,
    target_standard TEXT NOT NULL DEFAULT 'ISO/IEC 27001:2022',
    cycle_year INTEGER CHECK (cycle_year BETWEEN 2000 AND 2200),
    status TEXT NOT NULL DEFAULT 'Draft' CHECK (status IN (
        'Draft', 'Planned', 'Active', 'On hold', 'Completed', 'Cancelled'
    )),
    planned_start_date DATE,
    planned_end_date DATE,
    certification_target_date DATE,
    client_sponsor TEXT NOT NULL DEFAULT '',
    is_default BOOLEAN NOT NULL DEFAULT FALSE,
    created_by TEXT NOT NULL,
    updated_by TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (client_id, id),
    UNIQUE (client_id, reference),
    FOREIGN KEY (client_id, consulting_organization_id)
        REFERENCES securescope_client_consulting_organizations(
            client_id,
            organization_id
        ) ON DELETE RESTRICT,
    CHECK (
        planned_end_date IS NULL
        OR planned_start_date IS NULL
        OR planned_end_date >= planned_start_date
    )
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_client_default_engagement
    ON securescope_engagements(client_id)
    WHERE is_default AND status NOT IN ('Completed', 'Cancelled');

CREATE TABLE IF NOT EXISTS securescope_engagement_members (
    id BIGSERIAL PRIMARY KEY,
    client_id BIGINT NOT NULL
        REFERENCES securescope_clients(id) ON DELETE CASCADE,
    engagement_id BIGINT NOT NULL,
    user_id BIGINT NOT NULL,
    engagement_role TEXT NOT NULL CHECK (engagement_role IN (
        'Engagement lead', 'Consultant', 'Independent reviewer',
        'Client sponsor', 'ISMS manager', 'Control owner',
        'Auditor', 'Contributor'
    )),
    active BOOLEAN NOT NULL DEFAULT TRUE,
    assigned_by TEXT NOT NULL,
    assigned_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (client_id, engagement_id, user_id, engagement_role),
    FOREIGN KEY (client_id, engagement_id)
        REFERENCES securescope_engagements(client_id, id) ON DELETE CASCADE,
    FOREIGN KEY (client_id, user_id)
        REFERENCES securescope_workspace_memberships(client_id, user_id)
        ON DELETE RESTRICT
);

CREATE TABLE IF NOT EXISTS securescope_engagement_milestones (
    id BIGSERIAL PRIMARY KEY,
    client_id BIGINT NOT NULL
        REFERENCES securescope_clients(id) ON DELETE CASCADE,
    engagement_id BIGINT NOT NULL,
    title TEXT NOT NULL,
    milestone_type TEXT NOT NULL CHECK (milestone_type IN (
        'Workshop', 'Scope approval', 'Risk assessment', 'Internal audit',
        'Management review', 'Stage 1', 'Stage 2', 'Surveillance',
        'Deliverable', 'Other'
    )),
    description TEXT NOT NULL DEFAULT '',
    owner_user_id BIGINT,
    due_date DATE NOT NULL,
    completed_at TIMESTAMPTZ,
    status TEXT NOT NULL DEFAULT 'Planned' CHECK (status IN (
        'Planned', 'In progress', 'Blocked', 'Completed', 'Cancelled'
    )),
    acceptance_criteria TEXT NOT NULL DEFAULT '',
    created_by TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (client_id, id),
    FOREIGN KEY (client_id, engagement_id)
        REFERENCES securescope_engagements(client_id, id) ON DELETE CASCADE,
    FOREIGN KEY (client_id, owner_user_id)
        REFERENCES securescope_workspace_memberships(client_id, user_id)
        ON DELETE RESTRICT,
    CHECK (
        (status = 'Completed' AND completed_at IS NOT NULL)
        OR (status <> 'Completed')
    )
);

CREATE TABLE IF NOT EXISTS securescope_scope_definitions (
    id BIGSERIAL PRIMARY KEY,
    client_id BIGINT NOT NULL
        REFERENCES securescope_clients(id) ON DELETE CASCADE,
    engagement_id BIGINT NOT NULL,
    scope_uuid UUID NOT NULL UNIQUE,
    scope_code TEXT NOT NULL,
    name TEXT NOT NULL,
    current_approved_version_id BIGINT,
    archived BOOLEAN NOT NULL DEFAULT FALSE,
    created_by TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (client_id, id),
    UNIQUE (client_id, engagement_id, scope_code),
    FOREIGN KEY (client_id, engagement_id)
        REFERENCES securescope_engagements(client_id, id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS securescope_scope_versions (
    id BIGSERIAL PRIMARY KEY,
    client_id BIGINT NOT NULL
        REFERENCES securescope_clients(id) ON DELETE CASCADE,
    engagement_id BIGINT NOT NULL,
    scope_id BIGINT NOT NULL,
    version_number INTEGER NOT NULL CHECK (version_number > 0),
    status TEXT NOT NULL DEFAULT 'Draft' CHECK (status IN (
        'Draft', 'Under review', 'Approved', 'Rejected', 'Superseded'
    )),
    scope_statement TEXT NOT NULL,
    boundaries TEXT NOT NULL DEFAULT '',
    exclusions TEXT NOT NULL DEFAULT '',
    interfaces_and_dependencies TEXT NOT NULL DEFAULT '',
    locations JSONB NOT NULL DEFAULT '[]'::jsonb,
    organizational_units JSONB NOT NULL DEFAULT '[]'::jsonb,
    products_and_services JSONB NOT NULL DEFAULT '[]'::jsonb,
    technologies JSONB NOT NULL DEFAULT '[]'::jsonb,
    assumptions JSONB NOT NULL DEFAULT '[]'::jsonb,
    prepared_by TEXT NOT NULL,
    reviewed_by TEXT,
    approved_by TEXT,
    approved_at TIMESTAMPTZ,
    approval_comment TEXT NOT NULL DEFAULT '',
    effective_from DATE,
    effective_to DATE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (client_id, id),
    UNIQUE (client_id, scope_id, version_number),
    FOREIGN KEY (client_id, engagement_id)
        REFERENCES securescope_engagements(client_id, id) ON DELETE CASCADE,
    FOREIGN KEY (client_id, scope_id)
        REFERENCES securescope_scope_definitions(client_id, id) ON DELETE CASCADE,
    CHECK (
        (status = 'Approved' AND approved_by IS NOT NULL AND approved_at IS NOT NULL)
        OR status <> 'Approved'
    ),
    CHECK (
        effective_to IS NULL
        OR effective_from IS NULL
        OR effective_to >= effective_from
    )
);

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'fk_scope_current_approved_version'
    ) THEN
        ALTER TABLE securescope_scope_definitions
            ADD CONSTRAINT fk_scope_current_approved_version
            FOREIGN KEY (current_approved_version_id)
            REFERENCES securescope_scope_versions(id)
            ON DELETE SET NULL;
    END IF;
END;
$$;

CREATE TABLE IF NOT EXISTS securescope_organizational_units (
    id BIGSERIAL PRIMARY KEY,
    client_id BIGINT NOT NULL
        REFERENCES securescope_clients(id) ON DELETE CASCADE,
    engagement_id BIGINT NOT NULL,
    scope_id BIGINT,
    unit_uuid UUID NOT NULL UNIQUE,
    parent_unit_id BIGINT,
    unit_type TEXT NOT NULL CHECK (unit_type IN (
        'Legal entity', 'Site', 'Business unit', 'Department', 'Team'
    )),
    name TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    address TEXT NOT NULL DEFAULT '',
    in_scope BOOLEAN NOT NULL DEFAULT TRUE,
    owner TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'Active'
        CHECK (status IN ('Active', 'Inactive')),
    created_by TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (client_id, id),
    UNIQUE (client_id, engagement_id, unit_type, name),
    FOREIGN KEY (client_id, engagement_id)
        REFERENCES securescope_engagements(client_id, id) ON DELETE CASCADE,
    FOREIGN KEY (client_id, scope_id)
        REFERENCES securescope_scope_definitions(client_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (client_id, parent_unit_id)
        REFERENCES securescope_organizational_units(client_id, id)
        ON DELETE RESTRICT
);

CREATE TABLE IF NOT EXISTS securescope_context_issues (
    id BIGSERIAL PRIMARY KEY,
    client_id BIGINT NOT NULL
        REFERENCES securescope_clients(id) ON DELETE CASCADE,
    engagement_id BIGINT NOT NULL,
    scope_id BIGINT,
    issue_uuid UUID NOT NULL UNIQUE,
    issue_type TEXT NOT NULL CHECK (issue_type IN ('Internal', 'External')),
    category TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    effect_on_isms TEXT NOT NULL,
    relevance TEXT NOT NULL DEFAULT 'Under review' CHECK (relevance IN (
        'Relevant', 'Not relevant', 'Under review'
    )),
    owner TEXT NOT NULL,
    review_date DATE,
    status TEXT NOT NULL DEFAULT 'Open'
        CHECK (status IN ('Open', 'Monitoring', 'Closed')),
    created_by TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (client_id, id),
    FOREIGN KEY (client_id, engagement_id)
        REFERENCES securescope_engagements(client_id, id) ON DELETE CASCADE,
    FOREIGN KEY (client_id, scope_id)
        REFERENCES securescope_scope_definitions(client_id, id) ON DELETE RESTRICT
);

CREATE TABLE IF NOT EXISTS securescope_climate_determinations (
    id BIGSERIAL PRIMARY KEY,
    client_id BIGINT NOT NULL
        REFERENCES securescope_clients(id) ON DELETE CASCADE,
    engagement_id BIGINT NOT NULL,
    scope_id BIGINT,
    version_number INTEGER NOT NULL CHECK (version_number > 0),
    determination TEXT NOT NULL CHECK (determination IN (
        'Relevant', 'Not relevant', 'Under review'
    )),
    rationale TEXT NOT NULL,
    identified_impacts TEXT NOT NULL DEFAULT '',
    determined_by TEXT NOT NULL,
    determination_date DATE NOT NULL,
    next_review_date DATE,
    approved_by TEXT,
    approved_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (client_id, id),
    UNIQUE (client_id, engagement_id, version_number),
    FOREIGN KEY (client_id, engagement_id)
        REFERENCES securescope_engagements(client_id, id) ON DELETE CASCADE,
    FOREIGN KEY (client_id, scope_id)
        REFERENCES securescope_scope_definitions(client_id, id) ON DELETE RESTRICT,
    CHECK (
        (approved_by IS NULL AND approved_at IS NULL)
        OR (approved_by IS NOT NULL AND approved_at IS NOT NULL)
    )
);

CREATE TABLE IF NOT EXISTS securescope_interested_parties (
    id BIGSERIAL PRIMARY KEY,
    client_id BIGINT NOT NULL
        REFERENCES securescope_clients(id) ON DELETE CASCADE,
    engagement_id BIGINT NOT NULL,
    scope_id BIGINT,
    party_uuid UUID NOT NULL UNIQUE,
    name TEXT NOT NULL,
    party_type TEXT NOT NULL CHECK (party_type IN (
        'Customer', 'Employee', 'Regulator', 'Supplier', 'Partner',
        'Shareholder', 'Certification body', 'Public authority', 'Other'
    )),
    relationship_description TEXT NOT NULL DEFAULT '',
    needs_and_expectations TEXT NOT NULL,
    communication_method TEXT NOT NULL DEFAULT '',
    owner TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'Active'
        CHECK (status IN ('Active', 'Inactive')),
    created_by TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (client_id, id),
    UNIQUE (client_id, engagement_id, name),
    FOREIGN KEY (client_id, engagement_id)
        REFERENCES securescope_engagements(client_id, id) ON DELETE CASCADE,
    FOREIGN KEY (client_id, scope_id)
        REFERENCES securescope_scope_definitions(client_id, id) ON DELETE RESTRICT
);

CREATE TABLE IF NOT EXISTS securescope_interested_party_requirements (
    id BIGSERIAL PRIMARY KEY,
    client_id BIGINT NOT NULL
        REFERENCES securescope_clients(id) ON DELETE CASCADE,
    engagement_id BIGINT NOT NULL,
    scope_id BIGINT,
    party_id BIGINT NOT NULL,
    requirement_type TEXT NOT NULL CHECK (requirement_type IN (
        'Legal', 'Regulatory', 'Contractual', 'Stakeholder', 'Internal'
    )),
    requirement TEXT NOT NULL,
    source_reference TEXT NOT NULL DEFAULT '',
    applicability TEXT NOT NULL DEFAULT 'Applicable' CHECK (applicability IN (
        'Applicable', 'Not applicable', 'Under review'
    )),
    mandatory BOOLEAN NOT NULL DEFAULT TRUE,
    owner TEXT NOT NULL,
    review_date DATE,
    created_by TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (client_id, id),
    FOREIGN KEY (client_id, engagement_id)
        REFERENCES securescope_engagements(client_id, id) ON DELETE CASCADE,
    FOREIGN KEY (client_id, scope_id)
        REFERENCES securescope_scope_definitions(client_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (client_id, party_id)
        REFERENCES securescope_interested_parties(client_id, id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS securescope_isms_role_assignments (
    id BIGSERIAL PRIMARY KEY,
    client_id BIGINT NOT NULL
        REFERENCES securescope_clients(id) ON DELETE CASCADE,
    engagement_id BIGINT NOT NULL,
    scope_id BIGINT,
    user_id BIGINT NOT NULL,
    role_name TEXT NOT NULL,
    responsibility TEXT NOT NULL,
    raci_type TEXT NOT NULL CHECK (raci_type IN (
        'Responsible', 'Accountable', 'Consulted', 'Informed'
    )),
    authority TEXT NOT NULL DEFAULT '',
    effective_from DATE NOT NULL,
    effective_to DATE,
    status TEXT NOT NULL DEFAULT 'Active'
        CHECK (status IN ('Active', 'Inactive')),
    assigned_by TEXT NOT NULL,
    assigned_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (
        client_id,
        engagement_id,
        scope_id,
        user_id,
        role_name,
        raci_type
    ),
    UNIQUE (client_id, id),
    FOREIGN KEY (client_id, engagement_id)
        REFERENCES securescope_engagements(client_id, id) ON DELETE CASCADE,
    FOREIGN KEY (client_id, scope_id)
        REFERENCES securescope_scope_definitions(client_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (client_id, user_id)
        REFERENCES securescope_workspace_memberships(client_id, user_id)
        ON DELETE RESTRICT,
    CHECK (effective_to IS NULL OR effective_to >= effective_from)
);

CREATE TABLE IF NOT EXISTS securescope_grc_approvals (
    id BIGSERIAL PRIMARY KEY,
    client_id BIGINT NOT NULL
        REFERENCES securescope_clients(id) ON DELETE CASCADE,
    engagement_id BIGINT NOT NULL,
    scope_id BIGINT,
    subject_type TEXT NOT NULL,
    subject_id BIGINT NOT NULL,
    subject_version INTEGER,
    decision TEXT NOT NULL CHECK (decision IN ('Approved', 'Rejected')),
    decision_by_user_id BIGINT NOT NULL,
    comment TEXT NOT NULL,
    decided_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (client_id, id),
    FOREIGN KEY (client_id, engagement_id)
        REFERENCES securescope_engagements(client_id, id) ON DELETE CASCADE,
    FOREIGN KEY (client_id, scope_id)
        REFERENCES securescope_scope_definitions(client_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (client_id, decision_by_user_id)
        REFERENCES securescope_workspace_memberships(client_id, user_id)
        ON DELETE RESTRICT
);

CREATE TABLE IF NOT EXISTS securescope_engagement_record_links (
    id BIGSERIAL PRIMARY KEY,
    client_id BIGINT NOT NULL
        REFERENCES securescope_clients(id) ON DELETE CASCADE,
    engagement_id BIGINT NOT NULL,
    scope_id BIGINT,
    link_key TEXT NOT NULL,
    evidence_id BIGINT,
    assessment_id BIGINT,
    gap_id BIGINT,
    finding_id BIGINT,
    soa_version_id BIGINT,
    treatment_plan_id BIGINT,
    link_origin TEXT NOT NULL CHECK (link_origin IN (
        'Legacy backfill', 'Manual association', 'Scope inheritance'
    )),
    rationale TEXT NOT NULL DEFAULT '',
    linked_by TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (client_id, id),
    UNIQUE (client_id, engagement_id, link_key),
    FOREIGN KEY (client_id, engagement_id)
        REFERENCES securescope_engagements(client_id, id) ON DELETE CASCADE,
    FOREIGN KEY (client_id, scope_id)
        REFERENCES securescope_scope_definitions(client_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (client_id, evidence_id)
        REFERENCES securescope_evidence_records(client_id, id) ON DELETE CASCADE,
    FOREIGN KEY (client_id, assessment_id)
        REFERENCES securescope_control_assessments(client_id, id) ON DELETE CASCADE,
    FOREIGN KEY (client_id, gap_id)
        REFERENCES securescope_control_gaps(client_id, id) ON DELETE CASCADE,
    FOREIGN KEY (client_id, finding_id)
        REFERENCES securescope_findings(client_id, id) ON DELETE CASCADE,
    FOREIGN KEY (client_id, soa_version_id)
        REFERENCES securescope_soa_versions(client_id, id) ON DELETE CASCADE,
    FOREIGN KEY (client_id, treatment_plan_id)
        REFERENCES securescope_risk_treatment_plans(client_id, id)
        ON DELETE CASCADE,
    CHECK (num_nonnulls(
        evidence_id,
        assessment_id,
        gap_id,
        finding_id,
        soa_version_id,
        treatment_plan_id
    ) = 1)
);

CREATE TABLE IF NOT EXISTS securescope_grc_audit_events (
    id BIGSERIAL PRIMARY KEY,
    client_id BIGINT NOT NULL
        REFERENCES securescope_clients(id) ON DELETE CASCADE,
    engagement_id BIGINT,
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
    UNIQUE (client_id, event_hash),
    FOREIGN KEY (client_id, engagement_id)
        REFERENCES securescope_engagements(client_id, id) ON DELETE CASCADE
);

CREATE OR REPLACE FUNCTION securescope_guard_approved_scope_version()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' AND NOT EXISTS (
        SELECT 1 FROM securescope_clients WHERE id = OLD.client_id
    ) THEN
        RETURN OLD;
    END IF;
    IF OLD.status = 'Approved' THEN
        RAISE EXCEPTION 'Approved SecureScope scope versions are immutable';
    END IF;
    IF TG_OP = 'DELETE' THEN
        RETURN OLD;
    END IF;
    RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION securescope_reject_immutable_grc_change()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' AND NOT EXISTS (
        SELECT 1 FROM securescope_clients WHERE id = OLD.client_id
    ) THEN
        RETURN OLD;
    END IF;
    RAISE EXCEPTION 'SecureScope GRC approval and audit records are immutable';
END;
$$;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_trigger
        WHERE tgname = 'trg_securescope_scope_version_immutable'
    ) THEN
        CREATE TRIGGER trg_securescope_scope_version_immutable
        BEFORE UPDATE OR DELETE ON securescope_scope_versions
        FOR EACH ROW EXECUTE FUNCTION securescope_guard_approved_scope_version();
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_trigger
        WHERE tgname = 'trg_securescope_grc_approval_immutable'
    ) THEN
        CREATE TRIGGER trg_securescope_grc_approval_immutable
        BEFORE UPDATE OR DELETE ON securescope_grc_approvals
        FOR EACH ROW EXECUTE FUNCTION securescope_reject_immutable_grc_change();
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_trigger
        WHERE tgname = 'trg_securescope_grc_audit_immutable'
    ) THEN
        CREATE TRIGGER trg_securescope_grc_audit_immutable
        BEFORE UPDATE OR DELETE ON securescope_grc_audit_events
        FOR EACH ROW EXECUTE FUNCTION securescope_reject_immutable_grc_change();
    END IF;
END;
$$;

CREATE INDEX IF NOT EXISTS idx_engagements_client_status
    ON securescope_engagements(client_id, status, planned_end_date);
CREATE INDEX IF NOT EXISTS idx_engagement_members_client_engagement
    ON securescope_engagement_members(client_id, engagement_id, active);
CREATE INDEX IF NOT EXISTS idx_engagement_milestones_due
    ON securescope_engagement_milestones(
        client_id,
        engagement_id,
        status,
        due_date
    );
CREATE INDEX IF NOT EXISTS idx_scope_definitions_engagement
    ON securescope_scope_definitions(client_id, engagement_id, archived);
CREATE INDEX IF NOT EXISTS idx_scope_versions_scope
    ON securescope_scope_versions(client_id, scope_id, version_number DESC);
CREATE INDEX IF NOT EXISTS idx_context_issues_engagement
    ON securescope_context_issues(client_id, engagement_id, status, relevance);
CREATE INDEX IF NOT EXISTS idx_interested_parties_engagement
    ON securescope_interested_parties(client_id, engagement_id, status);
CREATE INDEX IF NOT EXISTS idx_party_requirements_engagement
    ON securescope_interested_party_requirements(
        client_id,
        engagement_id,
        applicability
    );
CREATE INDEX IF NOT EXISTS idx_organizational_units_engagement
    ON securescope_organizational_units(
        client_id,
        engagement_id,
        in_scope,
        unit_type
    );
CREATE INDEX IF NOT EXISTS idx_isms_roles_engagement
    ON securescope_isms_role_assignments(
        client_id,
        engagement_id,
        status,
        raci_type
    );
CREATE INDEX IF NOT EXISTS idx_grc_approvals_subject
    ON securescope_grc_approvals(
        client_id,
        engagement_id,
        subject_type,
        subject_id,
        decided_at DESC
    );
CREATE INDEX IF NOT EXISTS idx_engagement_record_links_context
    ON securescope_engagement_record_links(
        client_id,
        engagement_id,
        scope_id,
        created_at DESC
    );
CREATE INDEX IF NOT EXISTS idx_grc_audit_client_time
    ON securescope_grc_audit_events(client_id, created_at DESC);

-- Backfill one safe foundation for every pre-v5.3.8 workspace. Existing rows
-- are referenced; scanner, evidence, assessment and report tables are untouched.
INSERT INTO securescope_consulting_organizations (
    organization_uuid,
    name,
    legal_name,
    status,
    created_by
)
VALUES (
    md5('securescope-default-consulting-organization')::uuid,
    'Default Consulting Organization',
    '',
    'Active',
    'migration-005'
)
ON CONFLICT (name) DO NOTHING;

INSERT INTO securescope_client_consulting_organizations (
    client_id,
    organization_id,
    relationship_status,
    is_primary,
    started_on,
    created_by
)
SELECT
    client.id,
    organization.id,
    'Active',
    TRUE,
    CURRENT_DATE,
    'migration-005'
FROM securescope_clients AS client
CROSS JOIN securescope_consulting_organizations AS organization
WHERE organization.name = 'Default Consulting Organization'
ON CONFLICT (client_id, organization_id) DO NOTHING;

INSERT INTO securescope_engagements (
    client_id,
    consulting_organization_id,
    engagement_uuid,
    reference,
    name,
    engagement_type,
    objective,
    target_standard,
    cycle_year,
    status,
    planned_start_date,
    is_default,
    created_by,
    updated_by
)
SELECT
    relationship.client_id,
    relationship.organization_id,
    md5('securescope-default-engagement:' || relationship.client_id::text)::uuid,
    'LEGACY-ISO-' || relationship.client_id::text,
    'Existing ISO 27001 Programme',
    'ISO 27001 implementation',
    'Continue the existing SecureScope ISO/IEC 27001 programme.',
    'ISO/IEC 27001:2022',
    EXTRACT(YEAR FROM CURRENT_DATE)::integer,
    'Active',
    CURRENT_DATE,
    TRUE,
    'migration-005',
    'migration-005'
FROM securescope_client_consulting_organizations AS relationship
WHERE relationship.is_primary
ON CONFLICT (client_id, reference) DO NOTHING;

INSERT INTO securescope_scope_definitions (
    client_id,
    engagement_id,
    scope_uuid,
    scope_code,
    name,
    created_by
)
SELECT
    engagement.client_id,
    engagement.id,
    md5('securescope-default-scope:' || engagement.id::text)::uuid,
    'DEFAULT-SCOPE',
    'Existing ISMS Scope',
    'migration-005'
FROM securescope_engagements AS engagement
WHERE engagement.is_default
ON CONFLICT (client_id, engagement_id, scope_code) DO NOTHING;

INSERT INTO securescope_scope_versions (
    client_id,
    engagement_id,
    scope_id,
    version_number,
    status,
    scope_statement,
    boundaries,
    exclusions,
    interfaces_and_dependencies,
    prepared_by
)
SELECT
    scope.client_id,
    scope.engagement_id,
    scope.id,
    1,
    'Draft',
    'Define and approve the ISMS scope for this existing client workspace.',
    '',
    '',
    '',
    'migration-005'
FROM securescope_scope_definitions AS scope
JOIN securescope_engagements AS engagement
  ON engagement.client_id = scope.client_id
 AND engagement.id = scope.engagement_id
WHERE engagement.is_default
ON CONFLICT (client_id, scope_id, version_number) DO NOTHING;

WITH default_context AS (
    SELECT
        engagement.client_id,
        engagement.id AS engagement_id,
        scope.id AS scope_id
    FROM securescope_engagements AS engagement
    JOIN securescope_scope_definitions AS scope
      ON scope.client_id = engagement.client_id
     AND scope.engagement_id = engagement.id
    WHERE engagement.is_default
      AND scope.scope_code = 'DEFAULT-SCOPE'
)
INSERT INTO securescope_engagement_record_links (
    client_id,
    engagement_id,
    scope_id,
    link_key,
    evidence_id,
    link_origin,
    rationale,
    linked_by
)
SELECT
    context.client_id,
    context.engagement_id,
    context.scope_id,
    'evidence:' || evidence.id::text,
    evidence.id,
    'Legacy backfill',
    'Evidence existed before engagement-aware GRC context.',
    'migration-005'
FROM default_context AS context
JOIN securescope_evidence_records AS evidence
  ON evidence.client_id = context.client_id
ON CONFLICT (client_id, engagement_id, link_key) DO NOTHING;

WITH default_context AS (
    SELECT
        engagement.client_id,
        engagement.id AS engagement_id,
        scope.id AS scope_id
    FROM securescope_engagements AS engagement
    JOIN securescope_scope_definitions AS scope
      ON scope.client_id = engagement.client_id
     AND scope.engagement_id = engagement.id
    WHERE engagement.is_default
      AND scope.scope_code = 'DEFAULT-SCOPE'
)
INSERT INTO securescope_engagement_record_links (
    client_id,
    engagement_id,
    scope_id,
    link_key,
    assessment_id,
    link_origin,
    rationale,
    linked_by
)
SELECT
    context.client_id,
    context.engagement_id,
    context.scope_id,
    'assessment:' || assessment.id::text,
    assessment.id,
    'Legacy backfill',
    'Assessment existed before engagement-aware GRC context.',
    'migration-005'
FROM default_context AS context
JOIN securescope_control_assessments AS assessment
  ON assessment.client_id = context.client_id
ON CONFLICT (client_id, engagement_id, link_key) DO NOTHING;

WITH default_context AS (
    SELECT
        engagement.client_id,
        engagement.id AS engagement_id,
        scope.id AS scope_id
    FROM securescope_engagements AS engagement
    JOIN securescope_scope_definitions AS scope
      ON scope.client_id = engagement.client_id
     AND scope.engagement_id = engagement.id
    WHERE engagement.is_default
      AND scope.scope_code = 'DEFAULT-SCOPE'
)
INSERT INTO securescope_engagement_record_links (
    client_id,
    engagement_id,
    scope_id,
    link_key,
    gap_id,
    link_origin,
    rationale,
    linked_by
)
SELECT
    context.client_id,
    context.engagement_id,
    context.scope_id,
    'gap:' || gap.id::text,
    gap.id,
    'Legacy backfill',
    'Control gap existed before engagement-aware GRC context.',
    'migration-005'
FROM default_context AS context
JOIN securescope_control_gaps AS gap
  ON gap.client_id = context.client_id
ON CONFLICT (client_id, engagement_id, link_key) DO NOTHING;

WITH default_context AS (
    SELECT
        engagement.client_id,
        engagement.id AS engagement_id,
        scope.id AS scope_id
    FROM securescope_engagements AS engagement
    JOIN securescope_scope_definitions AS scope
      ON scope.client_id = engagement.client_id
     AND scope.engagement_id = engagement.id
    WHERE engagement.is_default
      AND scope.scope_code = 'DEFAULT-SCOPE'
)
INSERT INTO securescope_engagement_record_links (
    client_id,
    engagement_id,
    scope_id,
    link_key,
    finding_id,
    link_origin,
    rationale,
    linked_by
)
SELECT
    context.client_id,
    context.engagement_id,
    context.scope_id,
    'finding:' || finding.id::text,
    finding.id,
    'Legacy backfill',
    'Finding existed before engagement-aware GRC context.',
    'migration-005'
FROM default_context AS context
JOIN securescope_findings AS finding
  ON finding.client_id = context.client_id
ON CONFLICT (client_id, engagement_id, link_key) DO NOTHING;

WITH default_context AS (
    SELECT
        engagement.client_id,
        engagement.id AS engagement_id,
        scope.id AS scope_id
    FROM securescope_engagements AS engagement
    JOIN securescope_scope_definitions AS scope
      ON scope.client_id = engagement.client_id
     AND scope.engagement_id = engagement.id
    WHERE engagement.is_default
      AND scope.scope_code = 'DEFAULT-SCOPE'
)
INSERT INTO securescope_engagement_record_links (
    client_id,
    engagement_id,
    scope_id,
    link_key,
    soa_version_id,
    link_origin,
    rationale,
    linked_by
)
SELECT
    context.client_id,
    context.engagement_id,
    context.scope_id,
    'soa:' || soa.id::text,
    soa.id,
    'Legacy backfill',
    'SoA version existed before engagement-aware GRC context.',
    'migration-005'
FROM default_context AS context
JOIN securescope_soa_versions AS soa
  ON soa.client_id = context.client_id
ON CONFLICT (client_id, engagement_id, link_key) DO NOTHING;

WITH default_context AS (
    SELECT
        engagement.client_id,
        engagement.id AS engagement_id,
        scope.id AS scope_id
    FROM securescope_engagements AS engagement
    JOIN securescope_scope_definitions AS scope
      ON scope.client_id = engagement.client_id
     AND scope.engagement_id = engagement.id
    WHERE engagement.is_default
      AND scope.scope_code = 'DEFAULT-SCOPE'
)
INSERT INTO securescope_engagement_record_links (
    client_id,
    engagement_id,
    scope_id,
    link_key,
    treatment_plan_id,
    link_origin,
    rationale,
    linked_by
)
SELECT
    context.client_id,
    context.engagement_id,
    context.scope_id,
    'treatment-plan:' || treatment.id::text,
    treatment.id,
    'Legacy backfill',
    'Treatment plan existed before engagement-aware GRC context.',
    'migration-005'
FROM default_context AS context
JOIN securescope_risk_treatment_plans AS treatment
  ON treatment.client_id = context.client_id
ON CONFLICT (client_id, engagement_id, link_key) DO NOTHING;
