-- SecureScope v6.0 exposure-management and GRC schema.
-- Additive migration: existing scanner, history and ISO tables are preserved.

CREATE TABLE IF NOT EXISTS securescope_findings (
    id BIGSERIAL PRIMARY KEY,
    client_id BIGINT NOT NULL
        REFERENCES securescope_clients(id) ON DELETE CASCADE,
    finding_uuid UUID NOT NULL UNIQUE,
    fingerprint CHAR(64) NOT NULL,
    asset_identity TEXT NOT NULL,
    vulnerability_identity TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    severity TEXT NOT NULL DEFAULT 'Unknown'
        CHECK (severity IN ('Critical', 'High', 'Medium', 'Low', 'Info', 'Unknown')),
    cvss NUMERIC(4, 1),
    port TEXT NOT NULL DEFAULT '',
    protocol TEXT NOT NULL DEFAULT 'unknown',
    component TEXT NOT NULL DEFAULT 'unknown-component',
    lifecycle_status TEXT NOT NULL DEFAULT 'New'
        CHECK (lifecycle_status IN (
            'New', 'Triaged', 'Planned', 'In progress', 'Mitigated',
            'Ready for verification', 'Closed', 'Accepted risk',
            'False positive', 'Reopened'
        )),
    treatment_decision TEXT
        CHECK (treatment_decision IS NULL OR treatment_decision IN (
            'Remediate', 'Mitigate', 'Accept', 'Avoid', 'False positive'
        )),
    first_seen TIMESTAMPTZ NOT NULL,
    last_seen TIMESTAMPTZ NOT NULL,
    observation_count INTEGER NOT NULL DEFAULT 0 CHECK (observation_count >= 0),
    scanners JSONB NOT NULL DEFAULT '[]'::jsonb,
    kev_known_exploited BOOLEAN,
    epss_score NUMERIC(6, 5) CHECK (epss_score BETWEEN 0 AND 1),
    verification_state TEXT NOT NULL DEFAULT 'Not verified',
    most_recent_evidence JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_by TEXT,
    updated_by TEXT,
    version INTEGER NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (client_id, fingerprint),
    UNIQUE (client_id, id),
    CHECK (last_seen >= first_seen)
);

CREATE TABLE IF NOT EXISTS securescope_finding_observations (
    id BIGSERIAL PRIMARY KEY,
    client_id BIGINT NOT NULL
        REFERENCES securescope_clients(id) ON DELETE CASCADE,
    finding_id BIGINT NOT NULL,
    observation_key CHAR(64) NOT NULL,
    scanner TEXT NOT NULL,
    report_id TEXT NOT NULL,
    provider_observation_id TEXT NOT NULL DEFAULT '',
    observed_at TIMESTAMPTZ NOT NULL,
    severity TEXT NOT NULL DEFAULT 'Unknown',
    raw_evidence JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    FOREIGN KEY (client_id, finding_id)
        REFERENCES securescope_findings(client_id, id) ON DELETE CASCADE,
    UNIQUE (client_id, observation_key),
    UNIQUE (client_id, id)
);

CREATE TABLE IF NOT EXISTS securescope_finding_status_history (
    id BIGSERIAL PRIMARY KEY,
    client_id BIGINT NOT NULL
        REFERENCES securescope_clients(id) ON DELETE CASCADE,
    finding_id BIGINT NOT NULL,
    from_status TEXT,
    to_status TEXT NOT NULL,
    reason TEXT NOT NULL,
    evidence_reference TEXT,
    changed_by TEXT,
    changed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    FOREIGN KEY (client_id, finding_id)
        REFERENCES securescope_findings(client_id, id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS securescope_remediation_plans (
    id BIGSERIAL PRIMARY KEY,
    client_id BIGINT NOT NULL
        REFERENCES securescope_clients(id) ON DELETE CASCADE,
    plan_uuid UUID NOT NULL UNIQUE,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    priority TEXT NOT NULL CHECK (priority IN ('Critical', 'High', 'Medium', 'Low')),
    status TEXT NOT NULL DEFAULT 'Draft'
        CHECK (status IN (
            'Draft', 'Approved', 'In progress', 'Blocked',
            'Ready for verification', 'Completed', 'Cancelled'
        )),
    treatment_decision TEXT NOT NULL
        CHECK (treatment_decision IN (
            'Remediate', 'Mitigate', 'Accept', 'Avoid', 'False positive'
        )),
    remediation_owner TEXT NOT NULL,
    technical_owner TEXT NOT NULL,
    business_owner TEXT NOT NULL,
    risk_owner TEXT NOT NULL,
    start_date DATE,
    due_date DATE NOT NULL,
    sla_days INTEGER NOT NULL CHECK (sla_days > 0),
    required_resources TEXT NOT NULL DEFAULT '',
    dependencies TEXT NOT NULL DEFAULT '',
    implementation_steps TEXT NOT NULL DEFAULT '',
    compensating_controls TEXT NOT NULL DEFAULT '',
    expected_risk_reduction TEXT NOT NULL DEFAULT '',
    success_criteria TEXT NOT NULL,
    validation_method TEXT NOT NULL,
    linked_rescan_reference TEXT,
    closure_evidence_reference TEXT,
    created_by TEXT,
    updated_by TEXT,
    version INTEGER NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (client_id, id),
    CHECK (start_date IS NULL OR due_date >= start_date)
);

CREATE TABLE IF NOT EXISTS securescope_remediation_plan_findings (
    client_id BIGINT NOT NULL
        REFERENCES securescope_clients(id) ON DELETE CASCADE,
    plan_id BIGINT NOT NULL,
    finding_id BIGINT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (client_id, plan_id, finding_id),
    FOREIGN KEY (client_id, plan_id)
        REFERENCES securescope_remediation_plans(client_id, id) ON DELETE CASCADE,
    FOREIGN KEY (client_id, finding_id)
        REFERENCES securescope_findings(client_id, id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS securescope_remediation_tasks (
    id BIGSERIAL PRIMARY KEY,
    client_id BIGINT NOT NULL
        REFERENCES securescope_clients(id) ON DELETE CASCADE,
    plan_id BIGINT NOT NULL,
    title TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    owner TEXT NOT NULL,
    priority TEXT NOT NULL CHECK (priority IN ('Critical', 'High', 'Medium', 'Low')),
    status TEXT NOT NULL DEFAULT 'Open'
        CHECK (status IN (
            'Open', 'In progress', 'Blocked', 'Ready for verification',
            'Completed', 'Cancelled'
        )),
    start_date DATE,
    due_date DATE NOT NULL,
    sla_days INTEGER NOT NULL CHECK (sla_days > 0),
    dependency_task_id BIGINT,
    success_criteria TEXT NOT NULL,
    verification_method TEXT NOT NULL,
    created_by TEXT,
    updated_by TEXT,
    version INTEGER NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (client_id, id),
    FOREIGN KEY (client_id, plan_id)
        REFERENCES securescope_remediation_plans(client_id, id) ON DELETE CASCADE,
    FOREIGN KEY (client_id, dependency_task_id)
        REFERENCES securescope_remediation_tasks(client_id, id) ON DELETE RESTRICT,
    CHECK (start_date IS NULL OR due_date >= start_date)
);

CREATE TABLE IF NOT EXISTS securescope_remediation_milestones (
    id BIGSERIAL PRIMARY KEY,
    client_id BIGINT NOT NULL
        REFERENCES securescope_clients(id) ON DELETE CASCADE,
    plan_id BIGINT NOT NULL,
    task_id BIGINT,
    title TEXT NOT NULL,
    owner TEXT NOT NULL,
    priority TEXT NOT NULL CHECK (priority IN ('Critical', 'High', 'Medium', 'Low')),
    status TEXT NOT NULL DEFAULT 'Open'
        CHECK (status IN ('Open', 'In progress', 'Blocked', 'Completed', 'Cancelled')),
    due_date DATE NOT NULL,
    sla_days INTEGER NOT NULL CHECK (sla_days > 0),
    completion_date DATE,
    success_criteria TEXT NOT NULL,
    evidence_reference TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (client_id, id),
    FOREIGN KEY (client_id, plan_id)
        REFERENCES securescope_remediation_plans(client_id, id) ON DELETE CASCADE,
    FOREIGN KEY (client_id, task_id)
        REFERENCES securescope_remediation_tasks(client_id, id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS securescope_verification_evidence (
    id BIGSERIAL PRIMARY KEY,
    client_id BIGINT NOT NULL
        REFERENCES securescope_clients(id) ON DELETE CASCADE,
    finding_id BIGINT,
    plan_id BIGINT,
    task_id BIGINT,
    milestone_id BIGINT,
    evidence_type TEXT NOT NULL,
    source TEXT NOT NULL,
    raw_reference TEXT NOT NULL,
    summary TEXT NOT NULL,
    collected_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ,
    confidence TEXT NOT NULL CHECK (confidence IN ('Low', 'Medium', 'High')),
    validation_status TEXT NOT NULL DEFAULT 'Pending'
        CHECK (validation_status IN ('Pending', 'Validated', 'Rejected', 'Expired')),
    validator TEXT,
    validation_date DATE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    FOREIGN KEY (client_id, finding_id)
        REFERENCES securescope_findings(client_id, id) ON DELETE CASCADE,
    FOREIGN KEY (client_id, plan_id)
        REFERENCES securescope_remediation_plans(client_id, id) ON DELETE CASCADE,
    FOREIGN KEY (client_id, task_id)
        REFERENCES securescope_remediation_tasks(client_id, id) ON DELETE CASCADE,
    FOREIGN KEY (client_id, milestone_id)
        REFERENCES securescope_remediation_milestones(client_id, id) ON DELETE CASCADE,
    CHECK (num_nonnulls(finding_id, plan_id, task_id, milestone_id) >= 1),
    CHECK (expires_at IS NULL OR expires_at > collected_at)
);

CREATE TABLE IF NOT EXISTS securescope_comments (
    id BIGSERIAL PRIMARY KEY,
    client_id BIGINT NOT NULL
        REFERENCES securescope_clients(id) ON DELETE CASCADE,
    entity_type TEXT NOT NULL,
    entity_id BIGINT NOT NULL,
    comment_text TEXT NOT NULL,
    author TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS securescope_control_assessment_profiles (
    id BIGSERIAL PRIMARY KEY,
    client_id BIGINT NOT NULL
        REFERENCES securescope_clients(id) ON DELETE CASCADE,
    control_id TEXT NOT NULL,
    control_name TEXT NOT NULL,
    profile_version INTEGER NOT NULL CHECK (profile_version > 0),
    control_objective TEXT NOT NULL,
    expected_security_outcome TEXT NOT NULL,
    applicability TEXT NOT NULL DEFAULT 'Not reviewed',
    inclusion_justification TEXT NOT NULL DEFAULT '',
    exclusion_justification TEXT NOT NULL DEFAULT '',
    assessment_scope JSONB NOT NULL DEFAULT '{}'::jsonb,
    scope_inclusion_rules JSONB NOT NULL DEFAULT '[]'::jsonb,
    scope_exclusion_rules JSONB NOT NULL DEFAULT '[]'::jsonb,
    risk_addressed TEXT NOT NULL DEFAULT '',
    control_owner TEXT NOT NULL DEFAULT '',
    assessment_owner TEXT NOT NULL DEFAULT '',
    assessment_frequency TEXT NOT NULL DEFAULT '',
    assessment_methods JSONB NOT NULL DEFAULT '[]'::jsonb,
    evidence_requirements JSONB NOT NULL DEFAULT '[]'::jsonb,
    measurement_model TEXT NOT NULL
        CHECK (measurement_model IN (
            'quantitative_coverage', 'checklist', 'process_capability',
            'timeliness_sla', 'effectiveness_test', 'evidence_documentation',
            'risk_based', 'composite'
        )),
    measurement_criteria JSONB NOT NULL DEFAULT '{}'::jsonb,
    target_state_criteria JSONB NOT NULL DEFAULT '{}'::jsonb,
    effectiveness_tests JSONB NOT NULL DEFAULT '[]'::jsonb,
    validation_requirements JSONB NOT NULL DEFAULT '{}'::jsonb,
    acceptable_evidence_age_days INTEGER CHECK (acceptable_evidence_age_days > 0),
    scoring_rules JSONB,
    automation_level TEXT NOT NULL DEFAULT 'Manual',
    supported_data_sources JSONB NOT NULL DEFAULT '[]'::jsonb,
    approval_status TEXT NOT NULL DEFAULT 'Draft'
        CHECK (approval_status IN ('Draft', 'Approved', 'Retired')),
    approver TEXT,
    approval_date DATE,
    created_by TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (client_id, control_id, profile_version),
    UNIQUE (client_id, id)
);

CREATE TABLE IF NOT EXISTS securescope_control_criteria (
    id BIGSERIAL PRIMARY KEY,
    client_id BIGINT NOT NULL
        REFERENCES securescope_clients(id) ON DELETE CASCADE,
    profile_id BIGINT NOT NULL,
    criterion_id TEXT NOT NULL,
    description TEXT NOT NULL,
    required BOOLEAN NOT NULL DEFAULT TRUE,
    assessment_method TEXT NOT NULL,
    expected_evidence TEXT NOT NULL,
    weight NUMERIC(7, 4),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (client_id, profile_id, criterion_id),
    UNIQUE (client_id, id),
    FOREIGN KEY (client_id, profile_id)
        REFERENCES securescope_control_assessment_profiles(client_id, id)
        ON DELETE CASCADE,
    CHECK (weight IS NULL OR weight > 0)
);

CREATE TABLE IF NOT EXISTS securescope_control_targets (
    id BIGSERIAL PRIMARY KEY,
    client_id BIGINT NOT NULL
        REFERENCES securescope_clients(id) ON DELETE CASCADE,
    profile_id BIGINT NOT NULL,
    target_version INTEGER NOT NULL CHECK (target_version > 0),
    target_description TEXT NOT NULL,
    target_metric TEXT,
    target_value NUMERIC,
    unit TEXT,
    minimum_threshold NUMERIC,
    target_date DATE NOT NULL,
    rationale TEXT NOT NULL,
    risk_basis TEXT NOT NULL,
    remaining_scope_justification TEXT,
    required_evidence JSONB NOT NULL DEFAULT '[]'::jsonb,
    required_effectiveness_test TEXT,
    approver TEXT NOT NULL,
    approval_date DATE NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (client_id, profile_id, target_version),
    UNIQUE (client_id, id),
    FOREIGN KEY (client_id, profile_id)
        REFERENCES securescope_control_assessment_profiles(client_id, id)
        ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS securescope_control_assessments (
    id BIGSERIAL PRIMARY KEY,
    client_id BIGINT NOT NULL
        REFERENCES securescope_clients(id) ON DELETE CASCADE,
    profile_id BIGINT NOT NULL,
    target_id BIGINT,
    assessment_period_start DATE,
    assessment_period_end DATE,
    assessment_status TEXT NOT NULL
        CHECK (assessment_status IN (
            'Not assessed', 'Manual assessment required', 'Insufficient evidence',
            'Not implemented', 'Gap identified', 'Partially implemented',
            'Implemented but not verified', 'Target achieved',
            'Implemented and effective', 'Accepted residual risk', 'Not applicable'
        )),
    automated_recommendation TEXT,
    scope_definition TEXT NOT NULL DEFAULT '',
    current_state TEXT NOT NULL DEFAULT '',
    target_state TEXT NOT NULL DEFAULT '',
    gap_statement TEXT NOT NULL DEFAULT '',
    measurement_details JSONB NOT NULL DEFAULT '{}'::jsonb,
    denominator_definition TEXT,
    total_in_scope INTEGER CHECK (total_in_scope >= 0),
    covered_in_scope INTEGER CHECK (covered_in_scope >= 0),
    excluded_units INTEGER CHECK (excluded_units >= 0),
    exclusion_justification TEXT,
    baseline_value NUMERIC,
    current_value NUMERIC,
    target_value NUMERIC,
    unit TEXT,
    calculation_formula TEXT,
    remaining_gap NUMERIC,
    additional_required INTEGER CHECK (additional_required >= 0),
    evidence_freshness TEXT NOT NULL DEFAULT 'Unknown'
        CHECK (evidence_freshness IN ('Current', 'Approaching expiration', 'Expired', 'Unknown')),
    confidence TEXT NOT NULL DEFAULT 'Low'
        CHECK (confidence IN ('Low', 'Medium', 'High')),
    accountable_owner TEXT NOT NULL DEFAULT '',
    validation_status TEXT NOT NULL DEFAULT 'Pending',
    validator TEXT,
    validation_date DATE,
    assurance_score NUMERIC(5, 2) CHECK (assurance_score BETWEEN 0 AND 100),
    created_by TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (client_id, id),
    FOREIGN KEY (client_id, profile_id)
        REFERENCES securescope_control_assessment_profiles(client_id, id)
        ON DELETE CASCADE,
    FOREIGN KEY (client_id, target_id)
        REFERENCES securescope_control_targets(client_id, id) ON DELETE RESTRICT,
    CHECK (
        total_in_scope IS NULL OR covered_in_scope IS NULL
        OR covered_in_scope <= total_in_scope
    ),
    CHECK (
        assessment_period_start IS NULL OR assessment_period_end IS NULL
        OR assessment_period_end >= assessment_period_start
    )
);

CREATE TABLE IF NOT EXISTS securescope_control_criterion_results (
    id BIGSERIAL PRIMARY KEY,
    client_id BIGINT NOT NULL
        REFERENCES securescope_clients(id) ON DELETE CASCADE,
    assessment_id BIGINT NOT NULL,
    criterion_id BIGINT,
    criterion_identifier TEXT NOT NULL,
    description TEXT NOT NULL,
    required BOOLEAN NOT NULL DEFAULT TRUE,
    assessment_method TEXT NOT NULL,
    expected_evidence TEXT NOT NULL,
    result TEXT NOT NULL
        CHECK (result IN ('Pass', 'Partial', 'Fail', 'Not assessed', 'Not applicable')),
    evidence_reference TEXT,
    assessor TEXT NOT NULL,
    assessor_comment TEXT NOT NULL DEFAULT '',
    validation_status TEXT NOT NULL DEFAULT 'Pending',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (client_id, assessment_id, criterion_identifier),
    UNIQUE (client_id, id),
    FOREIGN KEY (client_id, assessment_id)
        REFERENCES securescope_control_assessments(client_id, id) ON DELETE CASCADE,
    FOREIGN KEY (client_id, criterion_id)
        REFERENCES securescope_control_criteria(client_id, id) ON DELETE RESTRICT
);

CREATE TABLE IF NOT EXISTS securescope_control_effectiveness_tests (
    id BIGSERIAL PRIMARY KEY,
    client_id BIGINT NOT NULL
        REFERENCES securescope_clients(id) ON DELETE CASCADE,
    assessment_id BIGINT NOT NULL,
    test_scenario TEXT NOT NULL,
    test_objective TEXT NOT NULL,
    expected_outcome TEXT NOT NULL,
    observed_outcome TEXT NOT NULL,
    test_date DATE NOT NULL,
    tested_sample TEXT NOT NULL,
    exceptions TEXT NOT NULL DEFAULT '',
    evidence_reference TEXT NOT NULL,
    tester TEXT NOT NULL,
    result TEXT NOT NULL
        CHECK (result IN (
            'Successful', 'Partially successful', 'Failed',
            'Not tested', 'Inconclusive'
        )),
    corrective_action TEXT NOT NULL DEFAULT '',
    retest_required BOOLEAN NOT NULL DEFAULT FALSE,
    retest_due_date DATE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (client_id, id),
    FOREIGN KEY (client_id, assessment_id)
        REFERENCES securescope_control_assessments(client_id, id) ON DELETE CASCADE,
    CHECK (NOT retest_required OR retest_due_date IS NOT NULL)
);

CREATE TABLE IF NOT EXISTS securescope_control_dimension_results (
    id BIGSERIAL PRIMARY KEY,
    client_id BIGINT NOT NULL
        REFERENCES securescope_clients(id) ON DELETE CASCADE,
    assessment_id BIGINT NOT NULL,
    dimension TEXT NOT NULL
        CHECK (dimension IN (
            'Design adequacy', 'Implementation', 'Scope coverage',
            'Operating effectiveness', 'Evidence assurance', 'Validation'
        )),
    status TEXT NOT NULL,
    score NUMERIC(5, 2) CHECK (score BETWEEN 0 AND 100),
    rationale TEXT NOT NULL,
    confidence TEXT NOT NULL CHECK (confidence IN ('Low', 'Medium', 'High')),
    validation_status TEXT NOT NULL DEFAULT 'Pending',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (client_id, assessment_id, dimension),
    FOREIGN KEY (client_id, assessment_id)
        REFERENCES securescope_control_assessments(client_id, id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS securescope_control_evidence (
    id BIGSERIAL PRIMARY KEY,
    client_id BIGINT NOT NULL
        REFERENCES securescope_clients(id) ON DELETE CASCADE,
    assessment_id BIGINT NOT NULL,
    criterion_id BIGINT,
    evidence_identifier TEXT NOT NULL,
    evidence_source TEXT NOT NULL,
    evidence_type TEXT NOT NULL,
    collection_method TEXT NOT NULL,
    collection_date TIMESTAMPTZ NOT NULL,
    assessment_period TEXT,
    source_asset_or_system TEXT,
    scanner_or_integration TEXT,
    raw_evidence_reference TEXT NOT NULL,
    evidence_summary TEXT NOT NULL,
    analyst_notes TEXT NOT NULL DEFAULT '',
    owner TEXT NOT NULL DEFAULT '',
    evidence_version INTEGER NOT NULL DEFAULT 1 CHECK (evidence_version > 0),
    freshness_status TEXT NOT NULL DEFAULT 'Unknown'
        CHECK (freshness_status IN ('Current', 'Approaching expiration', 'Expired', 'Unknown')),
    expiration_date TIMESTAMPTZ,
    confidence TEXT NOT NULL CHECK (confidence IN ('Low', 'Medium', 'High')),
    validation_status TEXT NOT NULL DEFAULT 'Pending',
    validator TEXT,
    validation_date DATE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (client_id, evidence_identifier, evidence_version),
    FOREIGN KEY (client_id, assessment_id)
        REFERENCES securescope_control_assessments(client_id, id) ON DELETE CASCADE,
    FOREIGN KEY (client_id, criterion_id)
        REFERENCES securescope_control_criteria(client_id, id) ON DELETE RESTRICT,
    CHECK (expiration_date IS NULL OR expiration_date > collection_date)
);

CREATE TABLE IF NOT EXISTS securescope_control_gaps (
    id BIGSERIAL PRIMARY KEY,
    client_id BIGINT NOT NULL
        REFERENCES securescope_clients(id) ON DELETE CASCADE,
    gap_uuid UUID NOT NULL UNIQUE,
    assessment_id BIGINT NOT NULL,
    control_id TEXT NOT NULL,
    sub_objective TEXT,
    gap_statement TEXT NOT NULL,
    affected_scope TEXT NOT NULL,
    failed_criterion TEXT,
    supporting_evidence JSONB NOT NULL DEFAULT '[]'::jsonb,
    related_risk TEXT NOT NULL,
    current_value NUMERIC,
    target_value NUMERIC,
    unit TEXT,
    remaining_effort TEXT NOT NULL,
    priority TEXT NOT NULL CHECK (priority IN ('Critical', 'High', 'Medium', 'Low')),
    recommended_treatment TEXT NOT NULL,
    required_verification TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'Open'
        CHECK (status IN ('Open', 'In progress', 'Ready for verification', 'Closed', 'Accepted risk', 'Reopened')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    closed_at TIMESTAMPTZ,
    UNIQUE (client_id, id),
    FOREIGN KEY (client_id, assessment_id)
        REFERENCES securescope_control_assessments(client_id, id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS securescope_improvement_actions (
    id BIGSERIAL PRIMARY KEY,
    client_id BIGINT NOT NULL
        REFERENCES securescope_clients(id) ON DELETE CASCADE,
    action_uuid UUID NOT NULL UNIQUE,
    gap_id BIGINT,
    control_id TEXT NOT NULL,
    affected_scope TEXT NOT NULL,
    related_risks JSONB NOT NULL DEFAULT '[]'::jsonb,
    recommended_action TEXT NOT NULL,
    action_owner TEXT NOT NULL,
    risk_owner TEXT NOT NULL,
    priority TEXT NOT NULL CHECK (priority IN ('Critical', 'High', 'Medium', 'Low')),
    required_resources TEXT NOT NULL DEFAULT '',
    dependencies TEXT NOT NULL DEFAULT '',
    start_date DATE,
    due_date DATE NOT NULL,
    sla_days INTEGER NOT NULL CHECK (sla_days > 0),
    success_criteria TEXT NOT NULL,
    verification_method TEXT NOT NULL,
    expected_evidence TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'Open'
        CHECK (status IN ('Open', 'In progress', 'Blocked', 'Ready for verification', 'Completed', 'Cancelled')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (client_id, id),
    FOREIGN KEY (client_id, gap_id)
        REFERENCES securescope_control_gaps(client_id, id) ON DELETE CASCADE,
    CHECK (start_date IS NULL OR due_date >= start_date)
);

CREATE TABLE IF NOT EXISTS securescope_improvement_milestones (
    id BIGSERIAL PRIMARY KEY,
    client_id BIGINT NOT NULL
        REFERENCES securescope_clients(id) ON DELETE CASCADE,
    action_id BIGINT NOT NULL,
    title TEXT NOT NULL,
    owner TEXT NOT NULL,
    priority TEXT NOT NULL CHECK (priority IN ('Critical', 'High', 'Medium', 'Low')),
    due_date DATE NOT NULL,
    sla_days INTEGER NOT NULL CHECK (sla_days > 0),
    status TEXT NOT NULL DEFAULT 'Open'
        CHECK (status IN ('Open', 'In progress', 'Blocked', 'Completed', 'Cancelled')),
    success_criteria TEXT NOT NULL,
    evidence_reference TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (client_id, id),
    FOREIGN KEY (client_id, action_id)
        REFERENCES securescope_improvement_actions(client_id, id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS securescope_poam_items (
    id BIGSERIAL PRIMARY KEY,
    client_id BIGINT NOT NULL
        REFERENCES securescope_clients(id) ON DELETE CASCADE,
    poam_uuid UUID NOT NULL UNIQUE,
    gap_id BIGINT,
    action_id BIGINT,
    control_id TEXT NOT NULL,
    weakness_description TEXT NOT NULL,
    source_reference TEXT NOT NULL,
    owner TEXT NOT NULL,
    risk_owner TEXT NOT NULL,
    priority TEXT NOT NULL CHECK (priority IN ('Critical', 'High', 'Medium', 'Low')),
    status TEXT NOT NULL DEFAULT 'Open'
        CHECK (status IN (
            'Open', 'In progress', 'Blocked', 'Ready for verification',
            'Completed', 'Cancelled'
        )),
    sla_days INTEGER NOT NULL CHECK (sla_days > 0),
    scheduled_completion_date DATE NOT NULL,
    verification_method TEXT NOT NULL,
    evidence_reference TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (client_id, id),
    FOREIGN KEY (client_id, gap_id)
        REFERENCES securescope_control_gaps(client_id, id) ON DELETE CASCADE,
    FOREIGN KEY (client_id, action_id)
        REFERENCES securescope_improvement_actions(client_id, id) ON DELETE CASCADE,
    CHECK (num_nonnulls(gap_id, action_id) >= 1)
);

CREATE TABLE IF NOT EXISTS securescope_risk_acceptances (
    id BIGSERIAL PRIMARY KEY,
    client_id BIGINT NOT NULL
        REFERENCES securescope_clients(id) ON DELETE CASCADE,
    acceptance_uuid UUID NOT NULL UNIQUE,
    finding_id BIGINT,
    gap_id BIGINT,
    risk_reference TEXT,
    business_justification TEXT NOT NULL,
    risk_owner TEXT NOT NULL,
    approver TEXT NOT NULL,
    approval_date DATE NOT NULL,
    inherent_likelihood TEXT NOT NULL,
    inherent_impact TEXT NOT NULL,
    current_controls TEXT NOT NULL,
    residual_likelihood TEXT NOT NULL,
    residual_impact TEXT NOT NULL,
    residual_risk_level TEXT NOT NULL,
    compensating_controls TEXT NOT NULL,
    evidence_reference TEXT NOT NULL,
    effective_date DATE NOT NULL,
    expiration_date DATE NOT NULL,
    review_frequency TEXT NOT NULL,
    acceptance_scope TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'Approved'
        CHECK (status IN ('Draft', 'Pending approval', 'Approved', 'Due for review', 'Expired', 'Revoked')),
    created_by TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (client_id, id),
    FOREIGN KEY (client_id, finding_id)
        REFERENCES securescope_findings(client_id, id) ON DELETE CASCADE,
    FOREIGN KEY (client_id, gap_id)
        REFERENCES securescope_control_gaps(client_id, id) ON DELETE CASCADE,
    CHECK (num_nonnulls(finding_id, gap_id, risk_reference) >= 1),
    CHECK (expiration_date > effective_date),
    CHECK (approval_date <= effective_date)
);

CREATE TABLE IF NOT EXISTS securescope_soa_versions (
    id BIGSERIAL PRIMARY KEY,
    client_id BIGINT NOT NULL
        REFERENCES securescope_clients(id) ON DELETE CASCADE,
    version_number INTEGER NOT NULL CHECK (version_number > 0),
    status TEXT NOT NULL DEFAULT 'Draft'
        CHECK (status IN ('Draft', 'Approved', 'Superseded')),
    prepared_by TEXT NOT NULL,
    approved_by TEXT,
    approval_date DATE,
    notes TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (client_id, version_number),
    UNIQUE (client_id, id)
);

CREATE TABLE IF NOT EXISTS securescope_soa_items (
    id BIGSERIAL PRIMARY KEY,
    client_id BIGINT NOT NULL
        REFERENCES securescope_clients(id) ON DELETE CASCADE,
    soa_version_id BIGINT NOT NULL,
    control_id TEXT NOT NULL,
    control_name TEXT NOT NULL,
    necessary_control BOOLEAN NOT NULL,
    applicability TEXT NOT NULL CHECK (applicability IN ('Applicable', 'Not applicable')),
    inclusion_justification TEXT,
    exclusion_justification TEXT,
    implementation_status TEXT NOT NULL,
    control_owner TEXT NOT NULL,
    related_risks JSONB NOT NULL DEFAULT '[]'::jsonb,
    related_treatment_plans JSONB NOT NULL DEFAULT '[]'::jsonb,
    evidence JSONB NOT NULL DEFAULT '[]'::jsonb,
    effectiveness_review TEXT NOT NULL DEFAULT '',
    reviewer TEXT,
    review_date DATE,
    approved BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (client_id, soa_version_id, control_id),
    FOREIGN KEY (client_id, soa_version_id)
        REFERENCES securescope_soa_versions(client_id, id) ON DELETE CASCADE,
    CHECK (
        (applicability = 'Applicable' AND coalesce(inclusion_justification, '') <> '')
        OR (applicability = 'Not applicable' AND coalesce(exclusion_justification, '') <> '' AND approved)
    )
);

CREATE TABLE IF NOT EXISTS securescope_risk_treatment_plans (
    id BIGSERIAL PRIMARY KEY,
    client_id BIGINT NOT NULL
        REFERENCES securescope_clients(id) ON DELETE CASCADE,
    plan_uuid UUID NOT NULL UNIQUE,
    title TEXT NOT NULL,
    risk_reference TEXT NOT NULL,
    treatment_option TEXT NOT NULL
        CHECK (treatment_option IN ('Remediate or modify', 'Mitigate', 'Avoid', 'Accept', 'Transfer or share')),
    linked_controls JSONB NOT NULL DEFAULT '[]'::jsonb,
    linked_gaps JSONB NOT NULL DEFAULT '[]'::jsonb,
    linked_findings JSONB NOT NULL DEFAULT '[]'::jsonb,
    linked_actions JSONB NOT NULL DEFAULT '[]'::jsonb,
    owner TEXT NOT NULL,
    risk_owner TEXT NOT NULL,
    required_resources TEXT NOT NULL DEFAULT '',
    dependencies TEXT NOT NULL DEFAULT '',
    due_date DATE NOT NULL,
    residual_risk TEXT NOT NULL,
    validation_evidence TEXT NOT NULL,
    approver TEXT NOT NULL,
    approval_date DATE NOT NULL,
    status TEXT NOT NULL DEFAULT 'Approved'
        CHECK (status IN ('Draft', 'Approved', 'In progress', 'Completed', 'Cancelled')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (client_id, id)
);

CREATE TABLE IF NOT EXISTS securescope_risk_treatment_milestones (
    id BIGSERIAL PRIMARY KEY,
    client_id BIGINT NOT NULL
        REFERENCES securescope_clients(id) ON DELETE CASCADE,
    treatment_plan_id BIGINT NOT NULL,
    title TEXT NOT NULL,
    owner TEXT NOT NULL,
    due_date DATE NOT NULL,
    status TEXT NOT NULL DEFAULT 'Open'
        CHECK (status IN ('Open', 'In progress', 'Blocked', 'Completed', 'Cancelled')),
    success_criteria TEXT NOT NULL,
    evidence_reference TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    FOREIGN KEY (client_id, treatment_plan_id)
        REFERENCES securescope_risk_treatment_plans(client_id, id)
        ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS securescope_audit_events (
    id BIGSERIAL PRIMARY KEY,
    client_id BIGINT NOT NULL
        REFERENCES securescope_clients(id) ON DELETE CASCADE,
    event_type TEXT NOT NULL,
    entity_type TEXT NOT NULL,
    entity_id TEXT NOT NULL,
    actor TEXT,
    summary TEXT NOT NULL,
    before_state JSONB,
    after_state JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS securescope_entity_status_history (
    id BIGSERIAL PRIMARY KEY,
    client_id BIGINT NOT NULL
        REFERENCES securescope_clients(id) ON DELETE CASCADE,
    entity_type TEXT NOT NULL,
    entity_id BIGINT NOT NULL,
    from_status TEXT,
    to_status TEXT NOT NULL,
    reason TEXT NOT NULL,
    evidence_reference TEXT,
    changed_by TEXT NOT NULL,
    changed_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Deliberately not workspace-owned: this retains only a minimal deletion event
-- after the selected workspace rows have been removed by cascade.
CREATE TABLE IF NOT EXISTS securescope_admin_audit_events (
    id BIGSERIAL PRIMARY KEY,
    event_type TEXT NOT NULL,
    deleted_client_id BIGINT,
    workspace_name TEXT NOT NULL,
    actor TEXT,
    summary JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_findings_client_status_severity
    ON securescope_findings(client_id, lifecycle_status, severity, last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_findings_client_asset
    ON securescope_findings(client_id, asset_identity, last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_findings_client_vulnerability
    ON securescope_findings(client_id, vulnerability_identity);
CREATE INDEX IF NOT EXISTS idx_observations_client_finding
    ON securescope_finding_observations(client_id, finding_id, observed_at DESC);
CREATE INDEX IF NOT EXISTS idx_observations_client_scanner
    ON securescope_finding_observations(client_id, scanner, observed_at DESC);
CREATE INDEX IF NOT EXISTS idx_finding_history_client
    ON securescope_finding_status_history(client_id, finding_id, changed_at DESC);
CREATE INDEX IF NOT EXISTS idx_remediation_plans_client_status
    ON securescope_remediation_plans(client_id, status, priority, due_date);
CREATE INDEX IF NOT EXISTS idx_remediation_tasks_client_status
    ON securescope_remediation_tasks(client_id, status, priority, due_date);
CREATE INDEX IF NOT EXISTS idx_remediation_milestones_client_due
    ON securescope_remediation_milestones(client_id, status, due_date);
CREATE INDEX IF NOT EXISTS idx_verification_evidence_client
    ON securescope_verification_evidence(client_id, validation_status, expires_at);
CREATE INDEX IF NOT EXISTS idx_profiles_client_control
    ON securescope_control_assessment_profiles(client_id, control_id, profile_version DESC);
CREATE INDEX IF NOT EXISTS idx_assessments_client_status
    ON securescope_control_assessments(client_id, assessment_status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_criterion_results_client_assessment
    ON securescope_control_criterion_results(client_id, assessment_id, result);
CREATE INDEX IF NOT EXISTS idx_effectiveness_tests_client_assessment
    ON securescope_control_effectiveness_tests(client_id, assessment_id, result);
CREATE INDEX IF NOT EXISTS idx_control_evidence_client_expiration
    ON securescope_control_evidence(client_id, freshness_status, expiration_date);
CREATE INDEX IF NOT EXISTS idx_control_gaps_client_status
    ON securescope_control_gaps(client_id, status, priority, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_improvement_actions_client_due
    ON securescope_improvement_actions(client_id, status, priority, due_date);
CREATE INDEX IF NOT EXISTS idx_improvement_milestones_client_due
    ON securescope_improvement_milestones(client_id, status, due_date);
CREATE INDEX IF NOT EXISTS idx_poam_items_client_due
    ON securescope_poam_items(client_id, status, priority, scheduled_completion_date);
CREATE INDEX IF NOT EXISTS idx_risk_acceptances_client_expiration
    ON securescope_risk_acceptances(client_id, status, expiration_date);
CREATE INDEX IF NOT EXISTS idx_soa_items_client_control
    ON securescope_soa_items(client_id, control_id, soa_version_id);
CREATE INDEX IF NOT EXISTS idx_risk_treatment_client_status
    ON securescope_risk_treatment_plans(client_id, status, due_date);
CREATE INDEX IF NOT EXISTS idx_risk_treatment_milestones_due
    ON securescope_risk_treatment_milestones(client_id, status, due_date);
CREATE INDEX IF NOT EXISTS idx_audit_events_client_created
    ON securescope_audit_events(client_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_entity_history_client_created
    ON securescope_entity_status_history(client_id, entity_type, entity_id, changed_at DESC);
CREATE INDEX IF NOT EXISTS idx_admin_audit_events_created
    ON securescope_admin_audit_events(created_at DESC);
