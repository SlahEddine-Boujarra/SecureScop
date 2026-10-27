# SecureScope correction pass — 26 September 2026

This pass extends the existing implementation from source revision `8827db7`. It does not replace Programme Foundation, Control Assurance, Policies, Risk Management, Evidence or Remediation persistence.

## Runtime fixes

- Scope Editor retains durable values for all six steps before rendering widgets. Moving forward/back no longer loses previously entered fields. Client and engagement namespaces avoid name collisions. Cancel still clears the editor; saving still uses the canonical version service.
- Control Profile → Create Remediation uses separate form and selection-state keys. A full Streamlit interaction regression opens and submits this form.

## Data and migrations

No schema migration or parallel model was introduced. Control requirements remain inside versioned Control Profiles; control actions remain canonical improvement actions; vulnerability plans remain canonical remediation plans.

Identical requirement saves return the existing profile version. Stale versions are rejected even when the submitted content is unchanged. Editing retains requirement order and automation provenance.

Transaction advisory locks serialize creation for the same client/control/scope/requirement or exact canonical finding set. Existing active work is reused. This is application-path idempotence, not a new database uniqueness constraint. Different finding groups remain distinct plans.

## UI changes

- Compact scoped KPI styling and a grouped assessment empty state.
- Three-column attention cards with counts and working filter actions.
- Control metrics read “Requirements Met” and “Open Remediation.”
- Required-policy blockers precede explicit failures, missing evidence, stale evidence and other unresolved requirements. Additional unresolved requirements remain reachable.
- Verification settings are secondary; normal requirement fields stay visible.
- Green Back-link styling is shared by native control/risk/foundation links and workbench navigation.
- Policy Builder B/I toolbar buttons removed. Its editing, saving, history and document structure remain intact.
- Treatment Due Date and Timescale are distinct columns.
- Specialist remediation fields moved under Advanced Details; Changed by defaults to the authenticated principal and is not editable.
- Saved project summary is secondary to the existing batch planner. Project progress explicitly does not establish compliance.

## Control Assurance and Remediation

The same requirement remediation queue is available in global Remediation and Gap Actions. Control Workspace links carry the existing action ID and keep selected context. No action is copied into a second table.

Completing requirement remediation requires Ready for verification, fresh validated canonical evidence mapped to the selected control/scope, reviewer metadata, and a passing evaluation of the originating requirement. The audit event retains the selected evidence, scope, engagement, actor, rationale and requirement result. Completion does not mark every requirement or the entire control effective.

Vulnerability task completion requires Ready for verification and an authorized reviewer. Verification references must identify canonical evidence as `EV-<id>`; a control ID alone is rejected. Evidence must be validated, have reviewer metadata, and remain within the existing 90-day/default expiry window. Milestones retain their existing status vocabulary and require the same evidence check at completion. These checks validate evidence provenance/currency; the reviewer remains responsible for confirming that it demonstrates the recorded success criteria.

Historical plans with identical finding sets are highlighted for review. No historical plan was deleted, merged or silently superseded. Live records must be inspected before deciding which historical work is redundant.

## Evidence

Evidence Register displays Accepted/Unreviewed aliases without changing persisted Validated/Pending values. Collected and expiry dates are visible. Existing source configuration remains in Evidence Settings; review, requests, detail, import and auditor export workflows are retained.

## Risk Management

Related Risk Treatments uses the same Current ISMS Scope / All Client Risks / Unassigned Risks choices. Open Treatment Plan and individual risk links carry the explicitly selected view. Default entry still selects Current ISMS Scope. Existing stage navigation and context stay intact.

Risk scoring, matrix comparisons, residual planned/unverified semantics and the seven-step risk editor are unchanged. No date is invented from a timescale.

## Files changed

Repositories:
- `src/securescope/persistence/assurance_workspace_repository.py`
- `src/securescope/persistence/exposure_repository.py`

UI:
- `ui/grc_workspace/scope_editor.py`, `linked_modules.py`, `stitch_records.py`
- `ui/control_workspace.py`, `assurance_dashboard.py`, `assurance_queue.py`
- `ui/components_v2/assurance_workbench.js`, `assurance_workbench.css`
- `ui/evidence_hub_ui.py`, `exposure_management_ui.py`, `gap_dashboard_ui.py`
- `ui/risk_management.py`, `risk_workspace.py`, `policy_workspace.py`, `workflow_sections.py`

Tests:
- `tests/test_final_runtime_corrections.py`
- `tests/test_assurance_workspace.py`
- `tests/test_assurance_remediation_ux_v5_3_8_11.py`
- `tests/frontend/drawers.test.mjs`
- `tests/frontend/risk_lifecycle.test.mjs`

UI paths above are relative to `src/securescope/`. Validation logs and this report are included in the archive.

## Verification

- Python: 625 passed; 4 PostgreSQL integration tests skipped because `SECURESCOPE_TEST_DATABASE_URL` is not configured.
- Frontend DOM tests: 40 passed.
- Changed Python files: Black and Flake8 checks.
- Regression coverage includes scope forward/back retention, namespace isolation, remediation form submission, unchanged saves, stale versions, invalid closure evidence, requirement-specific closure, duplicate-plan reuse, explicit risk-view navigation, recommended blocker ordering and canonical remediation links.

No live PostgreSQL migration/concurrency test or browser visual review was performed. Repository tests use controlled database doubles; Streamlit runtime tests exercise forms and session reruns. The development archive is not a claim of production deployment or live-data cleanup.

## Deliberately preserved / unavailable

Preserved: the seven-section Foundation architecture; governance grouping; Scope review/approval/version immutability; SoA ownership and historical records; structured Interested Party requirements; canonical Policies, Risks, Scope and treatments; scanner-versus-compliance separation; all existing histories.

Formal Risk Acceptance, configurable Methodology, automated review reminders/campaigns and other unavailable integrations remain truthfully marked Coming Soon. Existing duplicate plans require human review with live data. No source database was available to reconcile those historical records safely.
